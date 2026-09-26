package imagetrust

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Handler serves GET /image-trust: the last pass's per-container results,
// optionally filtered by ?namespace= and ?verdict=.
//
// It exposes what the broker's read API exposes, so it takes the same
// credential: when token (the broker READ-scope token the evaluator holds)
// is set, the request must carry it as a bearer token (401 otherwise).
// With broker auth off there is no token, and the broker serves the same
// data openly.
func (r *Runner) Handler(token string) http.Handler {
	token = strings.TrimSpace(token)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if token != "" {
			got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized: send the broker READ-scope token", http.StatusUnauthorized)
				return
			}
		}
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res, at := r.Results()
		ns, verdict := req.URL.Query().Get("namespace"), req.URL.Query().Get("verdict")
		out := make([]Result, 0, len(res))
		for _, x := range res {
			if (ns == "" || x.Namespace == ns) && (verdict == "" || x.Verdict == verdict) {
				out = append(out, x)
			}
		}
		body := struct {
			EvaluatedAt *time.Time `json:"evaluatedAt"`
			Results     []Result   `json:"results"`
		}{Results: out}
		if !at.IsZero() {
			body.EvaluatedAt = &at
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}
