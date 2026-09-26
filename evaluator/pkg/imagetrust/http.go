package imagetrust

import (
	"encoding/json"
	"net/http"
	"time"
)

// Handler serves GET /image-trust: the last pass's per-container results,
// optionally filtered by ?namespace= and ?verdict=.
func (r *Runner) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
