package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	log "github.com/rs/zerolog/log"
)

// Shared read plumbing for the JSON read endpoints (images, profiles).

// ErrNotFound is matched (errors.Is) by every broker 404.
var ErrNotFound = errors.New("not found")

// NotFoundError is a broker 404. Code and Message come from the JSON error
// body the profile endpoints send ({"error":"workload_not_found",...});
// both are empty for the plain-text "No data found" body.
type NotFoundError struct {
	Code    string
	Message string
}

func (e *NotFoundError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return e.Code
	}
	return "not found"
}

// Is makes errors.Is(err, ErrNotFound) true for every NotFoundError.
func (e *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// brokerErrorBody is the JSON error shape of the newer read endpoints.
type brokerErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// brokerGetBody GETs path and returns the body (capped at
// maxBrokerResponseBytes). 404 maps to ErrNotFound; any other non-200 is an
// error that carries the broker's message.
func brokerGetBody(op, path string) ([]byte, error) {
	resp, err := brokerGet(path)
	if err != nil {
		log.Error().Err(err).Msgf("%s: Error making GET request", op)
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msgf("%s: Error closing response body", op)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokerResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: reading response body: %w", op, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		var eb brokerErrorBody
		_ = json.Unmarshal(body, &eb)
		return nil, &NotFoundError{Code: eb.Error, Message: eb.Message}
	default:
		var eb brokerErrorBody
		if json.Unmarshal(body, &eb) == nil && eb.Message != "" {
			return nil, fmt.Errorf("%s: broker returned HTTP %d: %s", op, resp.StatusCode, eb.Message)
		}
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("%s: broker returned HTTP %d: %s", op, resp.StatusCode, msg)
	}
}
