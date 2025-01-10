package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/rs/zerolog/log"
)

func GetPodSysCall(podName string) ([]string, error) {

	time.Sleep(3 * time.Second)
	// Specify the URL of the REST API endpoint you want to invoke.
	apiURL := "http://127.0.0.1:9090/podsyscall/pod/" + podName

	// Send an HTTP GET request to the API endpoint.
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error making GET request")
		return nil, err
	}
	defer resp.Body.Close()
	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetPodSysCall: received non-OK HTTP status code: %v", resp.StatusCode)
	}
	var podSysCall []string

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error reading response body")
		return nil, err
	}

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.Unmarshal([]byte(body), &podSysCall); err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error unmarshal JSON")
		return nil, err
	}

	// If no pod syscall is found, return err
	if len(podSysCall) == 0 {
		return nil, fmt.Errorf("GetPodSysCall: No pod syscall found in database")
	}

	return podSysCall, nil
}
