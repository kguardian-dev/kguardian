package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type PodSysCall struct {
	Syscalls []string `json:"syscalls"`
	Arch     string   `json:"arch"`
}

type PodSysCallResponse struct {
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	Syscalls     string `json:"syscalls"`
	Arch         string `json:"arch"`
}

func GetPodSysCall(podName string) (PodSysCall, error) {
	apiURL := "http://127.0.0.1:9090/pod/syscalls/" + podName

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return PodSysCall{}, fmt.Errorf("GetPodSysCall: failed to build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			log.Error().Err(err).Msg("GetPodSysCall: request timed out")
			return PodSysCall{}, ErrTimeout
		}
		log.Error().Err(err).Msg("GetPodSysCall: Error making GET request")
		return PodSysCall{}, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetPodSysCall: Error closing response body")
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		log.Debug().Msgf("GetPodSysCall: resource not found (404) for pod %s", podName)
		return PodSysCall{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return PodSysCall{}, classifyStatusError(resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error reading response body")
		return PodSysCall{}, err
	}

	var podSysCallsResponse []PodSysCallResponse
	if err := json.Unmarshal(body, &podSysCallsResponse); err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error unmarshalling JSON")
		return PodSysCall{}, err
	}

	if len(podSysCallsResponse) == 0 {
		return PodSysCall{}, fmt.Errorf("GetPodSysCall: No pod syscall found in database")
	}

	var podSysCalls PodSysCall

	podSysCalls.Syscalls = strings.Split(podSysCallsResponse[0].Syscalls, ",")
	podSysCalls.Arch = podSysCallsResponse[0].Arch

	return podSysCalls, nil
}
