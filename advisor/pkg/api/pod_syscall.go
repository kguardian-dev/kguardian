package api

import (
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
	time.Sleep(3 * time.Second)
	apiURL := "http://127.0.0.1:9090/pod/syscalls/" + podName

	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error making GET request")
		return PodSysCall{}, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetPodSysCall: Error closing response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return PodSysCall{}, fmt.Errorf("GetPodSysCall: received non-OK HTTP status code: %v", resp.StatusCode)
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
