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
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	Syscalls     string `json:"syscalls"`
	Arch         string `json:"arch"`
}

func GetPodSysCall(podName string) ([]string, error) {
	time.Sleep(3 * time.Second)
	apiURL := "http://127.0.0.1:9090/pod/syscalls/" + podName

	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error making GET request")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetPodSysCall: received non-OK HTTP status code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error reading response body")
		return nil, err
	}

	var podSysCalls []PodSysCall
	if err := json.Unmarshal(body, &podSysCalls); err != nil {
		log.Error().Err(err).Msg("GetPodSysCall: Error unmarshalling JSON")
		return nil, err
	}

	if len(podSysCalls) == 0 {
		return nil, fmt.Errorf("GetPodSysCall: No pod syscall found in database")
	}

	return strings.Split(podSysCalls[0].Syscalls, ","), nil
}
