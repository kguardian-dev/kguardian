package k8s

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

var (
	// TODO: This namespace should be configurable if overridden
	serviceNamespace = "kguardian"
	serviceName      = "broker"
	ports            = []string{"9090:9090"}
)

// PortForward sets up a port-forwarding from the local machine to the given pod.
// It runs the port-forwarding operation in a Goroutine and returns a channel to stop the port-forwarding
func PortForward(config *Config) (chan struct{}, chan error, chan bool) {
	stopChan := make(chan struct{}, 1)
	errChan := make(chan error, 1)
	done := make(chan bool)

	// Basic validation
	if config == nil {
		errChan <- fmt.Errorf("nil Kubernetes configuration")
		close(done) // Signal completion to avoid blocking
		return stopChan, errChan, done
	}

	if config.Clientset == nil {
		errChan <- fmt.Errorf("nil Kubernetes clientset")
		close(done) // Signal completion to avoid blocking
		return stopChan, errChan, done
	}

	if config.Config == nil {
		errChan <- fmt.Errorf("nil REST configuration")
		close(done) // Signal completion to avoid blocking
		return stopChan, errChan, done
	}

	log.Debug().Msg("Configuring port-forwarding")

	go func() {
		var err error

		// Try to find the namespace from environment first
		actualNamespace := os.Getenv("KUBE_GUARDIAN_NAMESPACE")
		if actualNamespace == "" {
			// Use the hardcoded value as fallback
			actualNamespace = serviceNamespace
		}

		log.Debug().Msgf("Looking for broker service in namespace: %s", actualNamespace)

		// Use a context with timeout for all operations
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Fetch the service
		service, err := config.Clientset.CoreV1().Services(actualNamespace).Get(ctx, serviceName, metav1.GetOptions{})
		if err != nil {
			// Try fallback to alternative namespace
			if actualNamespace != "kube-system" {
				log.Warn().Err(err).Msgf("Service not found in %s, trying kube-system as fallback", actualNamespace)
				service, err = config.Clientset.CoreV1().Services("kube-system").Get(ctx, serviceName, metav1.GetOptions{})
				if err != nil {
					log.Error().Err(err).Msg("Error collecting broker service in fallback namespace kube-system")
					errChan <- fmt.Errorf("failed to find kguardian broker service in any namespace: %w", err)
					close(done)
					return
				}
				actualNamespace = "kube-system"
			} else {
				log.Error().Err(err).Msgf("Error collecting broker service in namespace %s", actualNamespace)
				errChan <- fmt.Errorf("failed to find kguardian broker service: %w", err)
				close(done)
				return
			}
		}

		if len(service.Spec.Selector) == 0 {
			err := fmt.Errorf("service %s/%s has no selectors", actualNamespace, serviceName)
			log.Error().Msg(err.Error())
			errChan <- err
			close(done)
			return
		}

		// Convert the service's selector map to a label selector string
		selectors := make([]string, 0)
		for key, val := range service.Spec.Selector {
			selectors = append(selectors, fmt.Sprintf("%s=%s", key, val))
		}
		labelSelectorString := strings.Join(selectors, ",")

		log.Debug().Msgf("Using port-forwarding pod with selector: %s", labelSelectorString)

		// List pods matching the service selector
		pods, err := config.Clientset.CoreV1().Pods(actualNamespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelectorString})
		if err != nil {
			log.Error().Err(err).Msg("Error collecting broker pods")
			errChan <- fmt.Errorf("failed to list kguardian broker pods: %w", err)
			close(done) // Signal completion to avoid blocking
			return
		}

		if len(pods.Items) == 0 {
			err := fmt.Errorf("no pods found for service %s/%s with selector %s",
				actualNamespace, serviceName, labelSelectorString)
			log.Error().Msg(err.Error())
			errChan <- err
			close(done)
			return
		}

		podNames := []string{}
		for _, pod := range pods.Items {
			podNames = append(podNames, pod.Name)
		}
		log.Debug().Msgf("Available port-forwarding pods: %s", strings.Join(podNames, ", "))

		// Find a ready pod to use
		var readyPod metav1.ObjectMeta
		foundReadyPod := false

		for _, pod := range pods.Items {
			// Check if pod is ready
			podReady := true
			for _, condition := range pod.Status.Conditions {
				if condition.Type == "Ready" && condition.Status != "True" {
					podReady = false
					break
				}
			}

			if podReady {
				readyPod = pod.ObjectMeta
				foundReadyPod = true
				break
			}
		}

		if !foundReadyPod {
			err := fmt.Errorf("no ready pods found for service %s/%s", actualNamespace, serviceName)
			log.Error().Msg(err.Error())
			errChan <- err
			close(done)
			return
		}

		// Use the first ready pod
		log.Debug().Msgf("Using port-forwarding pod: %s", readyPod.Name)

		// Set up Port Forwarding
		url := config.Clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Namespace(readyPod.Namespace).
			Name(readyPod.Name).
			SubResource("portforward").URL()

		log.Debug().Msgf("Configuring port-forwarding url: %s", url.String())
		transport, upgrader, err := spdy.RoundTripperFor(config.Config)
		if err != nil {
			log.Error().Err(err).Msg("Error creating round tripper for port forwarding")
			errChan <- fmt.Errorf("port forwarding setup failed: %w", err)
			close(done) // Signal completion to avoid blocking
			return
		}

		dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", url)

		// Create channels for port forwarding
		readyChan := make(chan struct{}, 1)
		pfErrChan := make(chan error, 1)

		out := io.Discard
		errOut := io.Writer(os.Stderr)

		// If debug logging is enabled, create a writer that logs debug messages
		if log.Debug().Enabled() {
			errOut = writerFunc(func(p []byte) (n int, err error) {
				log.Debug().Msgf("Port forward stderr: %s", string(p))
				return len(p), nil
			})
		}

		pf, err := portforward.New(dialer, ports, stopChan, readyChan, out, errOut)
		if err != nil {
			log.Error().Err(err).Msg("Error creating port forwarder")
			errChan <- fmt.Errorf("port forwarder creation failed: %w", err)
			close(done) // Signal completion to avoid blocking
			return
		}

		// Start port forwarding in another goroutine
		go func() {
			err := pf.ForwardPorts()
			if err != nil {
				log.Error().Err(err).Msg("Error during port forwarding")
				pfErrChan <- err
			} else {
				log.Debug().Msg("Port forwarding stopped normally")
			}
		}()

		// Wait for port forwarding to be ready
		select {
		case <-readyChan:
			log.Info().Msgf("Port forwarding ready for broker at %s:%s", "localhost", "9090")
			close(done) // Signal that port forwarding is ready
		case err := <-pfErrChan:
			errChan <- fmt.Errorf("port forwarding failed: %w", err)
			close(done)
		case <-time.After(10 * time.Second):
			errChan <- fmt.Errorf("timeout waiting for port forwarding to be ready")
			close(done)
		}
	}()

	return stopChan, errChan, done
}

// writerFunc implements io.Writer for custom writers
type writerFunc func(p []byte) (n int, err error)

// Write implements the io.Writer interface
func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}
