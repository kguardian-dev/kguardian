package k8s

import (
	"context"
	"io"
	"net/http"
	"os"

	log "github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

var (
	serviceNamespace = "kube-guardian"
	serviceName      = "kubeguardian-api"
	ports            = []string{"9090:9090"}
)

// PortForward sets up a port-forwarding from the local machine to the given pod.
// It runs the port-forwarding operation in a Goroutine and returns a channel to stop the port-forwarding
func PortForward(config *Config) (chan struct{}, chan error, chan bool) {
	stopChan := make(chan struct{}, 1)
	errChan := make(chan error, 1)
	done := make(chan bool)

	go func() {
		service, err := config.Clientset.CoreV1().Services(serviceNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			errChan <- err
			return
		}

		pods, err := config.Clientset.CoreV1().Pods(serviceNamespace).List(context.TODO(), metav1.ListOptions{LabelSelector: service.Spec.Selector["app"]})
		if err != nil {
			errChan <- err
			return
		}

		// Use the first pod in the pods list and return its metadata
		pod := pods.Items[0].ObjectMeta
		// TODO: Only use goroutine for port-forward logic
		log.Debug().Msgf("Using pod: %s", pod.Name)

		// Set up Port Forwarding
		url := config.Clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Namespace(pod.Namespace).
			Name(pod.Name).
			SubResource("portforward").URL()

		transport, upgrader, err := spdy.RoundTripperFor(config.Config)
		if err != nil {
			errChan <- err
			return
		}

		dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", url)

		pf, err := portforward.New(dialer, ports, make(chan struct{}, 1), make(chan struct{}, 1), io.Discard, os.Stderr)
		if err != nil {
			errChan <- err
			return
		}
		done <- true // Signal that the goroutine is done
		if err := pf.ForwardPorts(); err != nil {
			errChan <- err
			return
		}

	}()

	return stopChan, errChan, done
}
