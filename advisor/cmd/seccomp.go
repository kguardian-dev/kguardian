package cmd

import (
	"context"
	"fmt"
	"os"

	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
)

// Additional flags specific to seccomp profiles
var (
	defaultAction string
)

func init() {
	// Add existing flags
	seccompCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate profiles for all pods in all namespaces")
	seccompCmd.Flags().BoolVar(&allInNamespace, "all", false, "Generate profiles for all pods in the current namespace")

	// Add seccomp-specific flags
	seccompCmd.Flags().StringVar(&outputDir, "output-dir", "seccomp-profiles", "Directory to store generated seccomp profile JSON files")
	seccompCmd.Flags().StringVar(&defaultAction, "default-action", "SCMP_ACT_ERRNO", "Default seccomp action for unmatched syscalls (SCMP_ACT_ERRNO, SCMP_ACT_KILL, SCMP_ACT_LOG)")
}

var seccompCmd = &cobra.Command{
	Use:     "seccomp [pod-name]",
	Aliases: []string{"secp"},
	Short:   "Generate seccomp profile",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Set up the logger first, so we get useful debug output
		setupLogger()

		// For seccomp profiles, always ensure outputDir is set to "seccomp-profiles"
		// if not explicitly changed by the user
		if !cmd.Flags().Changed("output-dir") {
			outputDir = "seccomp-profiles"
		}

		config, ok := cmd.Context().Value(k8s.ConfigKey).(*k8s.Config)
		if !ok {
			fmt.Fprintf(os.Stderr, "Failed to retrieve Kubernetes configuration from context.\n\n")
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Verify your kubeconfig is valid:\n")
			fmt.Fprintf(os.Stderr, "    kubectl cluster-info\n")
			fmt.Fprintf(os.Stderr, "  Check your current context:\n")
			fmt.Fprintf(os.Stderr, "    kubectl config current-context\n")
			fmt.Fprintf(os.Stderr, "\nIf running directly as 'advisor', try kubectl plugin mode:\n")
			fmt.Fprintf(os.Stderr, "  kubectl guardian gen seccomp\n")
			log.Fatal().Msg("Failed to retrieve Kubernetes configuration")
		}

		// Set output directory in config
		config.OutputDir = outputDir
		log.Debug().Msgf("Using output directory: %s", outputDir)

		// Get the namespace from kubeConfigFlags
		namespace, _, err := kubeConfigFlags.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get namespace: %v\n\n", err)
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Check your kubeconfig context has a namespace set:\n")
			fmt.Fprintf(os.Stderr, "    kubectl config view --minify\n")
			fmt.Fprintf(os.Stderr, "  Or specify a namespace explicitly:\n")
			fmt.Fprintf(os.Stderr, "    kubectl guardian gen seccomp --namespace <namespace> <pod-name>\n")
			log.Fatal().Err(err).Msg("Failed to get namespace")
		}

		options := k8s.GenerateOptions{}

		if allNamespaces {
			options.Mode = k8s.AllPodsInAllNamespaces
		} else if allInNamespace {
			options.Mode = k8s.AllPodsInNamespace
			options.Namespace = namespace
		} else {
			// Validate that a pod name is provided
			if len(args) != 1 {
				_ = cmd.Usage()
				return
			}
			options.Mode = k8s.SinglePod
			options.PodName = args[0]
			options.Namespace = namespace
		}

		// Create a cancellable context so we can propagate cancellation to the
		// profile generator and cleanly shut down the error-watching goroutine.
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Set up port forwarding
		stopChan, errChan, done := k8s.PortForward(config, brokerNamespace, brokerService)
		<-done // Block until port-forwarding is set up
		log.Debug().Msg("Port forwarding set up successfully.")

		// Watch port-forwarding errors without blocking: if an error arrives
		// while profile generation is running we log it and cancel the context
		// so the generator can exit early. We never call log.Fatal() here so
		// the deferred cleanup (close(stopChan)) still runs.
		pfErrChan := make(chan error, 1)
		go func() {
			select {
			case err, ok := <-errChan:
				if ok && err != nil {
					log.Error().Err(err).Msg("Port-forwarding error during seccomp profile generation")
					pfErrChan <- err
					cancel()
				}
			case <-ctx.Done():
				// Context cancelled externally; nothing to do.
			}
		}()

		// Generate seccomp profiles
		k8s.GenerateSeccompProfile(ctx, options, config)
		close(stopChan)

		// Surface any port-forwarding error that was captured above so the
		// process exits with a non-zero status.
		select {
		case pfErr := <-pfErrChan:
			fmt.Fprintf(os.Stderr, "Port-forwarding error: %v\n\n", pfErr)
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Ensure the broker pod is running:\n")
			fmt.Fprintf(os.Stderr, "    kubectl get pods -n kguardian -l app=kguardian-broker\n")
			fmt.Fprintf(os.Stderr, "  Check the broker service exists:\n")
			fmt.Fprintf(os.Stderr, "    kubectl get svc -n kguardian\n")
			fmt.Fprintf(os.Stderr, "  Verify connectivity manually:\n")
			fmt.Fprintf(os.Stderr, "    kubectl port-forward -n kguardian svc/kguardian-broker 9090:9090\n")
			fmt.Fprintf(os.Stderr, "  Check broker pod logs for errors:\n")
			fmt.Fprintf(os.Stderr, "    kubectl logs -n kguardian -l app=kguardian-broker\n")
			os.Exit(1)
		default:
		}
	},
}
