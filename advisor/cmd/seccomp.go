package cmd

import (
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/xentra-ai/advisor/pkg/k8s"
)

// Additional flags specific to seccomp profiles
var (
	outputDir     string
	defaultAction string
)

func init() {
	// Add existing flags
	seccompCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate profiles for all pods in all namespaces")
	seccompCmd.Flags().BoolVar(&allInNamespace, "all", false, "Generate profiles for all pods in the current namespace")

	// Add seccomp-specific flags
	seccompCmd.Flags().StringVar(&outputDir, "output-dir", "seccomp-profiles", "Directory to store generated seccomp profiles")
	seccompCmd.Flags().StringVar(&defaultAction, "default-action", "SCMP_ACT_ERRNO", "Default action for seccomp profile (SCMP_ACT_ERRNO|SCMP_ACT_KILL|SCMP_ACT_LOG)")
}

var seccompCmd = &cobra.Command{
	Use:     "seccomp [pod-name]",
	Aliases: []string{"secp"},
	Short:   "Generate seccomp profile",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		config, ok := cmd.Context().Value(k8s.ConfigKey).(*k8s.Config)
		if !ok {
			log.Fatal().Msg("Failed to retrieve Kubernetes configuration")
		}

		// Get the namespace from kubeConfigFlags
		namespace, _, err := kubeConfigFlags.ToRawKubeConfigLoader().Namespace()
		if err != nil {
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

		// Set up port forwarding
		stopChan, errChan, done := k8s.PortForward(config)
		<-done // Block until port-forwarding is set up
		go func() {
			for err := range errChan {
				log.Fatal().Err(err).Msg("Error setting up port-forwarding")
			}
		}()
		log.Debug().Msg("Port forwarding set up successfully.")

		// Generate seccomp profiles
		k8s.GenerateSeccompProfile(options, config)
		close(stopChan)
	},
}
