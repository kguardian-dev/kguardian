package cmd

import (
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/xentra-ai/advisor/pkg/k8s"
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate resources",
}

var (
	allNamespaces  bool
	allInNamespace bool
)

func init() {
	networkPolicyCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate policies for all pods in all namespaces")
	networkPolicyCmd.Flags().BoolVar(&allInNamespace, "all", false, "Generate policies for all pods in the current namespace")
}

var networkPolicyCmd = &cobra.Command{
	Use:     "networkpolicy [pod-name]",
	Aliases: []string{"netpol"},
	Short:   "Generate network policy",
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
				cmd.Usage()
				return
			}
			options.Mode = k8s.SinglePod
			options.PodName = args[0]
			options.Namespace = namespace
		}

		stopChan, errChan, done := k8s.PortForward(config)
		<-done // Block until we receive a notification from the goroutine that port-forwarding has been set up
		go func() {
			for err := range errChan {
				log.Fatal().Err(err).Msg("Error setting up port-forwarding")
			}
		}()
		log.Debug().Msg("Port forwarding set up successfully.")
		k8s.GenerateNetworkPolicy(options, config)
		close(stopChan)
	},
}
