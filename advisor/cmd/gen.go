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

var networkPolicyCmd = &cobra.Command{
	Use:     "networkpolicy [pod-name]",
	Aliases: []string{"netpol"},
	Short:   "Generate network policy",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		namespace, _ := cmd.Flags().GetString("namespace")

		config, err := k8s.NewConfig(kubeconfig, namespace)
		if err != nil {
			log.Fatal().Err(err).Msg("Error initializing Kubernetes client")
		}

		log.Info().Msgf("Using kubeconfig file: %s", config.Kubeconfig)
		log.Info().Msgf("Using namespace: %s", config.Namespace)
		podName := args[0]

		stopChan, errChan, done := k8s.PortForward(config)
		<-done // Block until we receive a notification from the goroutine that port-forwarding has been set up
		go func() {
			for err := range errChan {
				log.Fatal().Err(err).Msg("Error setting up port-forwarding")
			}
		}()
		log.Info().Msg("Port forwarding set up successfully.")
		k8s.GenerateNetworkPolicy(podName, config)
		close(stopChan)
	},
}

var seccompCmd = &cobra.Command{
	Use:     "seccomp [pod-name]",
	Aliases: []string{"sc"},
	Short:   "Generate seccomp profile",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		podName := args[0]
		log.Info().Msgf("Generating seccomp profile for pod: %s", podName)
	},
}
