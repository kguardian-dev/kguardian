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
		// Retrieve the config from the command context
		config, ok := cmd.Context().Value(k8s.ConfigKey).(*k8s.Config)
		if !ok {
			log.Fatal().Msg("Failed to retrieve Kubernetes configuration")
		}
		podName := args[0]

		stopChan, errChan, done := k8s.PortForward(config)
		<-done // Block until we receive a notification from the goroutine that port-forwarding has been set up
		go func() {
			for err := range errChan {
				log.Fatal().Err(err).Msg("Error setting up port-forwarding")
			}
		}()
		log.Debug().Msg("Port forwarding set up successfully.")
		k8s.GenerateNetworkPolicy(podName, config)
		close(stopChan)
	},
}
