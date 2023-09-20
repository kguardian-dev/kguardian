package cmd

import (
	"os"

	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	// Set up logging to console
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: zerolog.TimeFieldFormat, NoColor: false}
	log.Logger = log.Output(consoleWriter)

	genCmd.AddCommand(networkPolicyCmd, seccompCmd)
	genCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file to use for CLI requests.")
	genCmd.PersistentFlags().String("namespace", "", "If present, the namespace scope for this CLI request")

	rootCmd.AddCommand(genCmd)
}

var rootCmd = &cobra.Command{
	Use:   "xentra",
	Short: "Xentra is a security tool for enhancing Kubernetes application profiles",
	Long: `Xentra is designed to improve the security profile of applications running in
	       Kubernetes clusters. It provides various functionalities like generating network
	       policies, seccomp profiles, and more to ensure that your applications meet
	       best security practices.
	       Complete documentation is available at [Your Documentation URL]`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
