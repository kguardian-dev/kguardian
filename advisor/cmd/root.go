package cmd

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/xentra-ai/advisor/pkg/k8s"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var (
	kubeConfigFlags *genericclioptions.ConfigFlags
	debug           bool // To store the value of the --debug flag
)

func init() {
	// Set up logging to console
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Add your sub-commands
	genCmd.AddCommand(networkPolicyCmd)

	// Initialize kubeConfigFlags
	kubeConfigFlags = genericclioptions.NewConfigFlags(true)

	// Add global flags from kubeConfigFlags to rootCmd
	kubeConfigFlags.AddFlags(rootCmd.PersistentFlags())

	// Add debug flag to rootCmd so it's available for all sub-commands
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "sets log level to debug")

	rootCmd.AddCommand(genCmd)

	// Set up colored output
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: zerolog.TimeFieldFormat, NoColor: false}
	log.Logger = log.Output(consoleWriter)
}

var rootCmd = &cobra.Command{
	Use:   "xentra",
	Short: "Xentra is a security tool for enhancing Kubernetes application profiles",
	Long: `Xentra is designed to improve the security profile of applications running in
	       Kubernetes clusters. It provides various functionalities like generating network
	       policies, seccomp profiles, and more to ensure that your applications meet
	       best security practices.
	       Complete documentation is available at [Your Documentation URL]`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Adjust log level according to the flag
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		// Initialize Kubernetes config and logging
		config, err := k8s.NewConfig(kubeConfigFlags)
		if err != nil {
			log.Fatal().Err(err).Msg("Error initializing Kubernetes client")
		}

		kubeconfigPath := kubeConfigFlags.ToRawKubeConfigLoader().ConfigAccess().GetDefaultFilename()
		if err != nil {
			log.Fatal().Err(err).Msg("Error initializing Kubernetes client")
		}

		namespace, _, err := kubeConfigFlags.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get namespace")
		}

		log.Info().Msgf("Using kubeconfig file: %s", kubeconfigPath)
		log.Info().Msgf("Using namespace: %s", namespace)

		// Create a new context with the config and assign it to the command
		ctx := context.WithValue(cmd.Context(), k8s.ConfigKey, config)
		cmd.SetContext(ctx)
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
