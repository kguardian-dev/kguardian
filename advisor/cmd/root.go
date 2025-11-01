package cmd

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var (
	kubeConfigFlags *genericclioptions.ConfigFlags
	debug           bool // To store the value of the --debug flag
)

func init() {
	// Set up logging to console with consistent full timestamp format
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Add your sub-commands
	genCmd.AddCommand(networkPolicyCmd)
	genCmd.AddCommand(seccompCmd)

	// Initialize kubeConfigFlags
	kubeConfigFlags = genericclioptions.NewConfigFlags(true)

	// Add global flags from kubeConfigFlags to rootCmd
	kubeConfigFlags.AddFlags(rootCmd.PersistentFlags())

	// Add debug flag to rootCmd so it's available for all sub-commands
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "sets log level to debug")

	// Add version flag to rootCmd
	rootCmd.Flags().BoolP("version", "v", false, "print version information and exit")

	// Add PersistentPreRun for handling Kubernetes setup
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Skip version command to avoid unnecessary Kubernetes setup
		if cmd.Name() == "version" {
			return
		}

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
	}

	rootCmd.AddCommand(genCmd)

	// Set up colored output with consistent RFC3339 timestamp format
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}
	log.Logger = log.Output(consoleWriter)
}

var rootCmd = &cobra.Command{
	Use:   "kguardian",
	Short: "kguardian is a Kubernetes security profile generator using eBPF",
	Long: `kguardian analyzes runtime behavior using eBPF and generates tailored security
	       resources like Network Policies and Seccomp Profiles. It helps improve the
	       security posture of applications running in Kubernetes clusters by creating
	       least-privilege security policies based on observed behavior.
	       Complete documentation is available at https://github.com/kguardian-dev/kguardian`,
}

func Execute() {
	// Check if --version or -v flag is provided as the only argument
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		// Manually run the version command
		versionCmd.Run(versionCmd, []string{})
		return
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
