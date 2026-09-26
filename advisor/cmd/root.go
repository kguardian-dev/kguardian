package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var (
	kubeConfigFlags *genericclioptions.ConfigFlags
	debug           bool // To store the value of the --debug flag
	brokerNamespace string
	brokerService   string
	brokerTokenFile string
)

// resolveBrokerToken returns the bearer token the CLI presents to the broker:
// the contents of --broker-token-file when given, else $KGUARDIAN_BROKER_TOKEN,
// else $BROKER_AUTH_TOKEN, else "" (no header, for a broker without auth).
// There is deliberately no flag taking the token itself: argv is visible to
// every user on the machine through ps.
func resolveBrokerToken(file string, getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	if file != "" {
		b, err := readFile(file)
		if err != nil {
			return "", fmt.Errorf("--broker-token-file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("--broker-token-file %s is empty", file)
		}
		return tok, nil
	}
	for _, key := range []string{"KGUARDIAN_BROKER_TOKEN", "BROKER_AUTH_TOKEN"} {
		if tok := strings.TrimSpace(getenv(key)); tok != "" {
			return tok, nil
		}
	}
	return "", nil
}

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

	// Add broker override flags
	rootCmd.PersistentFlags().StringVar(&brokerNamespace, "broker-namespace", "", "Namespace where the kguardian broker is installed (default \"kguardian\")")
	rootCmd.PersistentFlags().StringVar(&brokerService, "broker-service", "", "Name of the kguardian broker service (default \"broker\")")
	rootCmd.PersistentFlags().StringVar(&brokerTokenFile, "broker-token-file", "", "File holding the broker read token, for a broker with auth enabled (default: $KGUARDIAN_BROKER_TOKEN, then $BROKER_AUTH_TOKEN)")

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

		token, err := resolveBrokerToken(brokerTokenFile, os.Getenv, os.ReadFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Error reading the broker token")
		}
		api.BrokerAuthToken = token

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
		// A gate result (images vulns --fail-on) is not a failure to run:
		// it exits with its own code and its own message.
		var ge *gateError
		if errors.As(err, &ge) {
			fmt.Fprintln(os.Stderr, ge.msg)
			os.Exit(ge.code)
		}
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
