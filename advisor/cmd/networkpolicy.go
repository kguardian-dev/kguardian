package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/rs/zerolog/log"
	"github.com/rs/zerolog"
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
	policyType     string
	testMode       bool
	dryRun         bool
)

var networkPolicyCmd = &cobra.Command{
	Use:     "networkpolicy [pod-name]",
	Aliases: []string{"netpol"},
	Short:   "Generate Kubernetes NetworkPolicies to secure your cluster",
	Long:    `Generate Kubernetes NetworkPolicies for any Pod or group of Pods in your Kubernetes cluster, based on network traffic collected from the broker.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set up the logger first, so we get useful debug output
		setupLogger()

		log.Info().Msgf("Generating %s network policies", policyType)
		if testMode {
			log.Warn().Msg("Running in test mode - no Kubernetes connection required")
		}
		if dryRun {
			log.Info().Msg("Running in dry-run mode - no changes will be applied")
		}

		// Only attempt to get the Kubernetes config if not in test mode
		var config *k8s.Config
		var err error

		if !testMode {
			log.Debug().Msg("Setting up Kubernetes configuration")
			config, err = k8s.GetConfig(dryRun)
			if err != nil {
				log.Error().Err(err).Msg("Error retrieving Kubernetes configuration")
				fmt.Fprintf(os.Stderr, "Failed to get Kubernetes configuration: %v\n", err)
				fmt.Fprintf(os.Stderr, "If running directly as 'advisor', try using kubectl plugin mode: kubectl guardian gen networkpolicy\n")
				os.Exit(1)
			}

			// Setup port forwarding with a timeout context
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Get namespace from flag or current context
			targetNamespace, _ := cmd.Flags().GetString("namespace")
			if targetNamespace == "" && !allNamespaces {
				// If namespace flag wasn't specified and we're not targeting all namespaces,
				// get the namespace from the current context
				targetNamespace, err = k8s.GetCurrentNamespace(config)
				if err != nil {
					log.Error().Err(err).Msg("Error getting current namespace from context")
					fmt.Fprintf(os.Stderr, "Failed to get current namespace: %v\n", err)
					os.Exit(1)
				}
				log.Info().Msgf("Using namespace from current context: %s", targetNamespace)
			}

			log.Debug().Msg("Starting port forwarding")
			stopChan, errChan, done := k8s.PortForward(config)
			defer close(stopChan) // Ensure port forwarding is stopped when command finishes

			// Wait for port forwarding to be ready or error
			select {
			case <-done:
				log.Debug().Msg("Port forwarding setup completed")
			case err := <-errChan:
				log.Error().Err(err).Msg("Port forwarding failed")
				fmt.Fprintf(os.Stderr, "Failed to setup port forwarding: %v\n", err)
				fmt.Fprintf(os.Stderr, "If running directly as 'advisor', try using kubectl plugin mode: kubectl guardian gen networkpolicy\n")
				os.Exit(1)
			case <-ctx.Done():
				log.Error().Msg("Timeout waiting for port forwarding")
				fmt.Fprintf(os.Stderr, "Timeout waiting for port forwarding setup\n")
				os.Exit(1)
			}
		} else {
			// Create minimal config for test mode
			log.Warn().Msg("Test mode: Using minimal configuration")
			config = &k8s.Config{
				DryRun: true, // Treat test mode as dry run too
			}
		}

		// Set dry run mode in config
		config.DryRun = dryRun

		if allNamespaces {
			if policyType == "cilium" {
				k8s.GenerateCiliumNetworkPoliciesForAllNamespaces(config)
			} else {
				k8s.GenerateNetworkPoliciesForAllNamespaces(config)
			}
		} else if allInNamespace {
			namespace, _ := cmd.Flags().GetString("namespace")
			if namespace == "" {
				var err error
				namespace, err = k8s.GetCurrentNamespace(config)
				if err != nil {
					log.Error().Err(err).Msg("Error getting current namespace")
					fmt.Fprintf(os.Stderr, "Failed to get current namespace: %v\n", err)
					os.Exit(1)
				}
			}
			log.Info().Msgf("Generating policies for all pods in namespace: %s", namespace)
			if policyType == "cilium" {
				k8s.GenerateCiliumNetworkPoliciesForNamespace(config, namespace)
			} else {
				k8s.GenerateNetworkPoliciesForNamespace(config, namespace)
			}
		} else {
			podName, _ := cmd.Flags().GetString("pod")
			namespace, _ := cmd.Flags().GetString("namespace")

			if podName == "" {
				log.Error().Msg("Pod name is required when not using --all or --all-namespaces")
				fmt.Fprintf(os.Stderr, "Please specify a pod name with --pod\n")
				os.Exit(1)
			}

			if namespace == "" {
				var err error
				namespace, err = k8s.GetCurrentNamespace(config)
				if err != nil {
					log.Error().Err(err).Msg("Error getting current namespace")
					fmt.Fprintf(os.Stderr, "Failed to get current namespace: %v\n", err)
					os.Exit(1)
				}
			}

			log.Info().Msgf("Generating policy for pod %s in namespace %s", podName, namespace)
			if policyType == "cilium" {
				k8s.CreateCiliumNetworkPolicy(config, namespace, podName)
			} else {
				k8s.CreateKubernetesNetworkPolicy(config, namespace, podName)
			}
		}
	},
}

func init() {
	genCmd.AddCommand(networkPolicyCmd)

	// Add flags
	networkPolicyCmd.Flags().StringP("pod", "p", "", "Pod name")
	networkPolicyCmd.Flags().StringP("namespace", "n", "", "Namespace (defaults to current context namespace)")
	networkPolicyCmd.Flags().BoolVarP(&allInNamespace, "all", "a", false, "Generate policies for all pods in the specified or current namespace")
	networkPolicyCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate policies for all pods in all namespaces")
	networkPolicyCmd.Flags().StringVarP(&policyType, "type", "t", "kubernetes", "Type of network policy to generate (kubernetes or cilium)")
	networkPolicyCmd.Flags().BoolVar(&testMode, "test-mode", false, "Test mode - skips Kubernetes connection check (for development only)")
	networkPolicyCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Dry run - print policies that would be generated but don't apply them")

	// Add completion for the policy type flag
	networkPolicyCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"kubernetes", "cilium"}, cobra.ShellCompDirectiveNoFileComp
	})
}

// setupLogger configures the global logger
func setupLogger() {
	// Set up zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set logging level based on verbose flag or environment variable
	logLevel := zerolog.InfoLevel
	if os.Getenv("DEBUG") == "true" || os.Getenv("VERBOSE") == "true" {
		logLevel = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(logLevel)

	// Use a console writer with color support
	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	log.Logger = log.Output(output)

	log.Debug().Msg("Logger initialized with debug level")
}
