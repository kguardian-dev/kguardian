package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
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
	policyType     string
	dryRun         bool
	outputDir      string
)

var networkPolicyCmd = &cobra.Command{
	Use:     "networkpolicy [pod-name]",
	Aliases: []string{"netpol"},
	Short:   "Generate Kubernetes NetworkPolicies to secure your cluster",
	Long:    `Generate Kubernetes NetworkPolicies for pods in your Kubernetes cluster, based on network traffic collected from the broker.`,
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Set up the logger first, so we get useful debug output
		setupLogger()

		// For network policies, always ensure outputDir is set to "network-policies"
		// if not explicitly changed by the user
		if !cmd.Flags().Changed("output-dir") {
			outputDir = "network-policies"
		}

		log.Info().Msgf("Generating %s network policies", policyType)
		if dryRun {
			log.Info().Msg("Running in dry-run mode - policies will be saved to files but not applied to the cluster")
		} else {
			log.Info().Msg("Running in apply mode - policies will be applied to the cluster")
		}

		log.Debug().Msg("Setting up Kubernetes configuration")
		config, err := k8s.GetConfig(dryRun)
		if err != nil {
			log.Error().Err(err).Msg("Error retrieving Kubernetes configuration")
			fmt.Fprintf(os.Stderr, "Failed to get Kubernetes configuration: %v\n", err)
			fmt.Fprintf(os.Stderr, "If running directly as 'advisor', try using kubectl plugin mode: kubectl guardian gen networkpolicy\n")
			os.Exit(1)
		}

		// Set output directory in config
		config.OutputDir = outputDir
		log.Debug().Msgf("Using output directory: %s", outputDir)

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

		// Set dry run mode in config
		config.DryRun = dryRun

		// Check for --all or --all-namespaces flags
		if allNamespaces {
			log.Info().Msg("Generating policies for all pods in all namespaces")
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
			// Check if a pod name was provided
			if len(args) != 1 {
				log.Error().Msg("Pod name is required when not using --all or --all-namespaces flags")
				fmt.Fprintf(os.Stderr, "Error: pod name argument is required. Use --all to generate for all pods in a namespace.\n")
				os.Exit(1)
			}

			podName := args[0]
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

			log.Info().Msgf("Generating policy for pod %s in namespace %s", podName, namespace)
			options := k8s.GenerateOptions{
				Mode:      k8s.SinglePod,
				PodName:   podName,
				Namespace: namespace,
			}

			if policyType == "cilium" {
				k8s.GenerateCiliumNetworkPolicy(options, config)
			} else {
				k8s.GenerateNetworkPolicy(options, config)
			}
		}
	},
}

func init() {
	genCmd.AddCommand(networkPolicyCmd)

	// Add flags
	networkPolicyCmd.Flags().StringP("namespace", "n", "", "Namespace (defaults to current context namespace)")
	networkPolicyCmd.Flags().BoolVarP(&allInNamespace, "all", "a", false, "Generate policies for all pods in the specified or current namespace")
	networkPolicyCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate policies for all pods in all namespaces")
	networkPolicyCmd.Flags().StringVarP(&policyType, "type", "t", "kubernetes", "Type of network policy to generate (kubernetes or cilium)")
	networkPolicyCmd.Flags().BoolVar(&dryRun, "dry-run", true, "Only generate policies and save to files without applying them to the cluster")
	networkPolicyCmd.Flags().StringVar(&outputDir, "output-dir", "network-policies", "Directory to store generated network policies")

	// Add completion for the policy type flag
	networkPolicyCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"kubernetes", "cilium"}, cobra.ShellCompDirectiveNoFileComp
	})
}

// setupLogger configures the global logger
func setupLogger() {
	// Set up zerolog with consistent timestamp format
	zerolog.TimeFieldFormat = time.RFC3339

	// Set logging level based on verbose flag or environment variable
	logLevel := zerolog.InfoLevel
	if os.Getenv("DEBUG") == "true" || os.Getenv("VERBOSE") == "true" {
		logLevel = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(logLevel)

	// Use a console writer with full RFC3339 timestamp format
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}
	log.Logger = log.Output(output)

	log.Debug().Msg("Logger initialized with debug level")
}
