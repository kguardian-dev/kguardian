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
	"github.com/xentra-ai/advisor/pkg/network"
	corev1 "k8s.io/api/core/v1"
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
	Long:    `Generate Kubernetes NetworkPolicies for pods in your Kubernetes cluster, based on network traffic collected from the controller(s).`,
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

		// Create policy service with appropriate configuration
		var policyServiceType network.PolicyType
		if policyType == "cilium" {
			policyServiceType = network.CiliumPolicy
		} else {
			policyServiceType = network.StandardPolicy
		}

		// Create the policy service
		policyService := createPolicyService(config, policyServiceType)

		// Initialize output directory
		if err := policyService.InitOutputDirectory(); err != nil {
			log.Error().Err(err).Msg("Failed to initialize output directory")
			os.Exit(1)
		}

		// Check for --all or --all-namespaces flags
		if allNamespaces {
			log.Info().Msg("Generating policies for all pods in all namespaces")
			// Get all running pods across all namespaces
			pods, err := k8s.GetAllPodsInAllNamespaces(ctx, config)
			if err != nil {
				log.Error().Err(err).Msg("Error getting pods in all namespaces")
				os.Exit(1)
			}
			if err := policyService.BatchGenerateAndHandlePolicies(pods, policyServiceType); err != nil {
				log.Error().Err(err).Msg("Completed with errors while generating policies for all namespaces")
			}
		} else if allInNamespace {
			// Determine namespace (use targetNamespace which was resolved earlier)
			log.Info().Msgf("Generating policies for all pods in namespace: %s", targetNamespace)
			// Get all running pods in the specified namespace
			pods, err := k8s.GetPodsInNamespace(ctx, config, targetNamespace)
			if err != nil {
				log.Error().Err(err).Msgf("Error getting pods in namespace %s", targetNamespace)
				os.Exit(1)
			}
			if err := policyService.BatchGenerateAndHandlePolicies(pods, policyServiceType); err != nil {
				log.Error().Err(err).Msgf("Completed with errors while generating policies in namespace %s", targetNamespace)
			}
		} else {
			// Check if a pod name was provided
			if len(args) != 1 {
				log.Error().Msg("Pod name is required when not using --all or --all-namespaces flags")
				fmt.Fprintf(os.Stderr, "Error: pod name argument is required. Use --all to generate for all pods in a namespace.\n")
				os.Exit(1)
			}

			podName := args[0]
			log.Info().Msgf("Generating policy for pod %s in namespace %s", podName, targetNamespace)

			podCtx, podCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer podCancel()
			pod, err := k8s.GetPod(podCtx, config, targetNamespace, podName)
			if err != nil {
				log.Error().Err(err).Msgf("Error retrieving pod %s in namespace %s", podName, targetNamespace)
				os.Exit(1)
			}

			if err := policyService.GenerateAndHandlePolicy(pod, policyServiceType); err != nil {
				log.Error().Err(err).Msgf("Error generating policy for pod %s", podName)
				os.Exit(1)
			}
		}
	},
}

// createPolicyService creates and initializes a policy service
func createPolicyService(config *k8s.Config, defaultType network.PolicyType) *network.PolicyService {
	// Create a config adapter to implement the ConfigProvider interface
	configAdapter := &k8sConfigAdapter{config: config}

	// Create the policy service
	policyService := network.NewPolicyService(configAdapter, defaultType)

	// Register generators
	policyService.RegisterGenerator(network.NewStandardPolicyGenerator())
	policyService.RegisterGenerator(network.NewCiliumPolicyGenerator())

	return policyService
}

// k8sConfigAdapter adapts the k8s.Config to the network.ConfigProvider interface
type k8sConfigAdapter struct {
	config *k8s.Config
}

func (a *k8sConfigAdapter) GetClientset() interface{} {
	return a.config.Clientset
}

func (a *k8sConfigAdapter) IsDryRun() bool {
	return a.config.DryRun
}

func (a *k8sConfigAdapter) GetOutputDir() string {
	return a.config.OutputDir
}

func init() {
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
