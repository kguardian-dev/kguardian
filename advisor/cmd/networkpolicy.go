package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	"github.com/kguardian-dev/kguardian/advisor/pkg/network"
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
			fmt.Fprintf(os.Stderr, "Failed to get Kubernetes configuration: %v\n\n", err)
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Verify your kubeconfig is valid:\n")
			fmt.Fprintf(os.Stderr, "    kubectl cluster-info\n")
			fmt.Fprintf(os.Stderr, "  Check your current context:\n")
			fmt.Fprintf(os.Stderr, "    kubectl config current-context\n")
			fmt.Fprintf(os.Stderr, "\nIf running directly as 'advisor', try kubectl plugin mode:\n")
			fmt.Fprintf(os.Stderr, "  kubectl guardian gen networkpolicy\n")
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
				fmt.Fprintf(os.Stderr, "Failed to get current namespace: %v\n\n", err)
				fmt.Fprintf(os.Stderr, "Diagnosis:\n")
				fmt.Fprintf(os.Stderr, "  Check your kubeconfig context has a namespace set:\n")
				fmt.Fprintf(os.Stderr, "    kubectl config view --minify\n")
				fmt.Fprintf(os.Stderr, "  Or specify a namespace explicitly:\n")
				fmt.Fprintf(os.Stderr, "    kubectl guardian gen networkpolicy --namespace <namespace> <pod-name>\n")
				os.Exit(1)
			}
		}

		log.Debug().Msg("Starting port forwarding")
		stopChan, errChan, done := k8s.PortForward(config, brokerNamespace, brokerService)
		defer close(stopChan) // Ensure port forwarding is stopped when command finishes

		// Wait for port forwarding to be ready or error
		select {
		case <-done:
			log.Debug().Msg("Port forwarding setup completed")
		case err := <-errChan:
			log.Error().Err(err).Msg("Port forwarding failed")
			fmt.Fprintf(os.Stderr, "Port forwarding failed: %v\n\n", err)
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Ensure the broker pod is running:\n")
			fmt.Fprintf(os.Stderr, "    kubectl get pods -n kguardian -l app=kguardian-broker\n")
			fmt.Fprintf(os.Stderr, "  Check the broker service exists:\n")
			fmt.Fprintf(os.Stderr, "    kubectl get svc -n kguardian\n")
			fmt.Fprintf(os.Stderr, "  Verify connectivity manually:\n")
			fmt.Fprintf(os.Stderr, "    kubectl port-forward -n kguardian svc/kguardian-broker 9090:9090\n")
			fmt.Fprintf(os.Stderr, "  Check broker pod logs for errors:\n")
			fmt.Fprintf(os.Stderr, "    kubectl logs -n kguardian -l app=kguardian-broker\n")
			os.Exit(1)
		case <-ctx.Done():
			log.Error().Msg("Timeout waiting for port forwarding")
			fmt.Fprintf(os.Stderr, "Timed out waiting for port forwarding to become ready.\n\n")
			fmt.Fprintf(os.Stderr, "Diagnosis:\n")
			fmt.Fprintf(os.Stderr, "  Ensure the broker pod is running and healthy:\n")
			fmt.Fprintf(os.Stderr, "    kubectl get pods -n kguardian -l app=kguardian-broker\n")
			fmt.Fprintf(os.Stderr, "  Check broker pod logs:\n")
			fmt.Fprintf(os.Stderr, "    kubectl logs -n kguardian -l app=kguardian-broker\n")
			fmt.Fprintf(os.Stderr, "  Verify the broker service is reachable:\n")
			fmt.Fprintf(os.Stderr, "    kubectl port-forward -n kguardian svc/kguardian-broker 9090:9090\n")
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
			fmt.Fprintf(os.Stderr, "Failed to create output directory %q: %v\n\n", outputDir, err)
			fmt.Fprintf(os.Stderr, "Next steps:\n")
			fmt.Fprintf(os.Stderr, "  Check directory permissions in the current working directory.\n")
			fmt.Fprintf(os.Stderr, "  Specify a different output directory:\n")
			fmt.Fprintf(os.Stderr, "    kubectl guardian gen networkpolicy --output-dir /tmp/network-policies <pod-name>\n")
			os.Exit(1)
		}

		// Check for --all or --all-namespaces flags
		if allNamespaces {
			log.Info().Msg("Generating policies for all pods in all namespaces")
			// Get all running pods across all namespaces
			pods, err := k8s.GetAllPodsInAllNamespaces(ctx, config)
			if err != nil {
				log.Error().Err(err).Msg("Error getting pods in all namespaces")
				fmt.Fprintf(os.Stderr, "Failed to list pods across all namespaces: %v\n\n", err)
				fmt.Fprintf(os.Stderr, "Diagnosis:\n")
				fmt.Fprintf(os.Stderr, "  Verify cluster-wide pod list permissions:\n")
				fmt.Fprintf(os.Stderr, "    kubectl auth can-i list pods --all-namespaces\n")
				os.Exit(1)
			}
			processPods(pods, policyService, policyServiceType)
		} else if allInNamespace {
			// Determine namespace (use targetNamespace which was resolved earlier)
			log.Info().Msgf("Generating policies for all pods in namespace: %s", targetNamespace)
			// Get all running pods in the specified namespace
			pods, err := k8s.GetPodsInNamespace(ctx, config, targetNamespace)
			if err != nil {
				log.Error().Err(err).Msgf("Error getting pods in namespace %s", targetNamespace)
				fmt.Fprintf(os.Stderr, "Failed to list pods in namespace %q: %v\n\n", targetNamespace, err)
				fmt.Fprintf(os.Stderr, "Diagnosis:\n")
				fmt.Fprintf(os.Stderr, "  Check the namespace exists:\n")
				fmt.Fprintf(os.Stderr, "    kubectl get namespace %s\n", targetNamespace)
				fmt.Fprintf(os.Stderr, "  Verify pod list permissions in the namespace:\n")
				fmt.Fprintf(os.Stderr, "    kubectl auth can-i list pods -n %s\n", targetNamespace)
				os.Exit(1)
			}
			processPods(pods, policyService, policyServiceType)
		} else {
			// Check if a pod name was provided
			if len(args) != 1 {
				log.Error().Msg("Pod name is required when not using --all or --all-namespaces flags")
				fmt.Fprintf(os.Stderr, "Error: pod name argument is required.\n\n")
				fmt.Fprintf(os.Stderr, "Usage:\n")
				fmt.Fprintf(os.Stderr, "  kubectl guardian gen networkpolicy <pod-name>\n")
				fmt.Fprintf(os.Stderr, "  kubectl guardian gen networkpolicy --all             # all pods in current namespace\n")
				fmt.Fprintf(os.Stderr, "  kubectl guardian gen networkpolicy --all-namespaces  # all pods in all namespaces\n")
				os.Exit(1)
			}

			podName := args[0]
			log.Info().Msgf("Generating policy for pod %s in namespace %s", podName, targetNamespace)
			if err := policyService.GenerateAndHandlePolicy(podName, policyServiceType); err != nil {
				log.Error().Err(err).Msgf("Error generating policy for pod %s", podName)
				fmt.Fprintf(os.Stderr, "Failed to generate policy for pod %q: %v\n\n", podName, err)
				fmt.Fprintf(os.Stderr, "Diagnosis:\n")
				fmt.Fprintf(os.Stderr, "  Verify the pod exists and is running:\n")
				fmt.Fprintf(os.Stderr, "    kubectl get pod %s -n %s\n", podName, targetNamespace)
				fmt.Fprintf(os.Stderr, "  Confirm the broker has traffic data for this pod:\n")
				fmt.Fprintf(os.Stderr, "    kubectl logs -n kguardian -l app=kguardian-broker | grep %s\n", podName)
				os.Exit(1)
			}
		}
	},
}

// processPods processes a list of pods and generates policies for them
func processPods(pods []corev1.Pod, policyService *network.PolicyService, policyType network.PolicyType) {
	podNames := make([]string, len(pods))
	for i, pod := range pods {
		podNames[i] = pod.Name
	}
	if err := policyService.BatchGenerateAndHandlePolicies(podNames, policyType); err != nil {
		log.Error().Err(err).Msg("Error generating policies for pods")
	}
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
	networkPolicyCmd.Flags().StringP("namespace", "n", "", "Kubernetes namespace to target (defaults to current context namespace, e.g. default, kube-system)")
	networkPolicyCmd.Flags().BoolVarP(&allInNamespace, "all", "a", false, "Generate policies for all pods in the specified or current namespace")
	networkPolicyCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Generate policies for all pods in all namespaces")
	networkPolicyCmd.Flags().StringVarP(&policyType, "type", "t", "kubernetes", "Type of network policy to generate (kubernetes, cilium)")
	networkPolicyCmd.Flags().BoolVar(&dryRun, "dry-run", true, "Only generate policies and save to files without applying them to the cluster (true, false)")
	networkPolicyCmd.Flags().StringVar(&outputDir, "output-dir", "network-policies", "Directory to store generated network policy YAML files")

	// Add completion for the policy type flag
	_ = networkPolicyCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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
