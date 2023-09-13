package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/arx-inc/advisor/pkg/k8s"
	"github.com/spf13/cobra"
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
			fmt.Println("Error initializing Kubernetes client:", err)
			os.Exit(1)
		}

		fmt.Printf("Using kubeconfig file: %s\n", config.Kubeconfig)
		fmt.Printf("Using namespace: %s\n", config.Namespace)

		podName := args[0]

		stopChan, errChan, done := k8s.PortForward(config)
		<-done // Block until we receive a notification from the goroutine that port-forwarding has been set up
		go func() {
			for err := range errChan {
				log.Fatalf("Failed to start port-forwarding: %v", err)
			}
		}()
		fmt.Println("Port forwarding set up successfully.")
		k8s.GenerateNetworkPolicy(podName, config.Namespace)
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
		fmt.Printf("Generating seccomp profile for pod: %s\n", podName)
	},
}
