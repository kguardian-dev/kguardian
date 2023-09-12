package cmd

import (
	"fmt"
	"os"

	"github.com/arx-inc/advisor/pkg/k8s"
	"github.com/spf13/cobra"
)

func init() {
	genCmd.AddCommand(networkPolicyCmd, seccompCmd)
	rootCmd.AddCommand(genCmd)
}

var rootCmd = &cobra.Command{
	Use:   "arx",
	Short: "Arx is a security tool for enhancing Kubernetes application profiles",
	Long: `Arx is designed to improve the security profile of applications running in
	       Kubernetes clusters. It provides various functionalities like generating network
	       policies, seccomp profiles, and more to ensure that your applications meet
	       best security practices.
	       Complete documentation is available at [Your Documentation URL]`,
}

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate resources",
}

var networkPolicyCmd = &cobra.Command{
	Use:   "networkpolicy [pod-name]",
	Short: "Generate network policy",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		podName := args[0]
		fmt.Printf("Generating network policy for pod: %s\n", podName)
		k8s.GenerateNetworkPolicy(podName)
	},
}

var seccompCmd = &cobra.Command{
	Use:   "seccomp [pod-name]",
	Short: "Generate seccomp profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		podName := args[0]
		fmt.Printf("Generating seccomp profile for pod: %s\n", podName)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
