package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	genCmd.AddCommand(networkPolicyCmd, seccompCmd)
	genCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file to use for CLI requests.")
	genCmd.PersistentFlags().String("namespace", "", "If present, the namespace scope for this CLI request")

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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
