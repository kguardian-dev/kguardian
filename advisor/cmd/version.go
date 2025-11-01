package cmd

import (
	"fmt"
	"runtime"

	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
)

// Version information - these will be set during build
var (
	Version   = "development"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the client and server version information",
	Long:  `Display the client version and, if connected to a Kubernetes server, the server version as well.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set up the logger first, so we get useful debug output
		setupLogger()

		// Display client version information
		fmt.Printf("Client Version:\n")
		fmt.Printf("  Version:    %s\n", Version)
		fmt.Printf("  Git Commit: %s\n", GitCommit)
		fmt.Printf("  Build Date: %s\n", BuildDate)
		fmt.Printf("  Go Version: %s\n", runtime.Version())
		fmt.Printf("  Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)

		// Try to get server version information
		fmt.Printf("\nServer Version:\n")

		// Get Kubernetes config
		config, err := k8s.GetConfig(true) // Use dry-run mode
		if err != nil {
			log.Debug().Err(err).Msg("Failed to get Kubernetes configuration")
			fmt.Printf("  Unable to connect to Kubernetes server: %v\n", err)
			return
		}

		if config.Clientset == nil {
			log.Debug().Msg("Kubernetes clientset is nil")
			fmt.Printf("  Not connected to a Kubernetes server\n")
			return
		}

		// Get server version
		serverVersion, err := config.Clientset.Discovery().ServerVersion()
		if err != nil {
			log.Debug().Err(err).Msg("Failed to get server version")
			fmt.Printf("  Unable to retrieve server version: %v\n", err)
			return
		}

		fmt.Printf("  Version:     %s\n", serverVersion.GitVersion)
		fmt.Printf("  Platform:    %s/%s\n", serverVersion.Platform, serverVersion.GoVersion)
		fmt.Printf("  Build Date:  %s\n", serverVersion.BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
