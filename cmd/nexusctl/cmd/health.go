package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ConstantineCTF/nexus/cmd/nexusctl/config"
	"github.com/ConstantineCTF/nexus/pkg/sdk"
)

// healthCmd represents the health command
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check server health",
	Long: `Check the health status of the NEXUS server.

This command can be used without authentication if a server URL is configured.

Example:
  nexusctl health`,
	RunE: runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

func runHealth(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	serverAddr := cfg.Server
	if serverAddr == "" {
		// Try to get server from flag
		if serverURL != "" {
			serverAddr = serverURL
		} else {
			printError("No server configured. Run 'nexusctl login' first or specify --server")
			return nil
		}
	}

	sdkConfig := sdk.NewConfig(serverAddr)
	client := sdk.NewClient(sdkConfig)

	health, err := client.Health()
	if err != nil {
		printError("Health check failed: %v", err)
		return nil
	}

	if isTableFormat() {
		statusColor := successColor
		if health.Status != "healthy" {
			statusColor = errorColor
		}

		fmt.Printf("Server: %s\n", serverAddr)
		fmt.Print("Status: ")
		statusColor.Println(health.Status)
		fmt.Printf("Time:   %s\n", health.Timestamp.Format("2006-01-02 15:04:05"))
		if health.Error != "" {
			fmt.Printf("Error:  %s\n", health.Error)
		}
	} else {
		data := map[string]interface{}{
			"server":    serverAddr,
			"status":    health.Status,
			"timestamp": health.Timestamp,
		}
		if health.Error != "" {
			data["error"] = health.Error
		}
		outputData(data)
	}

	return nil
}

// SetServerURL is used to set the server URL from other commands
func SetServerURL(url string) {
	serverURL = url
}

// GetConfig returns the current config for external use
func GetConfig() (*config.Config, error) {
	return loadConfig()
}
