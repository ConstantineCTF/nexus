package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ConstantineCTF/nexus/cmd/nexusctl/config"
	"github.com/ConstantineCTF/nexus/pkg/sdk"
)

var (
	// Global flags
	outputFormat string
	cfgFile      string

	// Colors for output
	successColor = color.New(color.FgGreen)
	warningColor = color.New(color.FgYellow)
	errorColor   = color.New(color.FgRed)
	infoColor    = color.New(color.FgCyan)
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "nexusctl",
	Short: "NEXUS CLI - Secrets Management Tool",
	Long: `nexusctl is a command-line interface for interacting with the NEXUS
secrets management server. It allows you to manage secrets, API keys,
view audit logs, and more.

To get started, login to a NEXUS server:
  nexusctl login --server http://localhost:9000

Then you can manage secrets:
  nexusctl secret create my/secret "secret-value"
  nexusctl secret get my/secret
  nexusctl secret list`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default is ~/.nexus/config.yaml)")
}

// loadConfig loads the configuration file
func loadConfig() (*config.Config, error) {
	if cfgFile != "" {
		return config.LoadFrom(cfgFile)
	}
	return config.Load()
}

// getClient creates an SDK client from the current configuration
func getClient() (*sdk.Client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	if !cfg.IsAuthenticated() {
		return nil, fmt.Errorf("not logged in. Run 'nexusctl login' first")
	}

	sdkConfig := sdk.NewConfig(cfg.Server).WithToken(cfg.Token)
	return sdk.NewClient(sdkConfig), nil
}

// printSuccess prints a success message
func printSuccess(format string, args ...interface{}) {
	successColor.Printf("✓ "+format+"\n", args...)
}

// printWarning prints a warning message
func printWarning(format string, args ...interface{}) {
	warningColor.Printf("⚠ "+format+"\n", args...)
}

// printError prints an error message
func printError(format string, args ...interface{}) {
	errorColor.Printf("✗ "+format+"\n", args...)
}

// printInfo prints an info message
func printInfo(format string, args ...interface{}) {
	infoColor.Printf(format+"\n", args...)
}

// outputData outputs data in the specified format
func outputData(data interface{}) error {
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	case "yaml":
		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close()
		return enc.Encode(data)
	default:
		return nil
	}
}

// newTable creates a new table writer with standard formatting
func newTable(headers []string) *tablewriter.Table {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	return table
}

// isTableFormat returns true if the output format is table
func isTableFormat() bool {
	return outputFormat == "table" || outputFormat == ""
}
