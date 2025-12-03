package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	exportOutputFile string
	importFile       string
	importOverwrite  bool
)

// ExportedSecret represents a secret in the export format
type ExportedSecret struct {
	Path      string            `json:"path"`
	Value     string            `json:"value"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ExportData represents the full export file format
type ExportData struct {
	ExportedAt time.Time        `json:"exported_at"`
	Secrets    []ExportedSecret `json:"secrets"`
}

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all secrets to JSON file",
	Long: `Export all secrets to a JSON file with their values and metadata.

The server must be running for this command to work.

Example:
  nexusctl export --output secrets.json`,
	RunE: runExport,
}

// importCmd represents the import command
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from JSON file",
	Long: `Import secrets from a JSON file exported by 'nexusctl export'.

By default, existing secrets are skipped. Use --overwrite to update them.

The server must be running for this command to work.

Example:
  nexusctl import --file secrets.json
  nexusctl import --file secrets.json --overwrite`,
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)

	exportCmd.Flags().StringVarP(&exportOutputFile, "output", "o", "", "Output JSON file (required)")
	exportCmd.MarkFlagRequired("output")

	importCmd.Flags().StringVarP(&importFile, "file", "f", "", "JSON file to import from (required)")
	importCmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Overwrite existing secrets")
	importCmd.MarkFlagRequired("file")
}

func runExport(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	// List all secrets
	printInfo("Fetching secrets...")
	secretsList, err := client.ListSecrets("")
	if err != nil {
		printError("Failed to list secrets: %v", err)
		return nil
	}

	if len(secretsList.Secrets) == 0 {
		printInfo("No secrets found to export")
		return nil
	}

	// Fetch each secret with its value
	exportData := ExportData{
		ExportedAt: time.Now(),
		Secrets:    make([]ExportedSecret, 0, len(secretsList.Secrets)),
	}

	for i, s := range secretsList.Secrets {
		fmt.Printf("\rExporting secret %d/%d...", i+1, len(secretsList.Secrets))

		// Get full secret with value
		secret, err := client.GetSecret(s.Path)
		if err != nil {
			printWarning("Failed to get secret %s: %v", s.Path, err)
			continue
		}

		exportData.Secrets = append(exportData.Secrets, ExportedSecret{
			Path:      secret.Path,
			Value:     secret.Value,
			Version:   secret.Version,
			CreatedAt: secret.CreatedAt,
			CreatedBy: secret.CreatedBy,
			Metadata:  secret.Metadata,
		})
	}
	fmt.Println() // Clear the progress line

	// Write to file
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		printError("Failed to marshal export data: %v", err)
		return nil
	}

	if err := os.WriteFile(exportOutputFile, jsonData, 0600); err != nil {
		printError("Failed to write export file: %v", err)
		return nil
	}

	printSuccess("Exported %d secrets to %s", len(exportData.Secrets), exportOutputFile)
	return nil
}

func runImport(cmd *cobra.Command, args []string) error {
	// Check if import file exists
	if _, err := os.Stat(importFile); os.IsNotExist(err) {
		printError("Import file not found: %s", importFile)
		return nil
	}

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	// Read import file
	jsonData, err := os.ReadFile(importFile)
	if err != nil {
		printError("Failed to read import file: %v", err)
		return nil
	}

	var importData ExportData
	if err := json.Unmarshal(jsonData, &importData); err != nil {
		printError("Failed to parse import file: %v", err)
		return nil
	}

	if len(importData.Secrets) == 0 {
		printInfo("No secrets found in import file")
		return nil
	}

	printInfo("Importing %d secrets...", len(importData.Secrets))

	var created, updated, skipped, failed int

	for i, secret := range importData.Secrets {
		fmt.Printf("\rProcessing secret %d/%d...", i+1, len(importData.Secrets))

		// Try to create the secret first
		_, err := client.CreateSecret(secret.Path, secret.Value, secret.Metadata)
		if err != nil {
			// Check if it already exists
			if isConflictError(err) {
				if importOverwrite {
					// Update existing secret
					_, err := client.UpdateSecret(secret.Path, secret.Value, secret.Metadata)
					if err != nil {
						printWarning("Failed to update %s: %v", secret.Path, err)
						failed++
					} else {
						updated++
					}
				} else {
					skipped++
				}
			} else {
				printWarning("Failed to import %s: %v", secret.Path, err)
				failed++
			}
		} else {
			created++
		}
	}
	fmt.Println() // Clear the progress line

	// Print summary
	fmt.Println()
	printSuccess("Import complete:")
	fmt.Printf("  Created: %d\n", created)
	if importOverwrite {
		fmt.Printf("  Updated: %d\n", updated)
	}
	fmt.Printf("  Skipped: %d\n", skipped)
	if failed > 0 {
		fmt.Printf("  Failed:  %d\n", failed)
	}

	return nil
}

// isConflictError checks if the error is a conflict (secret already exists)
func isConflictError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "already exists") || strings.Contains(errStr, "Conflict") || strings.Contains(errStr, "conflict")
}
