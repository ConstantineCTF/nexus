package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	secretDescription string
	secretVersion     int
	secretPrefix      string
	showSecretValue   bool
)

// secretCmd represents the secret command
var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  `Create, read, update, delete, and list secrets.`,
}

// secretCreateCmd represents the secret create command
var secretCreateCmd = &cobra.Command{
	Use:   "create <path> <value>",
	Short: "Create a new secret",
	Long: `Create a new secret at the specified path.

Example:
  nexusctl secret create prod/database/password "myS3cr3t!"
  nexusctl secret create prod/api/key "api-key-value" --description "Production API key"`,
	Args: cobra.ExactArgs(2),
	RunE: runSecretCreate,
}

// secretGetCmd represents the secret get command
var secretGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Get a secret value",
	Long: `Retrieve the value of a secret by its path.

Example:
  nexusctl secret get prod/database/password`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretGet,
}

// secretListCmd represents the secret list command
var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets",
	Long: `List all secrets, optionally filtered by prefix.

Example:
  nexusctl secret list
  nexusctl secret list --prefix prod/`,
	RunE: runSecretList,
}

// secretUpdateCmd represents the secret update command
var secretUpdateCmd = &cobra.Command{
	Use:   "update <path> <value>",
	Short: "Update an existing secret",
	Long: `Update the value of an existing secret.

Example:
  nexusctl secret update prod/database/password "newS3cr3t!"`,
	Args: cobra.ExactArgs(2),
	RunE: runSecretUpdate,
}

// secretDeleteCmd represents the secret delete command
var secretDeleteCmd = &cobra.Command{
	Use:   "delete <path>",
	Short: "Delete a secret",
	Long: `Delete a secret by its path.

Example:
  nexusctl secret delete prod/database/password`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretDelete,
}

// secretVersionsCmd represents the secret versions command
var secretVersionsCmd = &cobra.Command{
	Use:   "versions <path>",
	Short: "List secret versions",
	Long: `Show version history for a secret.

Example:
  nexusctl secret versions prod/database/password`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretVersions,
}

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.AddCommand(secretCreateCmd)
	secretCmd.AddCommand(secretGetCmd)
	secretCmd.AddCommand(secretListCmd)
	secretCmd.AddCommand(secretUpdateCmd)
	secretCmd.AddCommand(secretDeleteCmd)
	secretCmd.AddCommand(secretVersionsCmd)

	secretCreateCmd.Flags().StringVarP(&secretDescription, "description", "d", "", "Secret description")
	secretGetCmd.Flags().IntVarP(&secretVersion, "version", "v", 0, "Specific version to retrieve")
	secretListCmd.Flags().StringVarP(&secretPrefix, "prefix", "p", "", "Filter by path prefix")
	secretListCmd.Flags().BoolVar(&showSecretValue, "show-value", false, "Show secret values (masked by default)")
}

func runSecretCreate(cmd *cobra.Command, args []string) error {
	path := args[0]
	value := args[1]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	var metadata map[string]string
	if secretDescription != "" {
		metadata = map[string]string{"description": secretDescription}
	}

	secret, err := client.CreateSecret(path, value, metadata)
	if err != nil {
		printError("Failed to create secret: %v", err)
		return nil
	}

	if isTableFormat() {
		printSuccess("Secret created: %s (version %d)", secret.Path, secret.Version)
	} else {
		outputData(secret)
	}

	return nil
}

func runSecretGet(cmd *cobra.Command, args []string) error {
	path := args[0]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	secret, err := client.GetSecret(path)
	if err != nil {
		printError("Failed to get secret: %v", err)
		return nil
	}

	if isTableFormat() {
		// Print just the value for easy piping
		fmt.Println(secret.Value)
	} else {
		outputData(secret)
	}

	return nil
}

func runSecretList(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	secrets, err := client.ListSecrets(secretPrefix)
	if err != nil {
		printError("Failed to list secrets: %v", err)
		return nil
	}

	if isTableFormat() {
		if len(secrets.Secrets) == 0 {
			printInfo("No secrets found")
			return nil
		}

		table := newTable([]string{"PATH", "VERSION", "CREATED", "CREATED BY"})
		for _, s := range secrets.Secrets {
			table.Append([]string{
				s.Path,
				fmt.Sprintf("%d", s.Version),
				s.CreatedAt.Format("2006-01-02 15:04:05"),
				s.CreatedBy,
			})
		}
		table.Render()
	} else {
		outputData(secrets)
	}

	return nil
}

func runSecretUpdate(cmd *cobra.Command, args []string) error {
	path := args[0]
	value := args[1]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	secret, err := client.UpdateSecret(path, value, nil)
	if err != nil {
		printError("Failed to update secret: %v", err)
		return nil
	}

	if isTableFormat() {
		printSuccess("Secret updated: %s (version %d)", secret.Path, secret.Version)
	} else {
		outputData(secret)
	}

	return nil
}

func runSecretDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	if err := client.DeleteSecret(path); err != nil {
		printError("Failed to delete secret: %v", err)
		return nil
	}

	if isTableFormat() {
		printSuccess("Secret deleted: %s", path)
	} else {
		outputData(map[string]string{"status": "deleted", "path": path})
	}

	return nil
}

func runSecretVersions(cmd *cobra.Command, args []string) error {
	path := args[0]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	versions, err := client.GetSecretVersions(path)
	if err != nil {
		printError("Failed to get versions: %v", err)
		return nil
	}

	if isTableFormat() {
		if len(versions.Versions) == 0 {
			printInfo("No versions found")
			return nil
		}

		table := newTable([]string{"VERSION", "CREATED", "CREATED BY"})
		for _, v := range versions.Versions {
			table.Append([]string{
				fmt.Sprintf("%d", v.Version),
				v.CreatedAt.Format("2006-01-02 15:04:05"),
				v.CreatedBy,
			})
		}
		table.Render()
	} else {
		outputData(versions)
	}

	return nil
}

// maskValue masks a secret value, showing only first/last few characters
func maskValue(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}
