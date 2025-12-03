package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var (
	apiKeyExpires string
)

// apikeyCmd represents the apikey command
var apikeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "Manage API keys",
	Long:  `Create, list, and revoke API keys.`,
}

// apikeyCreateCmd represents the apikey create command
var apikeyCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new API key",
	Long: `Create a new API key with the specified name.

The full API key is only shown once at creation time.
Make sure to store it securely.

Example:
  nexusctl apikey create "CI/CD Pipeline"
  nexusctl apikey create "Service Account" --expires 720h`,
	Args: cobra.ExactArgs(1),
	RunE: runAPIKeyCreate,
}

// apikeyListCmd represents the apikey list command
var apikeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List API keys",
	Long: `List all API keys for the current user.

Example:
  nexusctl apikey list`,
	RunE: runAPIKeyList,
}

// apikeyRevokeCmd represents the apikey revoke command
var apikeyRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an API key",
	Long: `Revoke an API key by its ID.

Example:
  nexusctl apikey revoke abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runAPIKeyRevoke,
}

func init() {
	rootCmd.AddCommand(apikeyCmd)
	apikeyCmd.AddCommand(apikeyCreateCmd)
	apikeyCmd.AddCommand(apikeyListCmd)
	apikeyCmd.AddCommand(apikeyRevokeCmd)

	apikeyCreateCmd.Flags().StringVar(&apiKeyExpires, "expires", "", "Expiration duration (e.g., 720h for 30 days)")
}

func runAPIKeyCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	var expiresIn time.Duration
	if apiKeyExpires != "" {
		var parseErr error
		expiresIn, parseErr = time.ParseDuration(apiKeyExpires)
		if parseErr != nil {
			printError("Invalid expiration duration: %v", parseErr)
			return nil
		}
	}

	key, err := client.CreateAPIKey(name, expiresIn)
	if err != nil {
		printError("Failed to create API key: %v", err)
		return nil
	}

	if isTableFormat() {
		printSuccess("API Key created: %s", name)
		fmt.Printf("Key: %s\n", key.Key)
		printWarning("Store this key securely - it won't be shown again!")
	} else {
		outputData(key)
	}

	return nil
}

func runAPIKeyList(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	keys, err := client.ListAPIKeys()
	if err != nil {
		printError("Failed to list API keys: %v", err)
		return nil
	}

	if isTableFormat() {
		if len(keys.Keys) == 0 {
			printInfo("No API keys found")
			return nil
		}

		table := newTable([]string{"ID", "NAME", "PREFIX", "CREATED", "EXPIRES", "LAST USED"})
		for _, k := range keys.Keys {
			expires := "-"
			if k.ExpiresAt != nil {
				expires = k.ExpiresAt.Format("2006-01-02 15:04:05")
			}
			lastUsed := "-"
			if k.LastUsed != nil {
				lastUsed = k.LastUsed.Format("2006-01-02 15:04:05")
			}
			table.Append([]string{
				k.ID,
				k.Name,
				k.Prefix + "...",
				k.CreatedAt.Format("2006-01-02 15:04:05"),
				expires,
				lastUsed,
			})
		}
		table.Render()
	} else {
		outputData(keys)
	}

	return nil
}

func runAPIKeyRevoke(cmd *cobra.Command, args []string) error {
	keyID := args[0]

	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	if err := client.RevokeAPIKey(keyID); err != nil {
		printError("Failed to revoke API key: %v", err)
		return nil
	}

	if isTableFormat() {
		printSuccess("API key revoked: %s", keyID)
	} else {
		outputData(map[string]string{"status": "revoked", "id": keyID})
	}

	return nil
}
