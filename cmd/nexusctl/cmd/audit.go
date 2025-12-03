package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ConstantineCTF/nexus/pkg/sdk"
)

var (
	auditLimit int
)

// auditCmd represents the audit command
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit logs",
	Long:  `View and filter audit logs.`,
}

// auditListCmd represents the audit list command
var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit logs",
	Long: `List audit log entries.

Example:
  nexusctl audit list
  nexusctl audit list --limit 50`,
	RunE: runAuditList,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditListCmd)

	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum number of entries to return")
}

func runAuditList(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		printError("%v", err)
		return nil
	}

	logs, err := client.ListAuditLogs(sdk.AuditListOptions{
		Limit: auditLimit,
	})
	if err != nil {
		printError("Failed to list audit logs: %v", err)
		return nil
	}

	if isTableFormat() {
		if len(logs.Logs) == 0 {
			printInfo("No audit logs found")
			return nil
		}

		table := newTable([]string{"TIMESTAMP", "ACTION", "USER", "RESOURCE"})
		for _, log := range logs.Logs {
			resource := log.SecretPath
			if resource == "" {
				resource = log.SecretID
			}
			if resource == "" {
				resource = "-"
			}
			table.Append([]string{
				log.Timestamp.Format("2006-01-02 15:04:05"),
				log.Action,
				log.User,
				resource,
			})
		}
		table.Render()
	} else {
		outputData(logs)
	}

	return nil
}
