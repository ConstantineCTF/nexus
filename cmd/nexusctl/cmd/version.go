package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information set at build time
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Long:  `Print the version, git commit, and build information of nexusctl.`,
	Run:   runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) {
	if isTableFormat() {
		fmt.Printf("nexusctl version %s\n", Version)
		fmt.Printf("  Git commit: %s\n", GitCommit)
		fmt.Printf("  Built:      %s\n", BuildTime)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	} else {
		data := map[string]string{
			"version":    Version,
			"git_commit": GitCommit,
			"build_time": BuildTime,
			"go_version": runtime.Version(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
		}
		outputData(data)
	}
}
