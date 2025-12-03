package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ConstantineCTF/nexus/cmd/nexusctl/config"
	"github.com/ConstantineCTF/nexus/pkg/sdk"
)

var (
	serverURL string
	username  string
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to a NEXUS server",
	Long: `Authenticate with a NEXUS server and store credentials locally.

The credentials are stored in ~/.nexus/config.yaml and used for
subsequent commands.

Example:
  nexusctl login --server http://localhost:9000

You will be prompted for username and password interactively.`,
	RunE: runLogin,
}

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from the current NEXUS server",
	Long: `Clear stored credentials and logout from the NEXUS server.

This removes the authentication token from ~/.nexus/config.yaml.`,
	RunE: runLogout,
}

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display current user information",
	Long:  `Show information about the currently authenticated user.`,
	RunE:  runWhoami,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)

	loginCmd.Flags().StringVarP(&serverURL, "server", "s", "", "NEXUS server URL (required)")
	loginCmd.Flags().StringVarP(&username, "username", "u", "", "Username (will prompt if not provided)")
	loginCmd.MarkFlagRequired("server")
}

func runLogin(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	// Get username if not provided via flag
	if username == "" {
		fmt.Print("Username: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
		username = strings.TrimSpace(input)
	}

	// Get password - try TTY first, fall back to stdin
	var password string
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // Print newline after hidden input
		password = string(passwordBytes)
	} else {
		// Non-interactive mode: read from stdin
		fmt.Print("Password: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = strings.TrimSpace(input)
	}

	// Create client and login
	sdkConfig := sdk.NewConfig(serverURL)
	client := sdk.NewClient(sdkConfig)

	loginResp, err := client.Login(username, password)
	if err != nil {
		printError("Login failed: %v", err)
		return nil
	}

	// Save configuration
	cfg := &config.Config{
		Server: serverURL,
		Token:  loginResp.Token,
		User: config.UserInfo{
			ID:   loginResp.User.ID,
			Name: loginResp.User.Name,
			Role: loginResp.User.Role,
		},
	}

	if cfgFile != "" {
		if err := cfg.SaveTo(cfgFile); err != nil {
			printWarning("Login successful but failed to save config: %v", err)
			return nil
		}
	} else {
		if err := cfg.Save(); err != nil {
			printWarning("Login successful but failed to save config: %v", err)
			return nil
		}
	}

	printSuccess("Logged in successfully as %s (%s)", loginResp.User.Name, loginResp.User.ID)
	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if !cfg.IsAuthenticated() {
		printInfo("Not currently logged in")
		return nil
	}

	cfg.Clear()
	if cfgFile != "" {
		if err := cfg.SaveTo(cfgFile); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	} else {
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	printSuccess("Logged out successfully")
	return nil
}

func runWhoami(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if !cfg.IsAuthenticated() {
		printError("Not logged in. Run 'nexusctl login' first")
		return nil
	}

	if isTableFormat() {
		fmt.Printf("User:   %s\n", cfg.User.Name)
		fmt.Printf("ID:     %s\n", cfg.User.ID)
		fmt.Printf("Role:   %s\n", cfg.User.Role)
		fmt.Printf("Server: %s\n", cfg.Server)
	} else {
		data := map[string]interface{}{
			"user":   cfg.User.Name,
			"id":     cfg.User.ID,
			"role":   cfg.User.Role,
			"server": cfg.Server,
		}
		outputData(data)
	}

	return nil
}
