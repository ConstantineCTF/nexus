package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration stored in ~/.nexus/config.yaml
type Config struct {
	Server string   `yaml:"server"`
	Token  string   `yaml:"token"`
	User   UserInfo `yaml:"user"`
}

// UserInfo stores authenticated user information
type UserInfo struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	Role string `yaml:"role"`
}

// DefaultConfigPath returns the default config file path
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".nexus", "config.yaml"), nil
}

// Load loads the configuration from the default path
func Load() (*Config, error) {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return nil, err
	}
	return LoadFrom(configPath)
}

// LoadFrom loads the configuration from a specific path
func LoadFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Save saves the configuration to the default path
func (c *Config) Save() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return err
	}
	return c.SaveTo(configPath)
}

// SaveTo saves the configuration to a specific path
func (c *Config) SaveTo(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Clear clears the authentication data (for logout)
func (c *Config) Clear() {
	c.Token = ""
	c.User = UserInfo{}
}

// IsAuthenticated returns true if a valid token is stored
func (c *Config) IsAuthenticated() bool {
	return c.Token != "" && c.Server != ""
}
