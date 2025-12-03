package sdk

// Config holds SDK configuration
type Config struct {
	ServerURL string
	Token     string
	APIKey    string
}

// NewConfig creates a new SDK configuration
func NewConfig(serverURL string) *Config {
	return &Config{
		ServerURL: serverURL,
	}
}

// WithToken sets the authentication token
func (c *Config) WithToken(token string) *Config {
	c.Token = token
	return c
}

// WithAPIKey sets the API key
func (c *Config) WithAPIKey(apiKey string) *Config {
	c.APIKey = apiKey
	return c
}
