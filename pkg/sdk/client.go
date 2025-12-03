package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the main NEXUS SDK client
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewClient creates a new SDK client
func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// doRequest performs an HTTP request with automatic token injection
func (c *Client) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	// Parse the server URL and construct the full URL properly
	baseURL, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %w", err)
	}

	// Parse the path (which may contain query parameters)
	pathURL, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path: %w", err)
	}

	// Resolve the path against the base URL
	reqURL := baseURL.ResolveReference(pathURL).String()

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}
	if c.config.APIKey != "" {
		req.Header.Set("X-Nexus-API-Key", c.config.APIKey)
	}

	return c.httpClient.Do(req)
}

// escapePathSegments escapes each segment of a path while preserving slashes
// This prevents injection attacks while maintaining path structure
func escapePathSegments(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// parseResponse parses the JSON response into the provided struct
func parseResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
	}

	if v != nil && len(body) > 0 {
		if err := json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

// UserInfo represents user information
type UserInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// Login authenticates with the server
func (c *Client) Login(username, password string) (*LoginResponse, error) {
	req := LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := c.doRequest(http.MethodPost, "/api/v1/auth/login", req)
	if err != nil {
		return nil, err
	}

	var loginResp LoginResponse
	if err := parseResponse(resp, &loginResp); err != nil {
		return nil, err
	}

	// Store the token in config
	c.config.Token = loginResp.Token

	return &loginResp, nil
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

// Health checks the server health
func (c *Client) Health() (*HealthResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	var healthResp HealthResponse
	if err := parseResponse(resp, &healthResp); err != nil {
		return nil, err
	}

	return &healthResp, nil
}

// CreateSecretRequest represents a request to create a secret
type CreateSecretRequest struct {
	Path     string            `json:"path"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// UpdateSecretRequest represents a request to update a secret
type UpdateSecretRequest struct {
	Value    string            `json:"value,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretResponse represents a secret in responses
type SecretResponse struct {
	ID        string            `json:"id"`
	Path      string            `json:"path"`
	Value     string            `json:"value,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by"`
	UpdatedAt time.Time         `json:"updated_at"`
	UpdatedBy string            `json:"updated_by"`
}

// SecretListResponse represents a list of secrets
type SecretListResponse struct {
	Secrets []SecretResponse `json:"secrets"`
	Total   int              `json:"total"`
}

// CreateSecret creates a new secret
func (c *Client) CreateSecret(path, value string, metadata map[string]string) (*SecretResponse, error) {
	req := CreateSecretRequest{
		Path:     path,
		Value:    value,
		Metadata: metadata,
	}

	resp, err := c.doRequest(http.MethodPost, "/api/v1/secrets", req)
	if err != nil {
		return nil, err
	}

	var secretResp SecretResponse
	if err := parseResponse(resp, &secretResp); err != nil {
		return nil, err
	}

	return &secretResp, nil
}

// GetSecret retrieves a secret by path
func (c *Client) GetSecret(path string) (*SecretResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/api/v1/secrets/"+escapePathSegments(path), nil)
	if err != nil {
		return nil, err
	}

	var secretResp SecretResponse
	if err := parseResponse(resp, &secretResp); err != nil {
		return nil, err
	}

	return &secretResp, nil
}

// ListSecrets lists secrets with optional prefix filter
func (c *Client) ListSecrets(prefix string) (*SecretListResponse, error) {
	path := "/api/v1/secrets"
	if prefix != "" {
		path += "?prefix=" + url.QueryEscape(prefix)
	}

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var listResp SecretListResponse
	if err := parseResponse(resp, &listResp); err != nil {
		return nil, err
	}

	return &listResp, nil
}

// UpdateSecret updates an existing secret
func (c *Client) UpdateSecret(path, value string, metadata map[string]string) (*SecretResponse, error) {
	req := UpdateSecretRequest{
		Value:    value,
		Metadata: metadata,
	}

	resp, err := c.doRequest(http.MethodPut, "/api/v1/secrets/"+escapePathSegments(path), req)
	if err != nil {
		return nil, err
	}

	var secretResp SecretResponse
	if err := parseResponse(resp, &secretResp); err != nil {
		return nil, err
	}

	return &secretResp, nil
}

// DeleteSecret deletes a secret
func (c *Client) DeleteSecret(path string) error {
	resp, err := c.doRequest(http.MethodDelete, "/api/v1/secrets/"+escapePathSegments(path), nil)
	if err != nil {
		return err
	}

	return parseResponse(resp, nil)
}

// VersionResponse represents a secret version
type VersionResponse struct {
	ID        string    `json:"id"`
	SecretID  string    `json:"secret_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// VersionListResponse represents a list of versions
type VersionListResponse struct {
	Versions []VersionResponse `json:"versions"`
	Total    int               `json:"total"`
}

// GetSecretVersions retrieves version history for a secret
func (c *Client) GetSecretVersions(path string) (*VersionListResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/api/v1/secrets/"+escapePathSegments(path)+"/versions", nil)
	if err != nil {
		return nil, err
	}

	var versionsResp VersionListResponse
	if err := parseResponse(resp, &versionsResp); err != nil {
		return nil, err
	}

	return &versionsResp, nil
}

// CreateAPIKeyRequest represents a request to create an API key
type CreateAPIKeyRequest struct {
	Name      string        `json:"name"`
	ExpiresIn time.Duration `json:"expires_in,omitempty"`
}

// APIKeyResponse represents an API key in responses
type APIKeyResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// CreateAPIKeyResponse represents the response when creating an API key
type CreateAPIKeyResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Key       string     `json:"key"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// APIKeyListResponse represents a list of API keys
type APIKeyListResponse struct {
	Keys  []APIKeyResponse `json:"keys"`
	Total int              `json:"total"`
}

// CreateAPIKey creates a new API key
func (c *Client) CreateAPIKey(name string, expiresIn time.Duration) (*CreateAPIKeyResponse, error) {
	req := CreateAPIKeyRequest{
		Name:      name,
		ExpiresIn: expiresIn,
	}

	resp, err := c.doRequest(http.MethodPost, "/api/v1/apikeys", req)
	if err != nil {
		return nil, err
	}

	var keyResp CreateAPIKeyResponse
	if err := parseResponse(resp, &keyResp); err != nil {
		return nil, err
	}

	return &keyResp, nil
}

// ListAPIKeys lists all API keys for the current user
func (c *Client) ListAPIKeys() (*APIKeyListResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/api/v1/apikeys", nil)
	if err != nil {
		return nil, err
	}

	var listResp APIKeyListResponse
	if err := parseResponse(resp, &listResp); err != nil {
		return nil, err
	}

	return &listResp, nil
}

// RevokeAPIKey revokes an API key
func (c *Client) RevokeAPIKey(keyID string) error {
	resp, err := c.doRequest(http.MethodDelete, "/api/v1/apikeys?id="+url.QueryEscape(keyID), nil)
	if err != nil {
		return err
	}

	return parseResponse(resp, nil)
}

// AuditLogResponse represents an audit log entry
type AuditLogResponse struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Action     string            `json:"action"`
	User       string            `json:"user"`
	SecretID   string            `json:"secret_id,omitempty"`
	SecretPath string            `json:"secret_path,omitempty"`
	IPAddress  string            `json:"ip_address"`
	UserAgent  string            `json:"user_agent"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// AuditLogListResponse represents a list of audit logs
type AuditLogListResponse struct {
	Logs  []AuditLogResponse `json:"logs"`
	Total int                `json:"total"`
}

// AuditListOptions represents options for listing audit logs
type AuditListOptions struct {
	Limit      int
	Offset     int
	User       string
	Action     string
	SecretPath string
}

// ListAuditLogs retrieves audit logs
func (c *Client) ListAuditLogs(opts AuditListOptions) (*AuditLogListResponse, error) {
	path := "/api/v1/audit"

	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", opts.Offset))
	}
	if opts.User != "" {
		params.Set("user", opts.User)
	}
	if opts.Action != "" {
		params.Set("action", opts.Action)
	}
	if opts.SecretPath != "" {
		params.Set("secret_path", opts.SecretPath)
	}

	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var logsResp AuditLogListResponse
	if err := parseResponse(resp, &logsResp); err != nil {
		return nil, err
	}

	return &logsResp, nil
}
