package server

import (
"time"
)

// CreateSecretRequest is the request body for creating a secret
type CreateSecretRequest struct {
Path     string            `json:"path"`
Value    string            `json:"value"`
Metadata map[string]string `json:"metadata,omitempty"`
}

// UpdateSecretRequest is the request body for updating a secret
type UpdateSecretRequest struct {
Value    string            `json:"value,omitempty"`
Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretResponse is the response for a secret
type SecretResponse struct {
ID        string            `json:"id"`
Path      string            `json:"path"`
Value     string            `json:"value,omitempty"` // Only included when getting a single secret
Metadata  map[string]string `json:"metadata,omitempty"`
Version   int               `json:"version"`
CreatedAt time.Time         `json:"created_at"`
CreatedBy string            `json:"created_by"`
UpdatedAt time.Time         `json:"updated_at"`
UpdatedBy string            `json:"updated_by"`
}

// SecretListResponse is the response for listing secrets
type SecretListResponse struct {
Secrets []SecretResponse `json:"secrets"`
Total   int              `json:"total"`
}

// VersionResponse is the response for a secret version
type VersionResponse struct {
ID        string    `json:"id"`
SecretID  string    `json:"secret_id"`
Version   int       `json:"version"`
CreatedAt time.Time `json:"created_at"`
CreatedBy string    `json:"created_by"`
}

// VersionListResponse is the response for listing secret versions
type VersionListResponse struct {
Versions []VersionResponse `json:"versions"`
Total    int               `json:"total"`
}

// LoginRequest is the request body for user login
type LoginRequest struct {
Username string `json:"username"`
Password string `json:"password"`
}

// LoginResponse is the response for successful login
type LoginResponse struct {
Token     string       `json:"token"`
ExpiresAt time.Time    `json:"expires_at"`
User      UserResponse `json:"user,omitempty"`
}

// UserResponse is the user information in responses
type UserResponse struct {
ID   string `json:"id"`
Name string `json:"name"`
Role string `json:"role"`
}

// HealthResponse is the response for health check
type HealthResponse struct {
Status    string    `json:"status"`
Timestamp time.Time `json:"timestamp"`
Error     string    `json:"error,omitempty"`
}

// ErrorResponse is the standard error response
type ErrorResponse struct {
Error   string `json:"error"`
Message string `json:"message"`
}

// AuditLogResponse is the response for an audit log entry
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

// AuditLogListResponse is the response for listing audit logs
type AuditLogListResponse struct {
Logs  []AuditLogResponse `json:"logs"`
Total int                `json:"total"`
}

// APIKeyResponse is the response for an API key (without the key itself)
type APIKeyResponse struct {
ID        string     `json:"id"`
Name      string     `json:"name"`
Prefix    string     `json:"prefix"` // First 8 chars for identification
CreatedAt time.Time  `json:"created_at"`
ExpiresAt *time.Time `json:"expires_at,omitempty"`
LastUsed  *time.Time `json:"last_used,omitempty"`
}

// CreateAPIKeyRequest is the request body for creating an API key
type CreateAPIKeyRequest struct {
Name      string        `json:"name"`
ExpiresIn time.Duration `json:"expires_in,omitempty"` // e.g., "720h" for 30 days
}

// CreateAPIKeyResponse is the response for creating an API key (includes the key once)
type CreateAPIKeyResponse struct {
ID        string     `json:"id"`
Name      string     `json:"name"`
Key       string     `json:"key"` // Only returned once at creation
Prefix    string     `json:"prefix"`
CreatedAt time.Time  `json:"created_at"`
ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// APIKeyListResponse is the response for listing API keys
type APIKeyListResponse struct {
Keys  []APIKeyResponse `json:"keys"`
Total int              `json:"total"`
}
