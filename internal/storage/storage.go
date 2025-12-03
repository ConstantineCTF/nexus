package storage

import (
	"context"
	"time"
)

// Secret represents a stored secret
type Secret struct {
	ID             string            `json:"id"`
	Path           string            `json:"path"`     // e.g., "prod/database/password"
	Value          []byte            `json:"value"`    // Encrypted value
	Metadata       map[string]string `json:"metadata"` // User-defined metadata
	Version        int               `json:"version"`  // Version number
	CreatedAt      time.Time         `json:"created_at"`
	CreatedBy      string            `json:"created_by"`
	UpdatedAt      time.Time         `json:"updated_at"`
	UpdatedBy      string            `json:"updated_by"`
	DeletedAt      *time.Time        `json:"deleted_at,omitempty"` // Soft delete
	RotationPolicy *RotationPolicy   `json:"rotation_policy,omitempty"`
}

// RotationPolicy defines automatic rotation settings
type RotationPolicy struct {
	Enabled      bool          `json:"enabled"`
	Interval     time.Duration `json:"interval"` // e.g., 30 days
	Provider     string        `json:"provider"` // e.g., "postgresql", "aws-rds"
	NextRotation time.Time     `json:"next_rotation"`
}

// SecretVersion represents a historical version of a secret
type SecretVersion struct {
	ID        string    `json:"id"`
	SecretID  string    `json:"secret_id"`
	Version   int       `json:"version"`
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Action     string            `json:"action"` // e.g., "secret. read", "secret.create"
	User       string            `json:"user"`
	SecretID   string            `json:"secret_id,omitempty"`
	SecretPath string            `json:"secret_path,omitempty"`
	IPAddress  string            `json:"ip_address"`
	UserAgent  string            `json:"user_agent"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Signature  string            `json:"signature"` // Ed25519 signature for tamper detection
}

// Storage is the interface all storage backends must implement
type Storage interface {
	// Secrets
	CreateSecret(ctx context.Context, secret *Secret) error
	GetSecret(ctx context.Context, path string) (*Secret, error)
	GetSecretByID(ctx context.Context, id string) (*Secret, error)
	UpdateSecret(ctx context.Context, secret *Secret) error
	DeleteSecret(ctx context.Context, path string) error // Soft delete
	ListSecrets(ctx context.Context, prefix string) ([]*Secret, error)
	SearchSecrets(ctx context.Context, query string) ([]*Secret, error)

	// Secret Versions
	CreateSecretVersion(ctx context.Context, version *SecretVersion) error
	GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error)
	GetSecretVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error)

	// Audit Logs
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, error)

	// Health & Maintenance
	Ping(ctx context.Context) error
	Close() error
	Backup(ctx context.Context, destination string) error
}

// AuditFilter defines filters for querying audit logs
type AuditFilter struct {
	StartTime  *time.Time
	EndTime    *time.Time
	User       string
	Action     string
	SecretPath string
	Success    *bool
	Limit      int
	Offset     int
}
