package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github. com/google/uuid"
)

// MemoryStorage implements Storage interface using in-memory maps (for testing)
type MemoryStorage struct {
	secrets   map[string]*Secret
	versions  map[string][]*SecretVersion
	auditLogs []*AuditLog
	mu        sync.RWMutex
	closed    bool
}

// NewMemoryStorage creates a new in-memory storage backend
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		secrets:   make(map[string]*Secret),
		versions:  make(map[string][]*SecretVersion),
		auditLogs: make([]*AuditLog, 0),
		closed:    false,
	}
}

// CreateSecret stores a new secret in memory
func (m *MemoryStorage) CreateSecret(ctx context.Context, secret *Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	if _, exists := m.secrets[secret.Path]; exists {
		return fmt.Errorf("secret already exists: %s", secret.Path)
	}

	// Generate ID if not provided
	if secret.ID == "" {
		secret.ID = uuid.New().String()
	}

	// Deep copy to avoid external modifications
	secretCopy := *secret
	if secretCopy.Metadata == nil {
		secretCopy.Metadata = make(map[string]string)
	}

	m.secrets[secret.Path] = &secretCopy
	return nil
}

// GetSecret retrieves a secret by path
func (m *MemoryStorage) GetSecret(ctx context.Context, path string) (*Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	secret, exists := m.secrets[path]
	if !exists || secret.DeletedAt != nil {
		return nil, fmt.Errorf("secret not found: %s", path)
	}

	// Deep copy
	secretCopy := *secret
	return &secretCopy, nil
}

// GetSecretByID retrieves a secret by ID
func (m *MemoryStorage) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	for _, secret := range m.secrets {
		if secret.ID == id && secret.DeletedAt == nil {
			secretCopy := *secret
			return &secretCopy, nil
		}
	}

	return nil, fmt.Errorf("secret not found: %s", id)
}

// UpdateSecret updates an existing secret
func (m *MemoryStorage) UpdateSecret(ctx context.Context, secret *Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	existing, exists := m.secrets[secret.Path]
	if !exists || existing.DeletedAt != nil {
		return fmt.Errorf("secret not found: %s", secret.Path)
	}

	secret.Version++
	secret.UpdatedAt = time.Now()

	secretCopy := *secret
	m.secrets[secret.Path] = &secretCopy
	return nil
}

// DeleteSecret soft-deletes a secret
func (m *MemoryStorage) DeleteSecret(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	secret, exists := m.secrets[path]
	if !exists || secret.DeletedAt != nil {
		return fmt.Errorf("secret not found: %s", path)
	}

	now := time.Now()
	secret.DeletedAt = &now
	return nil
}

// ListSecrets lists all secrets with optional prefix filter
func (m *MemoryStorage) ListSecrets(ctx context.Context, prefix string) ([]*Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	var secrets []*Secret
	for path, secret := range m.secrets {
		if secret.DeletedAt == nil && strings.HasPrefix(path, prefix) {
			secretCopy := *secret
			secrets = append(secrets, &secretCopy)
		}
	}

	return secrets, nil
}

// SearchSecrets searches secrets by query
func (m *MemoryStorage) SearchSecrets(ctx context.Context, query string) ([]*Secret, error) {
	return m.ListSecrets(ctx, query)
}

// CreateSecretVersion stores a secret version
func (m *MemoryStorage) CreateSecretVersion(ctx context.Context, version *SecretVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	// Generate ID if not provided
	if version.ID == "" {
		version.ID = uuid.New().String()
	}

	versionCopy := *version
	m.versions[version.SecretID] = append(m.versions[version.SecretID], &versionCopy)
	return nil
}

// GetSecretVersions retrieves all versions of a secret
func (m *MemoryStorage) GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	versions := m.versions[secretID]
	if versions == nil {
		return []*SecretVersion{}, nil
	}

	// Return copy in reverse order (newest first)
	result := make([]*SecretVersion, len(versions))
	for i := range versions {
		versionCopy := *versions[len(versions)-1-i]
		result[i] = &versionCopy
	}

	return result, nil
}

// GetSecretVersion retrieves a specific version
func (m *MemoryStorage) GetSecretVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	versions := m.versions[secretID]
	for _, v := range versions {
		if v.Version == version {
			versionCopy := *v
			return &versionCopy, nil
		}
	}

	return nil, fmt.Errorf("version not found")
}

// CreateAuditLog stores an audit log entry
func (m *MemoryStorage) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	// Generate ID if not provided
	if log.ID == "" {
		log.ID = uuid.New().String()
	}

	logCopy := *log
	if logCopy.Metadata == nil {
		logCopy.Metadata = make(map[string]string)
	}

	m.auditLogs = append(m.auditLogs, &logCopy)
	return nil
}

// GetAuditLogs retrieves audit logs with filters
func (m *MemoryStorage) GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	var filtered []*AuditLog

	for _, log := range m.auditLogs {
		// Apply filters
		if filter.StartTime != nil && log.Timestamp.Before(*filter.StartTime) {
			continue
		}

		if filter.EndTime != nil && log.Timestamp.After(*filter.EndTime) {
			continue
		}

		if filter.User != "" && log.User != filter.User {
			continue
		}

		if filter.Action != "" && log.Action != filter.Action {
			continue
		}

		if filter.SecretPath != "" && !strings.HasPrefix(log.SecretPath, filter.SecretPath) {
			continue
		}

		if filter.Success != nil && log.Success != *filter.Success {
			continue
		}

		logCopy := *log
		filtered = append(filtered, &logCopy)
	}

	// Apply limit and offset
	start := filter.Offset
	if start > len(filtered) {
		return []*AuditLog{}, nil
	}

	end := len(filtered)
	if filter.Limit > 0 && start+filter.Limit < end {
		end = start + filter.Limit
	}

	return filtered[start:end], nil
}

// Ping checks connectivity
func (m *MemoryStorage) Ping(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	return nil
}

// Close closes the storage
func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return nil
}

// Backup creates a backup (not supported for memory storage)
func (m *MemoryStorage) Backup(ctx context.Context, destination string) error {
	return fmt.Errorf("backup not supported for memory storage")
}
