package storage

import (
	"context"
	"fmt"
)

// PostgreSQLStorage implements Storage interface using PostgreSQL
// TODO: Implement PostgreSQL backend for production use
type PostgreSQLStorage struct {
	// Will be implemented in Phase 2
}

// NewPostgreSQLStorage creates a new PostgreSQL storage backend
func NewPostgreSQLStorage(connectionString string) (*PostgreSQLStorage, error) {
	return nil, fmt.Errorf("PostgreSQL storage not yet implemented - use SQLite for now")
}

// Placeholder methods to satisfy the interface
func (p *PostgreSQLStorage) CreateSecret(ctx context.Context, secret *Secret) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) GetSecret(ctx context.Context, path string) (*Secret, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) UpdateSecret(ctx context.Context, secret *Secret) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) DeleteSecret(ctx context.Context, path string) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) ListSecrets(ctx context.Context, prefix string) ([]*Secret, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) SearchSecrets(ctx context.Context, query string) ([]*Secret, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) CreateSecretVersion(ctx context.Context, version *SecretVersion) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) GetSecretVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) Ping(ctx context.Context) error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) Close() error {
	return fmt.Errorf("not implemented")
}

func (p *PostgreSQLStorage) Backup(ctx context.Context, destination string) error {
	return fmt.Errorf("not implemented")
}
