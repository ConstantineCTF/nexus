//go:build cgo

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStorage implements Storage interface using SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage backend
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	storage := &SQLiteStorage{db: db}

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the database tables
func (s *SQLiteStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		path TEXT UNIQUE NOT NULL,
		value BLOB NOT NULL,
		metadata TEXT,
		version INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		created_by TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		updated_by TEXT NOT NULL,
		deleted_at DATETIME,
		rotation_enabled BOOLEAN DEFAULT 0,
		rotation_interval INTEGER,
		rotation_provider TEXT,
		next_rotation DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);
	CREATE INDEX IF NOT EXISTS idx_secrets_deleted_at ON secrets(deleted_at);

	CREATE TABLE IF NOT EXISTS secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		value BLOB NOT NULL,
		created_at DATETIME NOT NULL,
		created_by TEXT NOT NULL,
		FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
		UNIQUE(secret_id, version)
	);

	CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		action TEXT NOT NULL,
		user TEXT NOT NULL,
		secret_id TEXT,
		secret_path TEXT,
		ip_address TEXT,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		error TEXT,
		metadata TEXT,
		signature TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_secret_path ON audit_logs(secret_path);
	`

	_, err := s.db.Exec(schema)
	return err
}

// CreateSecret stores a new secret
func (s *SQLiteStorage) CreateSecret(ctx context.Context, secret *Secret) error {
	if secret.ID == "" {
		secret.ID = uuid.New().String()
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var rotationInterval *int64
	var nextRotation *time.Time
	if secret.RotationPolicy != nil && secret.RotationPolicy.Enabled {
		interval := int64(secret.RotationPolicy.Interval.Seconds())
		rotationInterval = &interval
		nextRotation = &secret.RotationPolicy.NextRotation
	}

	query := `
		INSERT INTO secrets (
			id, path, value, metadata, version, 
			created_at, created_by, updated_at, updated_by,
			rotation_enabled, rotation_interval, rotation_provider, next_rotation
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		secret.ID,
		secret.Path,
		secret.Value,
		string(metadataJSON),
		secret.Version,
		secret.CreatedAt,
		secret.CreatedBy,
		secret.UpdatedAt,
		secret.UpdatedBy,
		secret.RotationPolicy != nil && secret.RotationPolicy.Enabled,
		rotationInterval,
		func() *string {
			if secret.RotationPolicy != nil {
				return &secret.RotationPolicy.Provider
			}
			return nil
		}(),
		nextRotation,
	)

	if err != nil {
		return fmt.Errorf("failed to insert secret: %w", err)
	}

	return nil
}

// GetSecret retrieves a secret by path
func (s *SQLiteStorage) GetSecret(ctx context.Context, path string) (*Secret, error) {
	query := `
		SELECT 
			id, path, value, metadata, version,
			created_at, created_by, updated_at, updated_by, deleted_at,
			rotation_enabled, rotation_interval, rotation_provider, next_rotation
		FROM secrets
		WHERE path = ?  AND deleted_at IS NULL
	`

	var secret Secret
	var metadataJSON string
	var deletedAt sql.NullTime
	var rotationEnabled bool
	var rotationInterval sql.NullInt64
	var rotationProvider sql.NullString
	var nextRotation sql.NullTime

	err := s.db.QueryRowContext(ctx, query, path).Scan(
		&secret.ID,
		&secret.Path,
		&secret.Value,
		&metadataJSON,
		&secret.Version,
		&secret.CreatedAt,
		&secret.CreatedBy,
		&secret.UpdatedAt,
		&secret.UpdatedBy,
		&deletedAt,
		&rotationEnabled,
		&rotationInterval,
		&rotationProvider,
		&nextRotation,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found: %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if deletedAt.Valid {
		secret.DeletedAt = &deletedAt.Time
	}

	if rotationEnabled {
		secret.RotationPolicy = &RotationPolicy{
			Enabled:  true,
			Interval: time.Duration(rotationInterval.Int64) * time.Second,
			Provider: rotationProvider.String,
		}
		if nextRotation.Valid {
			secret.RotationPolicy.NextRotation = nextRotation.Time
		}
	}

	return &secret, nil
}

// GetSecretByID retrieves a secret by ID
func (s *SQLiteStorage) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	query := `
		SELECT 
			id, path, value, metadata, version,
			created_at, created_by, updated_at, updated_by, deleted_at,
			rotation_enabled, rotation_interval, rotation_provider, next_rotation
		FROM secrets
		WHERE id = ? AND deleted_at IS NULL
	`

	var secret Secret
	var metadataJSON string
	var deletedAt sql.NullTime
	var rotationEnabled bool
	var rotationInterval sql.NullInt64
	var rotationProvider sql.NullString
	var nextRotation sql.NullTime

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID,
		&secret.Path,
		&secret.Value,
		&metadataJSON,
		&secret.Version,
		&secret.CreatedAt,
		&secret.CreatedBy,
		&secret.UpdatedAt,
		&secret.UpdatedBy,
		&deletedAt,
		&rotationEnabled,
		&rotationInterval,
		&rotationProvider,
		&nextRotation,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if deletedAt.Valid {
		secret.DeletedAt = &deletedAt.Time
	}

	if rotationEnabled {
		secret.RotationPolicy = &RotationPolicy{
			Enabled:  true,
			Interval: time.Duration(rotationInterval.Int64) * time.Second,
			Provider: rotationProvider.String,
		}
		if nextRotation.Valid {
			secret.RotationPolicy.NextRotation = nextRotation.Time
		}
	}

	return &secret, nil
}

// UpdateSecret updates an existing secret
func (s *SQLiteStorage) UpdateSecret(ctx context.Context, secret *Secret) error {
	secret.Version++
	secret.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var rotationInterval *int64
	var nextRotation *time.Time
	if secret.RotationPolicy != nil && secret.RotationPolicy.Enabled {
		interval := int64(secret.RotationPolicy.Interval.Seconds())
		rotationInterval = &interval
		nextRotation = &secret.RotationPolicy.NextRotation
	}

	query := `
		UPDATE secrets
		SET value = ?, metadata = ?, version = ?, updated_at = ?, updated_by = ?,
		    rotation_enabled = ?, rotation_interval = ?, rotation_provider = ?, next_rotation = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := s.db.ExecContext(ctx, query,
		secret.Value,
		string(metadataJSON),
		secret.Version,
		secret.UpdatedAt,
		secret.UpdatedBy,
		secret.RotationPolicy != nil && secret.RotationPolicy.Enabled,
		rotationInterval,
		func() *string {
			if secret.RotationPolicy != nil {
				return &secret.RotationPolicy.Provider
			}
			return nil
		}(),
		nextRotation,
		secret.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found or already deleted")
	}

	return nil
}

// DeleteSecret soft-deletes a secret
func (s *SQLiteStorage) DeleteSecret(ctx context.Context, path string) error {
	query := `UPDATE secrets SET deleted_at = ? WHERE path = ? AND deleted_at IS NULL`

	result, err := s.db.ExecContext(ctx, query, time.Now(), path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found: %s", path)
	}

	return nil
}

// ListSecrets lists all secrets with optional prefix filter
func (s *SQLiteStorage) ListSecrets(ctx context.Context, prefix string) ([]*Secret, error) {
	query := `
		SELECT 
			id, path, value, metadata, version,
			created_at, created_by, updated_at, updated_by
		FROM secrets
		WHERE deleted_at IS NULL AND path LIKE ?
		ORDER BY path
	`

	rows, err := s.db.QueryContext(ctx, query, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*Secret
	for rows.Next() {
		var secret Secret
		var metadataJSON string

		if err := rows.Scan(
			&secret.ID,
			&secret.Path,
			&secret.Value,
			&metadataJSON,
			&secret.Version,
			&secret.CreatedAt,
			&secret.CreatedBy,
			&secret.UpdatedAt,
			&secret.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

// SearchSecrets searches secrets by query (simple path matching for now)
func (s *SQLiteStorage) SearchSecrets(ctx context.Context, query string) ([]*Secret, error) {
	return s.ListSecrets(ctx, query)
}

// CreateSecretVersion stores a secret version
func (s *SQLiteStorage) CreateSecretVersion(ctx context.Context, version *SecretVersion) error {
	if version.ID == "" {
		version.ID = uuid.New().String()
	}

	query := `
		INSERT INTO secret_versions (id, secret_id, version, value, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		version.ID,
		version.SecretID,
		version.Version,
		version.Value,
		version.CreatedAt,
		version.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to insert secret version: %w", err)
	}

	return nil
}

// GetSecretVersions retrieves all versions of a secret
func (s *SQLiteStorage) GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error) {
	query := `
		SELECT id, secret_id, version, value, created_at, created_by
		FROM secret_versions
		WHERE secret_id = ? 
		ORDER BY version DESC
	`

	rows, err := s.db.QueryContext(ctx, query, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to query versions: %w", err)
	}
	defer rows.Close()

	var versions []*SecretVersion
	for rows.Next() {
		var v SecretVersion
		if err := rows.Scan(&v.ID, &v.SecretID, &v.Version, &v.Value, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}
		versions = append(versions, &v)
	}

	return versions, nil
}

// GetSecretVersion retrieves a specific version
func (s *SQLiteStorage) GetSecretVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error) {
	query := `
		SELECT id, secret_id, version, value, created_at, created_by
		FROM secret_versions
		WHERE secret_id = ? AND version = ?
	`

	var v SecretVersion
	err := s.db.QueryRowContext(ctx, query, secretID, version).Scan(
		&v.ID, &v.SecretID, &v.Version, &v.Value, &v.CreatedAt, &v.CreatedBy,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("version not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query version: %w", err)
	}

	return &v, nil
}

// CreateAuditLog stores an audit log entry
func (s *SQLiteStorage) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.New().String()
	}

	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO audit_logs (
			id, timestamp, action, user, secret_id, secret_path,
			ip_address, user_agent, success, error, metadata, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		log.ID,
		log.Timestamp,
		log.Action,
		log.User,
		log.SecretID,
		log.SecretPath,
		log.IPAddress,
		log.UserAgent,
		log.Success,
		log.Error,
		string(metadataJSON),
		log.Signature,
	)

	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs with filters
func (s *SQLiteStorage) GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, error) {
	query := "SELECT id, timestamp, action, user, secret_id, secret_path, ip_address, user_agent, success, error, metadata, signature FROM audit_logs WHERE 1=1"
	args := []interface{}{}

	if filter.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, *filter.EndTime)
	}

	if filter.User != "" {
		query += " AND user = ?"
		args = append(args, filter.User)
	}

	if filter.Action != "" {
		query += " AND action = ?"
		args = append(args, filter.Action)
	}

	if filter.SecretPath != "" {
		query += " AND secret_path LIKE ?"
		args = append(args, filter.SecretPath+"%")
	}

	if filter.Success != nil {
		query += " AND success = ?"
		args = append(args, *filter.Success)
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var secretID, secretPath, errorMsg sql.NullString
		var metadataJSON string

		if err := rows.Scan(
			&log.ID,
			&log.Timestamp,
			&log.Action,
			&log.User,
			&secretID,
			&secretPath,
			&log.IPAddress,
			&log.UserAgent,
			&log.Success,
			&errorMsg,
			&metadataJSON,
			&log.Signature,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if secretID.Valid {
			log.SecretID = secretID.String
		}
		if secretPath.Valid {
			log.SecretPath = secretPath.String
		}
		if errorMsg.Valid {
			log.Error = errorMsg.String
		}

		if err := json.Unmarshal([]byte(metadataJSON), &log.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		logs = append(logs, &log)
	}

	return logs, nil
}

// Ping checks database connectivity
func (s *SQLiteStorage) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Backup creates a backup of the database
func (s *SQLiteStorage) Backup(ctx context.Context, destination string) error {
	query := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(destination, "'", "''"))
	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to backup database: %w", err)
	}
	return nil
}
