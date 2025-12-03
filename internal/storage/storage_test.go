package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) (Storage, func()) {
	// Use in-memory storage (no CGO required, faster tests)
	storage := NewMemoryStorage()

	cleanup := func() {
		storage.Close()
	}

	return storage, cleanup
}

func TestCreateAndGetSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	secret := &Secret{
		Path:      "test/database/password",
		Value:     []byte("encrypted-value-here"),
		Metadata:  map[string]string{"env": "production", "owner": "devops"},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	// Create secret
	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Verify ID was generated
	if secret.ID == "" {
		t.Error("Secret ID was not generated")
	}

	// Get secret
	retrieved, err := storage.GetSecret(ctx, "test/database/password")
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	// Verify fields
	if retrieved.Path != secret.Path {
		t.Errorf("Expected path %s, got %s", secret.Path, retrieved.Path)
	}

	if string(retrieved.Value) != string(secret.Value) {
		t.Errorf("Expected value %s, got %s", secret.Value, retrieved.Value)
	}

	if retrieved.Metadata["env"] != "production" {
		t.Errorf("Expected metadata env=production, got %s", retrieved.Metadata["env"])
	}

	if retrieved.Version != 1 {
		t.Errorf("Expected version 1, got %d", retrieved.Version)
	}
}

func TestUpdateSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	secret := &Secret{
		Path:      "test/api/key",
		Value:     []byte("old-value"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	// Create
	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Update
	secret.Value = []byte("new-value")
	secret.UpdatedBy = "user123"

	if err := storage.UpdateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetSecret(ctx, "test/api/key")
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if string(retrieved.Value) != "new-value" {
		t.Errorf("Expected new-value, got %s", retrieved.Value)
	}

	if retrieved.Version != 2 {
		t.Errorf("Expected version 2, got %d", retrieved.Version)
	}

	if retrieved.UpdatedBy != "user123" {
		t.Errorf("Expected updated_by=user123, got %s", retrieved.UpdatedBy)
	}
}

func TestDeleteSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	secret := &Secret{
		Path:      "test/temp/secret",
		Value:     []byte("temporary"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	// Create
	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Delete
	if err := storage.DeleteSecret(ctx, "test/temp/secret"); err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Verify it's gone (soft delete)
	_, err := storage.GetSecret(ctx, "test/temp/secret")
	if err == nil {
		t.Error("Expected error when getting deleted secret, got nil")
	}
}

func TestListSecrets(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple secrets
	secrets := []*Secret{
		{
			Path:      "prod/database/url",
			Value:     []byte("value1"),
			Metadata:  map[string]string{},
			Version:   1,
			CreatedAt: time.Now(),
			CreatedBy: "admin",
			UpdatedAt: time.Now(),
			UpdatedBy: "admin",
		},
		{
			Path:      "prod/database/password",
			Value:     []byte("value2"),
			Metadata:  map[string]string{},
			Version:   1,
			CreatedAt: time.Now(),
			CreatedBy: "admin",
			UpdatedAt: time.Now(),
			UpdatedBy: "admin",
		},
		{
			Path:      "prod/api/key",
			Value:     []byte("value3"),
			Metadata:  map[string]string{},
			Version:   1,
			CreatedAt: time.Now(),
			CreatedBy: "admin",
			UpdatedAt: time.Now(),
			UpdatedBy: "admin",
		},
		{
			Path:      "dev/database/url",
			Value:     []byte("value4"),
			Metadata:  map[string]string{},
			Version:   1,
			CreatedAt: time.Now(),
			CreatedBy: "admin",
			UpdatedAt: time.Now(),
			UpdatedBy: "admin",
		},
	}

	for _, secret := range secrets {
		if err := storage.CreateSecret(ctx, secret); err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
	}

	// List all prod secrets
	prodSecrets, err := storage.ListSecrets(ctx, "prod/")
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(prodSecrets) != 3 {
		t.Errorf("Expected 3 prod secrets, got %d", len(prodSecrets))
	}

	// List database secrets
	dbSecrets, err := storage.ListSecrets(ctx, "prod/database/")
	if err != nil {
		t.Fatalf("Failed to list database secrets: %v", err)
	}

	if len(dbSecrets) != 2 {
		t.Errorf("Expected 2 database secrets, got %d", len(dbSecrets))
	}

	// List all secrets
	allSecrets, err := storage.ListSecrets(ctx, "")
	if err != nil {
		t.Fatalf("Failed to list all secrets: %v", err)
	}

	if len(allSecrets) != 4 {
		t.Errorf("Expected 4 total secrets, got %d", len(allSecrets))
	}
}

func TestSecretVersions(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	secret := &Secret{
		Path:      "test/versioned/secret",
		Value:     []byte("version-1"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	// Create secret
	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Create version 1
	version1 := &SecretVersion{
		SecretID:  secret.ID,
		Version:   1,
		Value:     []byte("version-1"),
		CreatedAt: time.Now(),
		CreatedBy: "admin",
	}

	if err := storage.CreateSecretVersion(ctx, version1); err != nil {
		t.Fatalf("Failed to create version 1: %v", err)
	}

	// Update secret (creates version 2)
	secret.Value = []byte("version-2")
	if err := storage.UpdateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	version2 := &SecretVersion{
		SecretID:  secret.ID,
		Version:   2,
		Value:     []byte("version-2"),
		CreatedAt: time.Now(),
		CreatedBy: "admin",
	}

	if err := storage.CreateSecretVersion(ctx, version2); err != nil {
		t.Fatalf("Failed to create version 2: %v", err)
	}

	// Get all versions
	versions, err := storage.GetSecretVersions(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get versions: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}

	// Verify version order (DESC)
	if versions[0].Version != 2 {
		t.Errorf("Expected first version to be 2, got %d", versions[0].Version)
	}

	// Get specific version
	v1, err := storage.GetSecretVersion(ctx, secret.ID, 1)
	if err != nil {
		t.Fatalf("Failed to get version 1: %v", err)
	}

	if string(v1.Value) != "version-1" {
		t.Errorf("Expected version-1, got %s", v1.Value)
	}
}

func TestAuditLogs(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create audit logs
	logs := []*AuditLog{
		{
			Timestamp:  time.Now().Add(-2 * time.Hour),
			Action:     "secret. create",
			User:       "admin",
			SecretPath: "prod/database/password",
			IPAddress:  "192.168. 1.1",
			UserAgent:  "nexusctl/1.0",
			Success:    true,
			Metadata:   map[string]string{"method": "cli"},
			Signature:  "signature1",
		},
		{
			Timestamp:  time.Now().Add(-1 * time.Hour),
			Action:     "secret.read",
			User:       "developer1",
			SecretPath: "prod/database/password",
			IPAddress:  "192.168.1.100",
			UserAgent:  "nexus-agent/1.0",
			Success:    true,
			Metadata:   map[string]string{"method": "api"},
			Signature:  "signature2",
		},
		{
			Timestamp:  time.Now().Add(-30 * time.Minute),
			Action:     "secret.read",
			User:       "attacker",
			SecretPath: "prod/database/password",
			IPAddress:  "203.0.113.1",
			UserAgent:  "curl/7.68.0",
			Success:    false,
			Error:      "unauthorized",
			Metadata:   map[string]string{},
			Signature:  "signature3",
		},
		{
			Timestamp:  time.Now(),
			Action:     "secret. delete",
			User:       "admin",
			SecretPath: "prod/old/key",
			IPAddress:  "192.168.1.1",
			UserAgent:  "nexusctl/1.0",
			Success:    true,
			Metadata:   map[string]string{},
			Signature:  "signature4",
		},
	}

	for _, log := range logs {
		if err := storage.CreateAuditLog(ctx, log); err != nil {
			t.Fatalf("Failed to create audit log: %v", err)
		}
	}

	// Test: Get all logs
	allLogs, err := storage.GetAuditLogs(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("Failed to get all audit logs: %v", err)
	}

	if len(allLogs) != 4 {
		t.Errorf("Expected 4 audit logs, got %d", len(allLogs))
	}

	// Test: Filter by user
	adminLogs, err := storage.GetAuditLogs(ctx, AuditFilter{User: "admin"})
	if err != nil {
		t.Fatalf("Failed to get admin logs: %v", err)
	}

	if len(adminLogs) != 2 {
		t.Errorf("Expected 2 admin logs, got %d", len(adminLogs))
	}

	// Test: Filter by action
	readLogs, err := storage.GetAuditLogs(ctx, AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatalf("Failed to get read logs: %v", err)
	}

	if len(readLogs) != 2 {
		t.Errorf("Expected 2 read logs, got %d", len(readLogs))
	}

	// Test: Filter by success
	successTrue := true
	successLogs, err := storage.GetAuditLogs(ctx, AuditFilter{Success: &successTrue})
	if err != nil {
		t.Fatalf("Failed to get success logs: %v", err)
	}

	if len(successLogs) != 3 {
		t.Errorf("Expected 3 successful logs, got %d", len(successLogs))
	}

	// Test: Filter by time range
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	recentLogs, err := storage.GetAuditLogs(ctx, AuditFilter{StartTime: &oneHourAgo})
	if err != nil {
		t.Fatalf("Failed to get recent logs: %v", err)
	}

	if len(recentLogs) < 2 {
		t.Errorf("Expected at least 2 recent logs, got %d", len(recentLogs))
	}

	// Test: Limit and offset
	limitedLogs, err := storage.GetAuditLogs(ctx, AuditFilter{Limit: 2})
	if err != nil {
		t.Fatalf("Failed to get limited logs: %v", err)
	}

	if len(limitedLogs) != 2 {
		t.Errorf("Expected 2 logs with limit, got %d", len(limitedLogs))
	}
}

func TestRotationPolicy(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	nextRotation := time.Now().Add(30 * 24 * time.Hour) // 30 days from now

	secret := &Secret{
		Path:      "prod/database/password",
		Value:     []byte("encrypted-password"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
		RotationPolicy: &RotationPolicy{
			Enabled:      true,
			Interval:     30 * 24 * time.Hour, // 30 days
			Provider:     "postgresql",
			NextRotation: nextRotation,
		},
	}

	// Create secret with rotation policy
	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Retrieve and verify rotation policy
	retrieved, err := storage.GetSecret(ctx, "prod/database/password")
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if retrieved.RotationPolicy == nil {
		t.Fatal("Expected rotation policy, got nil")
	}

	if !retrieved.RotationPolicy.Enabled {
		t.Error("Expected rotation enabled")
	}

	if retrieved.RotationPolicy.Provider != "postgresql" {
		t.Errorf("Expected provider postgresql, got %s", retrieved.RotationPolicy.Provider)
	}

	if retrieved.RotationPolicy.Interval != 30*24*time.Hour {
		t.Errorf("Expected interval 30 days, got %v", retrieved.RotationPolicy.Interval)
	}
}

func TestPingAndClose(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test ping
	if err := storage.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	// Test close
	if err := storage.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Ping should fail after close
	if err := storage.Ping(ctx); err == nil {
		t.Error("Expected ping to fail after close, got nil")
	}
}

func TestBackup(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	// Skip backup test for MemoryStorage
	if _, ok := storage.(*MemoryStorage); ok {
		t.Skip("Backup not supported for MemoryStorage")
	}

	ctx := context.Background()

	// Create a secret
	secret := &Secret{
		Path:      "test/backup/secret",
		Value:     []byte("backup-test"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Create backup
	backupPath := filepath.Join(t.TempDir(), "backup. db")
	if err := storage.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Backup file was not created")
	}

	// Open backup and verify data
	backupStorage, err := NewSQLiteStorage(backupPath)
	if err != nil {
		t.Fatalf("Failed to open backup: %v", err)
	}
	defer backupStorage.Close()

	// Verify secret exists in backup
	retrieved, err := backupStorage.GetSecret(ctx, "test/backup/secret")
	if err != nil {
		t.Fatalf("Failed to get secret from backup: %v", err)
	}

	if string(retrieved.Value) != "backup-test" {
		t.Errorf("Expected backup-test, got %s", retrieved.Value)
	}
}
