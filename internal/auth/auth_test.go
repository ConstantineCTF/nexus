package auth

import (
	"testing"
	"time"
)

func TestJWTGenerateAndValidate(t *testing.T) {
	manager := NewJWTManager([]byte("test-secret-key-32-bytes-long!!"), time.Hour)

	token, expiresAt, err := manager.GenerateToken("user-123", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	if expiresAt.Before(time.Now()) {
		t.Error("Token should expire in the future")
	}

	// Validate the token
	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", claims.UserID)
	}

	if claims.Role != "admin" {
		t.Errorf("Expected role 'admin', got '%s'", claims.Role)
	}
}

func TestJWTExpiredToken(t *testing.T) {
	manager := NewJWTManager([]byte("test-secret-key-32-bytes-long!!"), -time.Hour) // Already expired

	token, _, err := manager.GenerateToken("user-123", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = manager.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestJWTInvalidSignature(t *testing.T) {
	manager1 := NewJWTManager([]byte("secret-key-one-32-bytes-long!!!"), time.Hour)
	manager2 := NewJWTManager([]byte("secret-key-two-32-bytes-long!!!"), time.Hour)

	token, _, err := manager1.GenerateToken("user-123", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = manager2.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestAPIKeyCreateAndValidate(t *testing.T) {
	store := NewAPIKeyStore()

	key, rawKey, err := store.CreateKey("user-123", "admin", "test-key", nil)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	if key.ID == "" {
		t.Error("Key ID should not be empty")
	}

	if key.UserID != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", key.UserID)
	}

	if rawKey == "" {
		t.Error("Raw key should not be empty")
	}

	// Validate the key
	validatedKey, err := store.ValidateKey(rawKey)
	if err != nil {
		t.Fatalf("Failed to validate key: %v", err)
	}

	if validatedKey.UserID != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", validatedKey.UserID)
	}
}

func TestAPIKeyExpiration(t *testing.T) {
	store := NewAPIKeyStore()

	expiry := time.Now().Add(-time.Hour) // Already expired
	_, rawKey, err := store.CreateKey("user-123", "admin", "test-key", &expiry)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	_, err = store.ValidateKey(rawKey)
	if err == nil {
		t.Error("Expected error for expired key")
	}
}

func TestAPIKeyRevocation(t *testing.T) {
	store := NewAPIKeyStore()

	key, rawKey, err := store.CreateKey("user-123", "admin", "test-key", nil)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Revoke the key
	err = store.RevokeKey(key.ID, "user-123")
	if err != nil {
		t.Fatalf("Failed to revoke key: %v", err)
	}

	// Validate should fail
	_, err = store.ValidateKey(rawKey)
	if err == nil {
		t.Error("Expected error for revoked key")
	}
}

func TestAPIKeyListKeys(t *testing.T) {
	store := NewAPIKeyStore()

	// Create multiple keys for user-123
	store.CreateKey("user-123", "admin", "key-1", nil)
	store.CreateKey("user-123", "admin", "key-2", nil)
	store.CreateKey("other-user", "developer", "key-3", nil)

	keys := store.ListKeys("user-123")
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys for user-123, got %d", len(keys))
	}

	otherKeys := store.ListKeys("other-user")
	if len(otherKeys) != 1 {
		t.Errorf("Expected 1 key for other-user, got %d", len(otherKeys))
	}
}

func TestPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()

	// Add policies
	engine.AddPolicy(&Policy{
		Role: "developer",
		Permissions: []Permission{
			{Resource: "secrets/dev/*", Actions: []string{"read", "write"}},
			{Resource: "secrets/prod/*", Actions: []string{"read"}},
		},
	})

	engine.AddPolicy(&Policy{
		Role: "admin",
		Permissions: []Permission{
			{Resource: "*", Actions: []string{"*"}},
		},
	})

	// Test developer permissions
	if !engine.CanAccess("developer", "secrets/dev/password", "read") {
		t.Error("Developer should be able to read dev secrets")
	}

	if !engine.CanAccess("developer", "secrets/dev/password", "write") {
		t.Error("Developer should be able to write dev secrets")
	}

	if !engine.CanAccess("developer", "secrets/prod/password", "read") {
		t.Error("Developer should be able to read prod secrets")
	}

	if engine.CanAccess("developer", "secrets/prod/password", "write") {
		t.Error("Developer should not be able to write prod secrets")
	}

	// Test admin permissions
	if !engine.CanAccess("admin", "secrets/prod/password", "delete") {
		t.Error("Admin should have full access")
	}
}
