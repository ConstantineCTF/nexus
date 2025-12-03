package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// APIKey represents an API key
type APIKey struct {
	ID        string
	UserID    string
	Role      string
	Name      string
	KeyHash   string // SHA-256 hash of the key
	Prefix    string // First 8 chars for identification
	CreatedAt time.Time
	ExpiresAt *time.Time
	LastUsed  *time.Time
	Revoked   bool
}

// APIKeyStore manages API keys
type APIKeyStore struct {
	keys map[string]*APIKey // keyHash -> APIKey
	mu   sync.RWMutex
}

// NewAPIKeyStore creates a new API key store
func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{
		keys: make(map[string]*APIKey),
	}
}

// CreateKey creates a new API key and returns the key and raw key string
func (s *APIKeyStore) CreateKey(userID, role, name string, expiresAt *time.Time) (*APIKey, string, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", err
	}

	rawKey := "nxs_" + hex.EncodeToString(keyBytes)

	// Hash the key for storage
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	// Generate ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", err
	}

	key := &APIKey{
		ID:        hex.EncodeToString(idBytes),
		UserID:    userID,
		Role:      role,
		Name:      name,
		KeyHash:   keyHash,
		Prefix:    rawKey[:12], // "nxs_" + first 8 hex chars
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	s.mu.Lock()
	s.keys[keyHash] = key
	s.mu.Unlock()

	return key, rawKey, nil
}

// ValidateKey validates an API key and returns the key info
func (s *APIKeyStore) ValidateKey(rawKey string) (*APIKey, error) {
	// Hash the provided key
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keys[keyHash]
	if !exists {
		return nil, errors.New("invalid API key")
	}

	if key.Revoked {
		return nil, errors.New("API key has been revoked")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, errors.New("API key has expired")
	}

	// Update last used
	now := time.Now()
	key.LastUsed = &now

	return key, nil
}

// RevokeKey revokes an API key
func (s *APIKeyStore) RevokeKey(keyID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range s.keys {
		if key.ID == keyID {
			if key.UserID != userID {
				return errors.New("not authorized to revoke this key")
			}
			key.Revoked = true
			return nil
		}
	}

	return errors.New("key not found")
}

// ListKeys returns all non-revoked keys for a user
func (s *APIKeyStore) ListKeys(userID string) []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []*APIKey
	for _, key := range s.keys {
		if key.UserID == userID && !key.Revoked {
			keys = append(keys, key)
		}
	}

	return keys
}
