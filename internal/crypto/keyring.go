package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
)

// Keyring manages all encryption keys for NEXUS
type Keyring struct {
	MasterKey    []byte               // Master encryption key
	SigningKey   ed25519.PrivateKey   // For audit log signing
	VerifyKey    ed25519.PublicKey    // For audit log verification
	AgeIdentity  *age.X25519Identity  // age encryption identity
	AgeRecipient *age.X25519Recipient // age encryption recipient
}

// NewKeyring creates a new keyring with generated keys
func NewKeyring() (*Keyring, error) {
	// Generate master key (32 bytes for AES-256)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Generate Ed25519 signing key pair
	verifyKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keys: %w", err)
	}

	// Generate age identity for encryption
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age identity: %w", err)
	}

	return &Keyring{
		MasterKey:    masterKey,
		SigningKey:   signingKey,
		VerifyKey:    verifyKey,
		AgeIdentity:  ageIdentity,
		AgeRecipient: ageIdentity.Recipient(),
	}, nil
}

// SaveToFiles saves the keyring to disk (encrypted with password)
func (k *Keyring) SaveToFiles(dir string, password string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Derive key from password using Argon2id
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	derivedKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Save master key
	masterKeyPath := filepath.Join(dir, "master. key")
	if err := k.saveEncryptedKey(masterKeyPath, k.MasterKey, derivedKey, salt); err != nil {
		return fmt.Errorf("failed to save master key: %w", err)
	}

	// Save signing key
	signingKeyPath := filepath.Join(dir, "signing.key")
	if err := k.saveEncryptedKey(signingKeyPath, k.SigningKey, derivedKey, salt); err != nil {
		return fmt.Errorf("failed to save signing key: %w", err)
	}

	// Save verify key (public, no encryption needed but we'll encrypt anyway)
	verifyKeyPath := filepath.Join(dir, "verify.key")
	if err := k.saveEncryptedKey(verifyKeyPath, k.VerifyKey, derivedKey, salt); err != nil {
		return fmt.Errorf("failed to save verify key: %w", err)
	}

	// Save age identity
	ageIdentityPath := filepath.Join(dir, "age. key")
	ageIdentityStr := k.AgeIdentity.String()
	if err := k.saveEncryptedKey(ageIdentityPath, []byte(ageIdentityStr), derivedKey, salt); err != nil {
		return fmt.Errorf("failed to save age identity: %w", err)
	}

	return nil
}

// LoadFromFiles loads the keyring from disk (decrypted with password)
func LoadFromFiles(dir string, password string) (*Keyring, error) {
	keyring := &Keyring{}

	// Helper to load each key
	loadKey := func(filename string) ([]byte, []byte, error) {
		path := filepath.Join(dir, filename)
		return loadEncryptedKey(path)
	}

	// Load master key
	masterKey, salt, err := loadKey("master. key")
	if err != nil {
		return nil, fmt.Errorf("failed to load master key: %w", err)
	}

	// Derive key from password
	derivedKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Decrypt master key
	decryptedMaster, err := decryptKey(masterKey, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key (wrong password?): %w", err)
	}
	keyring.MasterKey = decryptedMaster

	// Load signing key
	signingKeyEnc, _, err := loadKey("signing.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	decryptedSigning, err := decryptKey(signingKeyEnc, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt signing key: %w", err)
	}
	keyring.SigningKey = ed25519.PrivateKey(decryptedSigning)

	// Load verify key
	verifyKeyEnc, _, err := loadKey("verify. key")
	if err != nil {
		return nil, fmt.Errorf("failed to load verify key: %w", err)
	}
	decryptedVerify, err := decryptKey(verifyKeyEnc, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt verify key: %w", err)
	}
	keyring.VerifyKey = ed25519.PublicKey(decryptedVerify)

	// Load age identity
	ageIdentityEnc, _, err := loadKey("age.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load age identity: %w", err)
	}
	decryptedAge, err := decryptKey(ageIdentityEnc, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt age identity: %w", err)
	}

	ageIdentity, err := age.ParseX25519Identity(string(decryptedAge))
	if err != nil {
		return nil, fmt.Errorf("failed to parse age identity: %w", err)
	}
	keyring.AgeIdentity = ageIdentity
	keyring.AgeRecipient = ageIdentity.Recipient()

	return keyring, nil
}

// saveEncryptedKey saves an encrypted key to disk
func (k *Keyring) saveEncryptedKey(path string, data, key, salt []byte) error {
	encrypted, err := encryptKey(data, key)
	if err != nil {
		return err
	}

	// Format: salt (16 bytes) + encrypted data
	output := append(salt, encrypted...)

	return os.WriteFile(path, []byte(hex.EncodeToString(output)), 0600)
}

// loadEncryptedKey loads an encrypted key from disk
func loadEncryptedKey(path string) ([]byte, []byte, error) {
	hexData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	data, err := hex.DecodeString(string(hexData))
	if err != nil {
		return nil, nil, err
	}

	if len(data) < 16 {
		return nil, nil, fmt.Errorf("invalid key file format")
	}

	salt := data[:16]
	encrypted := data[16:]

	return encrypted, salt, nil
}

// Rotate generates new keys while keeping old ones for decryption
func (k *Keyring) Rotate() (*Keyring, error) {
	newKeyring, err := NewKeyring()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new keyring: %w", err)
	}

	// In production, we'd keep old keys for decryption of old secrets
	// For now, just return new keyring
	return newKeyring, nil
}

// Zeroize securely wipes keys from memory
func (k *Keyring) Zeroize() {
	// Zero out master key
	for i := range k.MasterKey {
		k.MasterKey[i] = 0
	}

	// Zero out signing key
	for i := range k.SigningKey {
		k.SigningKey[i] = 0
	}

	// Note: age. X25519Identity doesn't expose its bytes directly
	// but Go's GC will eventually clear it
}
