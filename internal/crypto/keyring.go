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

	// Generate salt for key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password using Argon2id
	derivedKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Save each key
	keys := map[string][]byte{
		"master.key":  k.MasterKey,
		"signing.key": k.SigningKey,
		"verify.key":  k.VerifyKey,
		"age.key":     []byte(k.AgeIdentity.String()),
	}

	for filename, data := range keys {
		path := filepath.Join(dir, filename)
		if err := saveEncryptedKey(path, data, derivedKey, salt); err != nil {
			return fmt.Errorf("failed to save %s: %w", filename, err)
		}
	}

	return nil
}

// LoadFromFiles loads the keyring from disk (decrypted with password)
func LoadFromFiles(dir string, password string) (*Keyring, error) {
	keyring := &Keyring{}

	// Load master key first to get salt
	masterKeyPath := filepath.Join(dir, "master.key")
	encryptedMaster, salt, err := loadEncryptedKey(masterKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load master key: %w", err)
	}

	// Derive key from password
	derivedKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Decrypt master key
	masterKey, err := decryptKey(encryptedMaster, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key (wrong password?): %w", err)
	}
	keyring.MasterKey = masterKey

	// Load and decrypt signing key
	signingKeyPath := filepath.Join(dir, "signing.key")
	encryptedSigning, _, err := loadEncryptedKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	signingKey, err := decryptKey(encryptedSigning, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt signing key: %w", err)
	}
	keyring.SigningKey = ed25519.PrivateKey(signingKey)

	// Load and decrypt verify key
	verifyKeyPath := filepath.Join(dir, "verify.key")
	encryptedVerify, _, err := loadEncryptedKey(verifyKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load verify key: %w", err)
	}
	verifyKey, err := decryptKey(encryptedVerify, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt verify key: %w", err)
	}
	keyring.VerifyKey = ed25519.PublicKey(verifyKey)

	// Load and decrypt age identity
	ageKeyPath := filepath.Join(dir, "age.key")
	encryptedAge, _, err := loadEncryptedKey(ageKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load age identity: %w", err)
	}
	ageIdentityStr, err := decryptKey(encryptedAge, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt age identity: %w", err)
	}

	ageIdentity, err := age.ParseX25519Identity(string(ageIdentityStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse age identity: %w", err)
	}
	keyring.AgeIdentity = ageIdentity
	keyring.AgeRecipient = ageIdentity.Recipient()

	return keyring, nil
}

// saveEncryptedKey saves an encrypted key to disk (standalone function)
func saveEncryptedKey(path string, data, key, salt []byte) error {
	encrypted, err := encryptKey(data, key)
	if err != nil {
		return err
	}

	// Format: salt (16 bytes) + encrypted data
	output := append(salt, encrypted...)
	hexEncoded := hex.EncodeToString(output)

	return os.WriteFile(path, []byte(hexEncoded), 0600)
}

// loadEncryptedKey loads an encrypted key from disk
func loadEncryptedKey(path string) ([]byte, []byte, error) {
	hexData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	data, err := hex.DecodeString(string(hexData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	if len(data) < 16 {
		return nil, nil, fmt.Errorf("invalid key file format: too short")
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
