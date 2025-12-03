package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNewKeyring(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keyring: %v", err)
	}

	if len(keyring.MasterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(keyring.MasterKey))
	}

	if keyring.SigningKey == nil {
		t.Error("Signing key is nil")
	}

	if keyring.AgeIdentity == nil {
		t.Error("Age identity is nil")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keyring: %v", err)
	}

	plaintext := []byte("super secret password")

	// Test age encryption
	encrypted, err := keyring.EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := keyring.DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}

	// Test AES encryption
	encryptedAES, err := keyring.EncryptAES(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt with AES: %v", err)
	}

	decryptedAES, err := keyring.DecryptAES(encryptedAES)
	if err != nil {
		t.Fatalf("Failed to decrypt with AES: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedAES) {
		t.Errorf("AES decrypted data doesn't match original")
	}
}

func TestSignVerify(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keyring: %v", err)
	}

	data := "important audit log entry"

	signature, err := keyring.SignString(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	valid, err := keyring.VerifyString(data, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed for valid signature")
	}

	// Test with tampered data
	tamperedData := "tampered audit log entry"
	valid, err = keyring.VerifyString(tamperedData, signature)
	if err != nil {
		t.Fatalf("Failed to verify tampered signature: %v", err)
	}

	if valid {
		t.Error("Signature verification succeeded for tampered data")
	}
}

func TestSaveLoadKeyring(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "nexus-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keyring: %v", err)
	}

	password := "test-password-123"

	// Save keyring
	if err := keyring.SaveToFiles(tempDir, password); err != nil {
		t.Fatalf("Failed to save keyring: %v", err)
	}

	// Verify files exist
	requiredFiles := []string{"master.key", "signing.key", "verify.key", "age.key"}
	for _, filename := range requiredFiles {
		path := filepath.Join(tempDir, filename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("Expected file %s does not exist", filename)
		}
	}

	// Load keyring
	loadedKeyring, err := LoadFromFiles(tempDir, password)
	if err != nil {
		t.Fatalf("Failed to load keyring: %v", err)
	}

	// Verify master key matches
	if !bytes.Equal(keyring.MasterKey, loadedKeyring.MasterKey) {
		t.Error("Loaded master key doesn't match original")
	}

	// Verify signing key matches
	if !bytes.Equal(keyring.SigningKey, loadedKeyring.SigningKey) {
		t.Error("Loaded signing key doesn't match original")
	}

	// Test with wrong password
	_, err = LoadFromFiles(tempDir, "wrong-password")
	if err == nil {
		t.Error("Expected error with wrong password, got nil")
	}
}

func TestZeroize(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keyring: %v", err)
	}

	// Verify key is not all zeros
	allZeros := true
	for _, b := range keyring.MasterKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Master key is all zeros before zeroization")
	}

	// Zeroize
	keyring.Zeroize()

	// Verify key is all zeros
	for i, b := range keyring.MasterKey {
		if b != 0 {
			t.Errorf("Master key not zeroized at index %d: %v", i, b)
		}
	}
}
