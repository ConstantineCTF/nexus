package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// Sign signs data using Ed25519 (for audit logs)
func (k *Keyring) Sign(data []byte) (string, error) {
	if k.SigningKey == nil {
		return "", fmt.Errorf("signing key not initialized")
	}

	signature := ed25519.Sign(k.SigningKey, data)
	return hex.EncodeToString(signature), nil
}

// Verify verifies a signature using Ed25519
func (k *Keyring) Verify(data []byte, signatureHex string) (bool, error) {
	if k.VerifyKey == nil {
		return false, fmt.Errorf("verify key not initialized")
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	return ed25519.Verify(k.VerifyKey, data, signature), nil
}

// SignString is a convenience method for signing strings
func (k *Keyring) SignString(data string) (string, error) {
	return k.Sign([]byte(data))
}

// VerifyString is a convenience method for verifying string signatures
func (k *Keyring) VerifyString(data string, signatureHex string) (bool, error) {
	return k.Verify([]byte(data), signatureHex)
}
