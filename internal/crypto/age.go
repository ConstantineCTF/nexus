package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

// EncryptWithAge encrypts data using age encryption
func EncryptWithAge(data []byte, recipient *age.X25519Recipient) ([]byte, error) {
	if recipient == nil {
		return nil, fmt.Errorf("recipient cannot be nil")
	}

	var encrypted bytes.Buffer

	writer, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create age writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close age writer: %w", err)
	}

	return encrypted.Bytes(), nil
}

// DecryptWithAge decrypts data using age encryption
func DecryptWithAge(encrypted []byte, identity *age.X25519Identity) ([]byte, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity cannot be nil")
	}

	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create age reader: %w", err)
	}

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decrypted, nil
}

// EncryptSecret encrypts a secret value using the keyring
func (k *Keyring) EncryptSecret(plaintext []byte) ([]byte, error) {
	return EncryptWithAge(plaintext, k.AgeRecipient)
}

// DecryptSecret decrypts a secret value using the keyring
func (k *Keyring) DecryptSecret(ciphertext []byte) ([]byte, error) {
	return DecryptWithAge(ciphertext, k.AgeIdentity)
}
