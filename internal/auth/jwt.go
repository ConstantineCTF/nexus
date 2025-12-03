package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// JWTManager handles JWT token generation and validation
type JWTManager struct {
	secret []byte
	expiry time.Duration
}

// Claims represents JWT claims
type Claims struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secret []byte, expiry time.Duration) *JWTManager {
	return &JWTManager{
		secret: secret,
		expiry: expiry,
	}
}

// GenerateToken generates a new JWT token
func (m *JWTManager) GenerateToken(userID, role string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(m.expiry)

	claims := Claims{
		UserID:    userID,
		Role:      role,
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}

	// Create header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Base64 encode header and claims
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signature
	message := headerB64 + "." + claimsB64
	signature := m.sign([]byte(message))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	token := message + "." + signatureB64
	return token, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (m *JWTManager) ValidateToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	expectedSig := m.sign([]byte(message))
	if !hmac.Equal(signature, expectedSig) {
		return nil, errors.New("invalid signature")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid claims encoding")
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Check expiration
	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// sign creates an HMAC-SHA256 signature
func (m *JWTManager) sign(message []byte) []byte {
	h := hmac.New(sha256.New, m.secret)
	h.Write(message)
	return h.Sum(nil)
}
