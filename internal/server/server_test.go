package server

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ConstantineCTF/nexus/internal/crypto"
	"github.com/ConstantineCTF/nexus/internal/storage"
)

func setupTestServer(t *testing.T) *Server {
	store := storage.NewMemoryStorage()

	// Load or create keyring
	var keyring *crypto.Keyring
	var err error

	keyringDir := "./data/keys"
	keyringPassword := os.Getenv("NEXUS_KEY_PASSWORD")
	if keyringPassword == "" {
		keyringPassword = "changeme-in-production" // Default password
	}

	// Try to load existing keyring
	keyring, err = crypto.LoadFromFiles(keyringDir, keyringPassword)
	if err != nil {
		// Keyring doesn't exist, create new one
		log.Println("No existing keyring found, creating new one...")
		keyring, err = crypto.NewKeyring()
		if err != nil {
			log.Fatalf("Failed to create keyring: %v", err)
		}

		// Save keyring to disk
		if err := keyring.SaveToFiles(keyringDir, keyringPassword); err != nil {
			log.Fatalf("Failed to save keyring: %v", err)
		}
		log.Printf("✓ Keyring saved to %s", keyringDir)
	} else {
		log.Printf("✓ Loaded existing keyring from %s", keyringDir)
	}

	cfg := Config{
		Address:      ":8080",
		JWTSecret:    []byte("test-secret-key-32-bytes-long!!"),
		JWTExpiry:    time.Hour,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return NewServer(cfg, store, keyring)
}

func TestHealthEndpoint(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
	}
}

func TestLoginEndpoint(t *testing.T) {
	server := setupTestServer(t)

	// Test successful login
	loginReq := LoginRequest{
		Username: "admin",
		Password: "admin",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Token == "" {
		t.Error("Expected token in response")
	}

	if resp.User.ID != "admin-001" {
		t.Errorf("Expected user ID 'admin-001', got '%s'", resp.User.ID)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	server := setupTestServer(t)

	loginReq := LoginRequest{
		Username: "admin",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestSecretsEndpointRequiresAuth(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	w := httptest.NewRecorder()

	// Use the middleware-wrapped handler
	handler := server.requireAuth(server.handleSecrets)
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestCreateAndGetSecret(t *testing.T) {
	server := setupTestServer(t)

	// First, login to get a token
	loginReq := LoginRequest{
		Username: "admin",
		Password: "admin",
	}
	loginBody, _ := json.Marshal(loginReq)

	loginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReqHTTP.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()

	server.handleLogin(loginW, loginReqHTTP)

	var loginResp LoginResponse
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)

	// Create a secret
	createReq := CreateSecretRequest{
		Path:     "test/database/password",
		Value:    "supersecret123",
		Metadata: map[string]string{"env": "test"},
	}
	createBody, _ := json.Marshal(createReq)

	createReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(createBody))
	createReqHTTP.Header.Set("Content-Type", "application/json")
	createReqHTTP.Header.Set("Authorization", "Bearer "+loginResp.Token)
	createW := httptest.NewRecorder()

	handler := server.requireAuth(server.handleSecrets)
	handler(createW, createReqHTTP)

	if createW.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", createW.Code, createW.Body.String())
	}

	var createResp SecretResponse
	json.Unmarshal(createW.Body.Bytes(), &createResp)

	if createResp.Path != "test/database/password" {
		t.Errorf("Expected path 'test/database/password', got '%s'", createResp.Path)
	}

	// Get the secret
	getReqHTTP := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/test/database/password", nil)
	getReqHTTP.Header.Set("Authorization", "Bearer "+loginResp.Token)
	getW := httptest.NewRecorder()

	getHandler := server.requireAuth(server.handleSecret)
	getHandler(getW, getReqHTTP)

	if getW.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", getW.Code, getW.Body.String())
	}

	var getResp SecretResponse
	json.Unmarshal(getW.Body.Bytes(), &getResp)

	if getResp.Value != "supersecret123" {
		t.Errorf("Expected value 'supersecret123', got '%s'", getResp.Value)
	}

	if getResp.Metadata["env"] != "test" {
		t.Errorf("Expected metadata env='test', got '%s'", getResp.Metadata["env"])
	}
}

func TestListSecrets(t *testing.T) {
	server := setupTestServer(t)

	// Login
	loginReq := LoginRequest{Username: "admin", Password: "admin"}
	loginBody, _ := json.Marshal(loginReq)
	loginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReqHTTP.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	server.handleLogin(loginW, loginReqHTTP)
	var loginResp LoginResponse
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)

	// Create multiple secrets
	secrets := []CreateSecretRequest{
		{Path: "prod/db/password", Value: "secret1"},
		{Path: "prod/api/key", Value: "secret2"},
		{Path: "dev/db/password", Value: "secret3"},
	}

	for _, s := range secrets {
		body, _ := json.Marshal(s)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+loginResp.Token)
		w := httptest.NewRecorder()
		handler := server.requireAuth(server.handleSecrets)
		handler(w, req)
	}

	// List all secrets
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	listReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	listW := httptest.NewRecorder()
	listHandler := server.requireAuth(server.handleSecrets)
	listHandler(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", listW.Code)
	}

	var listResp SecretListResponse
	json.Unmarshal(listW.Body.Bytes(), &listResp)

	if listResp.Total != 3 {
		t.Errorf("Expected 3 secrets, got %d", listResp.Total)
	}

	// List with prefix filter
	listReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/secrets?prefix=prod/", nil)
	listReq2.Header.Set("Authorization", "Bearer "+loginResp.Token)
	listW2 := httptest.NewRecorder()
	listHandler(listW2, listReq2)

	var listResp2 SecretListResponse
	json.Unmarshal(listW2.Body.Bytes(), &listResp2)

	if listResp2.Total != 2 {
		t.Errorf("Expected 2 prod secrets, got %d", listResp2.Total)
	}
}

func TestDeleteSecret(t *testing.T) {
	server := setupTestServer(t)

	// Login
	loginReq := LoginRequest{Username: "admin", Password: "admin"}
	loginBody, _ := json.Marshal(loginReq)
	loginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReqHTTP.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	server.handleLogin(loginW, loginReqHTTP)
	var loginResp LoginResponse
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)

	// Create a secret
	createReq := CreateSecretRequest{Path: "temp/secret", Value: "delete-me"}
	createBody, _ := json.Marshal(createReq)
	createReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(createBody))
	createReqHTTP.Header.Set("Content-Type", "application/json")
	createReqHTTP.Header.Set("Authorization", "Bearer "+loginResp.Token)
	createW := httptest.NewRecorder()
	handler := server.requireAuth(server.handleSecrets)
	handler(createW, createReqHTTP)

	// Delete the secret
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/temp/secret", nil)
	deleteReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	deleteW := httptest.NewRecorder()
	deleteHandler := server.requireAuth(server.handleSecret)
	deleteHandler(deleteW, deleteReq)

	if deleteW.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d: %s", deleteW.Code, deleteW.Body.String())
	}

	// Verify it's gone
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/temp/secret", nil)
	getReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	getW := httptest.NewRecorder()
	getHandler := server.requireAuth(server.handleSecret)
	getHandler(getW, getReq)

	if getW.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 after delete, got %d", getW.Code)
	}
}

func TestAPIKeyManagement(t *testing.T) {
	server := setupTestServer(t)

	// Login
	loginReq := LoginRequest{Username: "admin", Password: "admin"}
	loginBody, _ := json.Marshal(loginReq)
	loginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReqHTTP.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	server.handleLogin(loginW, loginReqHTTP)
	var loginResp LoginResponse
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)

	// Create an API key
	createKeyReq := CreateAPIKeyRequest{Name: "test-key"}
	createKeyBody, _ := json.Marshal(createKeyReq)
	createKeyReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/apikeys", bytes.NewReader(createKeyBody))
	createKeyReqHTTP.Header.Set("Content-Type", "application/json")
	createKeyReqHTTP.Header.Set("Authorization", "Bearer "+loginResp.Token)
	createKeyW := httptest.NewRecorder()
	keyHandler := server.requireAuth(server.handleAPIKeys)
	keyHandler(createKeyW, createKeyReqHTTP)

	if createKeyW.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", createKeyW.Code, createKeyW.Body.String())
	}

	var createKeyResp CreateAPIKeyResponse
	json.Unmarshal(createKeyW.Body.Bytes(), &createKeyResp)

	if createKeyResp.Key == "" {
		t.Error("Expected API key in response")
	}

	if createKeyResp.Name != "test-key" {
		t.Errorf("Expected name 'test-key', got '%s'", createKeyResp.Name)
	}

	// Use the API key to access secrets
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	listReq.Header.Set("X-API-Key", createKeyResp.Key)
	listW := httptest.NewRecorder()
	listHandler := server.requireAuth(server.handleSecrets)
	listHandler(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Errorf("Expected status 200 with API key, got %d", listW.Code)
	}

	// List API keys
	listKeysReq := httptest.NewRequest(http.MethodGet, "/api/v1/apikeys", nil)
	listKeysReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	listKeysW := httptest.NewRecorder()
	keyHandler(listKeysW, listKeysReq)

	var listKeysResp APIKeyListResponse
	json.Unmarshal(listKeysW.Body.Bytes(), &listKeysResp)

	if listKeysResp.Total != 1 {
		t.Errorf("Expected 1 API key, got %d", listKeysResp.Total)
	}
}

func TestAuditLogsRequiresAdmin(t *testing.T) {
	server := setupTestServer(t)

	// Add a non-admin user
	server.AddUser("developer", &User{
		ID:       "dev-001",
		Name:     "Developer",
		Role:     "developer",
		Password: "devpass",
	})

	// Login as developer
	loginReq := LoginRequest{Username: "developer", Password: "devpass"}
	loginBody, _ := json.Marshal(loginReq)
	loginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReqHTTP.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	server.handleLogin(loginW, loginReqHTTP)
	var loginResp LoginResponse
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)

	// Try to access audit logs
	auditReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	auditReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	auditW := httptest.NewRecorder()
	auditHandler := server.requireAuth(server.handleAuditLogs)
	auditHandler(auditW, auditReq)

	if auditW.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for non-admin, got %d", auditW.Code)
	}

	// Login as admin and access audit logs
	adminLoginReq := LoginRequest{Username: "admin", Password: "admin"}
	adminLoginBody, _ := json.Marshal(adminLoginReq)
	adminLoginReqHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(adminLoginBody))
	adminLoginReqHTTP.Header.Set("Content-Type", "application/json")
	adminLoginW := httptest.NewRecorder()
	server.handleLogin(adminLoginW, adminLoginReqHTTP)
	var adminLoginResp LoginResponse
	json.Unmarshal(adminLoginW.Body.Bytes(), &adminLoginResp)

	adminAuditReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	adminAuditReq.Header.Set("Authorization", "Bearer "+adminLoginResp.Token)
	adminAuditW := httptest.NewRecorder()
	auditHandler(adminAuditW, adminAuditReq)

	if adminAuditW.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin, got %d: %s", adminAuditW.Code, adminAuditW.Body.String())
	}
}
