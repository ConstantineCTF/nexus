package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ConstantineCTF/nexus/internal/storage"
	"github.com/google/uuid"
)

// handleHealth returns the health status of the server
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()
	err := s.storage.Ping(ctx)

	resp := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
	}

	if err != nil {
		resp.Status = "unhealthy"
		resp.Error = err.Error()
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleSecrets handles GET (list) and POST (create) for /api/v1/secrets
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListSecrets(w, r)
	case http.MethodPost:
		s.handleCreateSecret(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSecret handles GET, PUT, DELETE for /api/v1/secrets/{path}
func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetSecret(w, r)
	case http.MethodPut:
		s.handleUpdateSecret(w, r)
	case http.MethodDelete:
		s.handleDeleteSecret(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleListSecrets lists all secrets with optional prefix filter
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	prefix := r.URL.Query().Get("prefix")

	// Log the action
	s.logAuditEvent(r, "secret.list", "", prefix, userID, true, "")

	secrets, err := s.storage.ListSecrets(ctx, prefix)
	if err != nil {
		s.logAuditEvent(r, "secret.list", "", prefix, userID, false, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}

	// Convert to response format (without exposing encrypted values)
	items := make([]SecretResponse, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, SecretResponse{
			ID:        secret.ID,
			Path:      secret.Path,
			Metadata:  secret.Metadata,
			Version:   secret.Version,
			CreatedAt: secret.CreatedAt,
			CreatedBy: secret.CreatedBy,
			UpdatedAt: secret.UpdatedAt,
			UpdatedBy: secret.UpdatedBy,
		})
	}

	writeJSON(w, http.StatusOK, SecretListResponse{
		Secrets: items,
		Total:   len(items),
	})
}

// handleGetSecret retrieves a single secret by path
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract path from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "secret path is required")
		return
	}

	secret, err := s.storage.GetSecret(ctx, path)
	if err != nil {
		s.logAuditEvent(r, "secret.read", "", path, userID, false, err.Error())
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}

	// Decrypt the value
	decryptedValue, err := s.keyring.DecryptAES(secret.Value)
	if err != nil {
		s.logAuditEvent(r, "secret.read", secret.ID, path, userID, false, "decryption failed")
		writeError(w, http.StatusInternalServerError, "failed to decrypt secret")
		return
	}

	s.logAuditEvent(r, "secret.read", secret.ID, path, userID, true, "")

	writeJSON(w, http.StatusOK, SecretResponse{
		ID:        secret.ID,
		Path:      secret.Path,
		Value:     string(decryptedValue),
		Metadata:  secret.Metadata,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt,
		CreatedBy: secret.CreatedBy,
		UpdatedAt: secret.UpdatedAt,
		UpdatedBy: secret.UpdatedBy,
	})
}

// handleCreateSecret creates a new secret
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	// Encrypt the value
	encryptedValue, err := s.keyring.EncryptAES([]byte(req.Value))
	if err != nil {
		s.logAuditEvent(r, "secret.create", "", req.Path, userID, false, "encryption failed")
		writeError(w, http.StatusInternalServerError, "failed to encrypt secret")
		return
	}

	now := time.Now()
	secret := &storage.Secret{
		ID:        uuid.New().String(),
		Path:      req.Path,
		Value:     encryptedValue,
		Metadata:  req.Metadata,
		Version:   1,
		CreatedAt: now,
		CreatedBy: userID,
		UpdatedAt: now,
		UpdatedBy: userID,
	}

	if secret.Metadata == nil {
		secret.Metadata = make(map[string]string)
	}

	if err := s.storage.CreateSecret(ctx, secret); err != nil {
		s.logAuditEvent(r, "secret.create", "", req.Path, userID, false, err.Error())
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "secret already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create secret")
		return
	}

	// Create initial version
	version := &storage.SecretVersion{
		ID:        uuid.New().String(),
		SecretID:  secret.ID,
		Version:   1,
		Value:     encryptedValue,
		CreatedAt: now,
		CreatedBy: userID,
	}
	_ = s.storage.CreateSecretVersion(ctx, version)

	s.logAuditEvent(r, "secret.create", secret.ID, req.Path, userID, true, "")

	writeJSON(w, http.StatusCreated, SecretResponse{
		ID:        secret.ID,
		Path:      secret.Path,
		Metadata:  secret.Metadata,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt,
		CreatedBy: secret.CreatedBy,
		UpdatedAt: secret.UpdatedAt,
		UpdatedBy: secret.UpdatedBy,
	})
}

// handleUpdateSecret updates an existing secret
func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract path from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "secret path is required")
		return
	}

	var req UpdateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get existing secret
	secret, err := s.storage.GetSecret(ctx, path)
	if err != nil {
		s.logAuditEvent(r, "secret.update", "", path, userID, false, err.Error())
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}

	// Update value if provided
	if req.Value != "" {
		encryptedValue, err := s.keyring.EncryptAES([]byte(req.Value))
		if err != nil {
			s.logAuditEvent(r, "secret.update", secret.ID, path, userID, false, "encryption failed")
			writeError(w, http.StatusInternalServerError, "failed to encrypt secret")
			return
		}
		secret.Value = encryptedValue
	}

	// Update metadata if provided
	if req.Metadata != nil {
		secret.Metadata = req.Metadata
	}

	secret.UpdatedBy = userID

	if err := s.storage.UpdateSecret(ctx, secret); err != nil {
		s.logAuditEvent(r, "secret.update", secret.ID, path, userID, false, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to update secret")
		return
	}

	// Create new version
	version := &storage.SecretVersion{
		ID:        uuid.New().String(),
		SecretID:  secret.ID,
		Version:   secret.Version,
		Value:     secret.Value,
		CreatedAt: secret.UpdatedAt,
		CreatedBy: userID,
	}
	_ = s.storage.CreateSecretVersion(ctx, version)

	s.logAuditEvent(r, "secret.update", secret.ID, path, userID, true, "")

	writeJSON(w, http.StatusOK, SecretResponse{
		ID:        secret.ID,
		Path:      secret.Path,
		Metadata:  secret.Metadata,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt,
		CreatedBy: secret.CreatedBy,
		UpdatedAt: secret.UpdatedAt,
		UpdatedBy: secret.UpdatedBy,
	})
}

// handleDeleteSecret soft-deletes a secret
func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract path from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "secret path is required")
		return
	}

	// Get the secret first to log its ID
	secret, err := s.storage.GetSecret(ctx, path)
	if err != nil {
		s.logAuditEvent(r, "secret.delete", "", path, userID, false, err.Error())
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}

	if err := s.storage.DeleteSecret(ctx, path); err != nil {
		s.logAuditEvent(r, "secret.delete", secret.ID, path, userID, false, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}

	s.logAuditEvent(r, "secret.delete", secret.ID, path, userID, true, "")

	w.WriteHeader(http.StatusNoContent)
}

// handleVersions retrieves version history for a secret
func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract path from URL: /api/v1/secrets/{path}/versions
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	path = strings.TrimSuffix(path, "/versions")
	if path == "" {
		writeError(w, http.StatusBadRequest, "secret path is required")
		return
	}

	// Get the secret to get its ID
	secret, err := s.storage.GetSecret(ctx, path)
	if err != nil {
		s.logAuditEvent(r, "secret.versions", "", path, userID, false, err.Error())
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}

	versions, err := s.storage.GetSecretVersions(ctx, secret.ID)
	if err != nil {
		s.logAuditEvent(r, "secret.versions", secret.ID, path, userID, false, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to get versions")
		return
	}

	s.logAuditEvent(r, "secret.versions", secret.ID, path, userID, true, "")

	items := make([]VersionResponse, 0, len(versions))
	for _, v := range versions {
		items = append(items, VersionResponse{
			ID:        v.ID,
			SecretID:  v.SecretID,
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		})
	}

	writeJSON(w, http.StatusOK, VersionListResponse{
		Versions: items,
		Total:    len(items),
	})
}

// handleAuditLogs retrieves audit logs (admin only)
func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	role, _ := ctx.Value(contextKeyRole).(string)
	if role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	// Parse query parameters
	filter := storage.AuditFilter{}

	if user := r.URL.Query().Get("user"); user != "" {
		filter.User = user
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = action
	}

	if secretPath := r.URL.Query().Get("secret_path"); secretPath != "" {
		filter.SecretPath = secretPath
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = &t
		}
	}

	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = &t
		}
	}

	s.logAuditEvent(r, "audit.list", "", "", userID, true, "")

	logs, err := s.storage.GetAuditLogs(ctx, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get audit logs")
		return
	}

	items := make([]AuditLogResponse, 0, len(logs))
	for _, log := range logs {
		items = append(items, AuditLogResponse{
			ID:         log.ID,
			Timestamp:  log.Timestamp,
			Action:     log.Action,
			User:       log.User,
			SecretID:   log.SecretID,
			SecretPath: log.SecretPath,
			IPAddress:  log.IPAddress,
			UserAgent:  log.UserAgent,
			Success:    log.Success,
			Error:      log.Error,
			Metadata:   log.Metadata,
		})
	}

	writeJSON(w, http.StatusOK, AuditLogListResponse{
		Logs:  items,
		Total: len(items),
	})
}

// handleAPIKeys handles API key management
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListAPIKeys(w, r)
	case http.MethodPost:
		s.handleCreateAPIKey(w, r)
	case http.MethodDelete:
		s.handleRevokeAPIKey(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleListAPIKeys lists all API keys for the authenticated user
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keys := s.apiKeyStore.ListKeys(userID)

	items := make([]APIKeyResponse, 0, len(keys))
	for _, key := range keys {
		items = append(items, APIKeyResponse{
			ID:        key.ID,
			Name:      key.Name,
			Prefix:    key.Prefix,
			CreatedAt: key.CreatedAt,
			ExpiresAt: key.ExpiresAt,
			LastUsed:  key.LastUsed,
		})
	}

	writeJSON(w, http.StatusOK, APIKeyListResponse{
		Keys:  items,
		Total: len(items),
	})
}

// handleCreateAPIKey creates a new API key
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	role, _ := ctx.Value(contextKeyRole).(string)

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(req.ExpiresIn)
		expiresAt = &t
	}

	key, rawKey, err := s.apiKeyStore.CreateKey(userID, role, req.Name, expiresAt)
	if err != nil {
		s.logAuditEvent(r, "apikey.create", "", "", userID, false, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	s.logAuditEvent(r, "apikey.create", key.ID, "", userID, true, "")

	writeJSON(w, http.StatusCreated, CreateAPIKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Key:       rawKey, // Only returned once at creation
		Prefix:    key.Prefix,
		CreatedAt: key.CreatedAt,
		ExpiresAt: key.ExpiresAt,
	})
}

// handleRevokeAPIKey revokes an API key
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keyID := r.URL.Query().Get("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "key id is required")
		return
	}

	if err := s.apiKeyStore.RevokeKey(keyID, userID); err != nil {
		s.logAuditEvent(r, "apikey.revoke", keyID, "", userID, false, err.Error())
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not authorized") {
			writeError(w, http.StatusNotFound, "API key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to revoke API key")
		return
	}

	s.logAuditEvent(r, "apikey.revoke", keyID, "", userID, true, "")

	w.WriteHeader(http.StatusNoContent)
}

// handleLogin handles user authentication
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Verify credentials (simplified - in production, use proper password hashing)
	user, ok := s.users[req.Username]
	if !ok || user.Password != req.Password {
		s.logAuditEvent(r, "auth.login", "", "", req.Username, false, "invalid credentials")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate JWT token
	token, expiresAt, err := s.jwtManager.GenerateToken(user.ID, user.Role)
	if err != nil {
		s.logAuditEvent(r, "auth.login", "", "", req.Username, false, "token generation failed")
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	s.logAuditEvent(r, "auth.login", "", "", req.Username, true, "")

	writeJSON(w, http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User: UserResponse{
			ID:   user.ID,
			Name: user.Name,
			Role: user.Role,
		},
	})
}

// handleRefreshToken refreshes an authentication token
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()
	userID, ok := ctx.Value(contextKeyUserID).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	role, _ := ctx.Value(contextKeyRole).(string)

	token, expiresAt, err := s.jwtManager.GenerateToken(userID, role)
	if err != nil {
		s.logAuditEvent(r, "auth.refresh", "", "", userID, false, "token generation failed")
		writeError(w, http.StatusInternalServerError, "failed to refresh token")
		return
	}

	s.logAuditEvent(r, "auth.refresh", "", "", userID, true, "")

	writeJSON(w, http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	})
}

// logAuditEvent creates an audit log entry
func (s *Server) logAuditEvent(r *http.Request, action, secretID, secretPath, userID string, success bool, errMsg string) {
	ctx := r.Context()

	// Sign the audit log entry
	logData := action + userID + secretPath + time.Now().Format(time.RFC3339)
	signature, _ := s.keyring.SignString(logData)

	log := &storage.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		Action:     action,
		User:       userID,
		SecretID:   secretID,
		SecretPath: secretPath,
		IPAddress:  getClientIP(r),
		UserAgent:  r.UserAgent(),
		Success:    success,
		Error:      errMsg,
		Metadata:   make(map[string]string),
		Signature:  signature,
	}

	_ = s.storage.CreateAuditLog(ctx, log)
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}
