package server

import (
	"context"
	"net/http"
	"time"

	"github.com/ConstantineCTF/nexus/internal/auth"
	"github.com/ConstantineCTF/nexus/internal/crypto"
	"github.com/ConstantineCTF/nexus/internal/storage"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	contextKeyUserID contextKey = "userID"
	contextKeyRole   contextKey = "role"
)

// User represents an authenticated user (simplified for now)
type User struct {
	ID       string
	Name     string
	Role     string
	Password string // In production, use proper hashing
}

// Server represents the NEXUS HTTP server
type Server struct {
	storage     storage.Storage
	keyring     *crypto.Keyring
	jwtManager  *auth.JWTManager
	apiKeyStore *auth.APIKeyStore
	users       map[string]*User // username -> user (simplified auth)
	httpServer  *http.Server
}

// Config holds server configuration
type Config struct {
	Address      string
	JWTSecret    []byte
	JWTExpiry    time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewServer creates a new NEXUS server
func NewServer(cfg Config, store storage.Storage, keyring *crypto.Keyring) *Server {
	s := &Server{
		storage:     store,
		keyring:     keyring,
		jwtManager:  auth.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiry),
		apiKeyStore: auth.NewAPIKeyStore(),
		users:       make(map[string]*User),
	}

	// Initialize default admin user (in production, load from config/database)
	s.users["admin"] = &User{
		ID:       "admin-001",
		Name:     "Admin User",
		Role:     "admin",
		Password: "admin", // In production, use proper hashing
	}

	// Set up HTTP server with routes
	mux := http.NewServeMux()

	// Health check (no auth required)
	mux.HandleFunc("/health", s.handleHealth)

	// Authentication endpoints
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/refresh", s.requireAuth(s.handleRefreshToken))

	// Secret endpoints
	mux.HandleFunc("/api/v1/secrets", s.requireAuth(s.handleSecrets))
	mux.HandleFunc("/api/v1/secrets/", s.requireAuth(s.handleSecretRoutes))

	// Audit logs (admin only)
	mux.HandleFunc("/api/v1/audit", s.requireAuth(s.handleAuditLogs))

	// API keys
	mux.HandleFunc("/api/v1/apikeys", s.requireAuth(s.handleAPIKeys))

	s.httpServer = &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

// handleSecretRoutes routes requests to the appropriate handler based on path
func (s *Server) handleSecretRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check if it's a versions request: /api/v1/secrets/{path}/versions
	if len(path) > len("/api/v1/secrets/") {
		suffix := path[len("/api/v1/secrets/"):]
		if len(suffix) > 9 && suffix[len(suffix)-9:] == "/versions" {
			s.handleVersions(w, r)
			return
		}
	}

	// Otherwise, it's a single secret request
	s.handleSecret(w, r)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// AddUser adds a user to the server (for testing/initialization)
func (s *Server) AddUser(username string, user *User) {
	s.users[username] = user
}
