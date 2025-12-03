package server

import (
	"context"
	"net/http"
	"strings"
)

// requireAuth is a middleware that requires authentication via JWT or API key
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userID, role string
		var authenticated bool

		// Check for Bearer token in Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := s.jwtManager.ValidateToken(token)
			if err == nil {
				userID = claims.UserID
				role = claims.Role
				authenticated = true
			}
		}

		// If not authenticated via JWT, try API key
		if !authenticated {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				// Also check query parameter for API key
				apiKey = r.URL.Query().Get("api_key")
			}

			if apiKey != "" {
				key, err := s.apiKeyStore.ValidateKey(apiKey)
				if err == nil {
					userID = key.UserID
					role = key.Role
					authenticated = true
				}
			}
		}

		if !authenticated {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		ctx = context.WithValue(ctx, contextKeyRole, role)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
