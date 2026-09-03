package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	globalAPIKey     string
	globalAPIKeyOnce sync.Once
)

// InitAPIKey initializes and returns the active API key.
// Reads COPSEC_API_KEY from the environment.
// If empty, generates a cryptographically secure 32-byte (64 hex char) fallback key,
// logs a prominent security warning, but NEVER fails open.
func InitAPIKey() string {
	globalAPIKeyOnce.Do(func() {
		envKey := strings.TrimSpace(os.Getenv("COPSEC_API_KEY"))
		if envKey != "" {
			globalAPIKey = envKey
			log.Printf("[AUTH] 🔐 COPSEC_API_KEY loaded from environment (length: %d chars)", len(envKey))
		} else {
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				log.Fatalf("[FATAL] 💥 Failed to generate secure fallback API key: %v", err)
			}
			globalAPIKey = hex.EncodeToString(buf)
			log.Printf("================================================================================")
			log.Printf("[SECURITY WARNING] ⚠️  COPSEC_API_KEY environment variable is not configured!")
			log.Printf("[SECURITY WARNING] 🔑 Generated ephemeral 32-byte fallback API key:")
			log.Printf("[SECURITY WARNING]     %s", globalAPIKey)
			log.Printf("[SECURITY WARNING] Set COPSEC_API_KEY in environment/service to persist credentials.")
			log.Printf("================================================================================")
		}
	})
	return globalAPIKey
}

// GetActiveAPIKey returns the initialized API key or initializes it if needed.
func GetActiveAPIKey() string {
	if globalAPIKey == "" {
		return InitAPIKey()
	}
	return globalAPIKey
}

// SetActiveAPIKey allows dynamic override in unit tests.
func SetActiveAPIKey(key string) {
	globalAPIKey = key
}

// AuthErrorResponse represents the standard JSON 401 unauthorized payload.
type AuthErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    int    `json:"code"`
}

// isWhitelistedRoute checks if the incoming path is permitted without authentication.
// Whitelists only static assets (e.g. /, /index.html, /static/*, /favicon.ico, CSS/JS) and health probes (/health).
func isWhitelistedRoute(path string) bool {
	// Exact matches for root, health, and favicon
	if path == "/" || path == "/index.html" || path == "/favicon.ico" || path == "/health" {
		return true
	}

	// Static asset directories
	if strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/assets/") {
		return true
	}

	// File extension check for embedded static assets (e.g., .css, .js, .png, .svg, .woff2, .ico, .html)
	// Make sure we do NOT accidentally whitelist /api/* or /ws/* or /soar/* even if they contain dots
	if !strings.HasPrefix(path, "/api/") &&
		!strings.HasPrefix(path, "/ws/") &&
		!strings.HasPrefix(path, "/soar/") &&
		!strings.HasPrefix(path, "/admin/") {
		if strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ico") ||
			strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".woff") ||
			strings.HasSuffix(path, ".woff2") ||
			strings.HasSuffix(path, ".ttf") ||
			strings.HasSuffix(path, ".html") {
			return true
		}
	}

	return false
}

// extractToken extracts credentials according to priority:
// 1. X-API-Key header
// 2. Authorization: Bearer <token> header
// 3. ?token= query parameter (strictly reserved for /ws/* WebSocket upgrade routes)
func extractToken(r *http.Request) string {
	// 1. Check X-API-Key header
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}

	// 2. Check Authorization: Bearer <token>
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if token := strings.TrimSpace(parts[1]); token != "" {
				return token
			}
		}
	}

	// 3. Check ?token= query parameter strictly reserved for WebSocket endpoints (/ws/*)
	if strings.HasPrefix(r.URL.Path, "/ws/") || r.URL.Path == "/ws" {
		if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
			return token
		}
	}

	return ""
}

// AuthMiddleware creates an HTTP middleware verifying API keys with constant-time comparison.
func AuthMiddleware(next http.Handler) http.Handler {
	activeKey := GetActiveAPIKey()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)

		// 1. Explicitly Block Direct SQLite Database and SQL Dump Files (.db, .db-wal, .db-shm, .sqlite, .sql)
		if strings.HasSuffix(path, ".db") ||
			strings.HasSuffix(path, ".db-wal") ||
			strings.HasSuffix(path, ".db-shm") ||
			strings.HasSuffix(path, ".sqlite") ||
			strings.HasSuffix(path, ".sqlite3") ||
			strings.HasSuffix(path, ".sql") ||
			strings.Contains(path, "copsec.db") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: direct database access is blocked"}`))
			return
		}

		// Route whitelisting
		if isWhitelistedRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract credential token
		token := extractToken(r)
		if token == "" {
			writeUnauthorized(w, "Authentication required: missing API key credentials")
			return
		}

		// Constant-time comparison to mitigate timing attacks
		expectedKey := GetActiveAPIKey()
		if expectedKey == "" {
			expectedKey = activeKey
		}

		tokenBytes := []byte(token)
		expectedBytes := []byte(expectedKey)

		match := subtle.ConstantTimeCompare(tokenBytes, expectedBytes)
		if match != 1 {
			writeUnauthorized(w, "Authentication failed: invalid API key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("WWW-Authenticate", `Bearer realm="CoPSeC SOC Control Plane"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(AuthErrorResponse{
		Success: false,
		Error:   message,
		Code:    http.StatusUnauthorized,
	})
}
