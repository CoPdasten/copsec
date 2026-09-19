package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	testKey := "test-secret-key-1234567890abcdef"
	SetActiveAPIKey(testKey)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	protectedHandler := AuthMiddleware(dummyHandler)

	tests := []struct {
		name           string
		path           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "Valid X-API-Key header",
			path:           "/api/telemetry",
			headers:        map[string]string{"X-API-Key": testKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid Bearer Authorization header",
			path:           "/api/telemetry",
			headers:        map[string]string{"Authorization": "Bearer " + testKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid ?token query parameter on WebSocket route",
			path:           "/ws/telemetry?token=" + testKey,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Token query param blocked on REST /api/* route",
			path:           "/api/telemetry?token=" + testKey,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Missing key on protected route",
			path:           "/api/telemetry",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid key on protected route",
			path:           "/api/telemetry",
			headers:        map[string]string{"X-API-Key": "wrong-key"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Whitelisted root route",
			path:           "/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Whitelisted health route",
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Whitelisted static route",
			path:           "/static/app.js",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Unauthenticated /api/fleet is blocked (F4)",
			path:           "/api/fleet",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Authenticated /api/fleet is permitted (F4)",
			path:           "/api/fleet",
			headers:        map[string]string{"X-API-Key": testKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Unauthenticated /api/pcap/samples is blocked (F4)",
			path:           "/api/pcap/samples",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Authenticated /api/pcap/samples is permitted (F4)",
			path:           "/api/pcap/samples",
			headers:        map[string]string{"X-API-Key": testKey},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			protectedHandler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Fatalf("Path: %s, expected status %d, got %d", tc.path, tc.expectedStatus, rec.Code)
			}
		})
	}
}
