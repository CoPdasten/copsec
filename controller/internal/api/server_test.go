package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/copsec/controller/internal/storage"
)

func TestCockpitHandlerEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_vault.db")

	store, err := storage.NewSecurityStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create SecurityStorage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Seed audit trail & fleet agent
	_, err = store.RecordAuditEntry(ctx, storage.AuditEntry{
		ActorIdentity: "SOC_L2_EFE",
		ActorIP:       "192.168.1.11",
		ActionType:    "MANUAL_UNBAN",
		TargetEntity:  "192.168.1.12",
		Justification: "Test validation complete",
	})
	if err != nil {
		t.Fatalf("failed to record audit entry: %v", err)
	}

	err = store.UpsertAgentHeartbeat(ctx, storage.AgentTelemetry{
		NodeID:              "chachy",
		NodeGroup:           "DMZ_INGRESS",
		IPAddress:           "192.168.1.10",
		ActiveInterface:     "wlan0",
		XDPStatus:           "ACTIVE",
		LastSeenMs:          time.Now().UnixMilli(),
		CPUUsagePct:         14.2,
		MemoryUsageMB:       256.0,
		TotalPacketsDropped: 55000,
	})
	if err != nil {
		t.Fatalf("failed to upsert agent heartbeat: %v", err)
	}

	handler := NewCockpitHandler(store, tempDir, "test_api_key")

	// 2. Test GET /api/fleet
	reqFleet := httptest.NewRequest(http.MethodGet, "/api/fleet", nil)
	rrFleet := httptest.NewRecorder()
	handler.ServeHTTP(rrFleet, reqFleet)

	if rrFleet.Code != http.StatusOK {
		t.Fatalf("GET /api/fleet returned HTTP %d: %s", rrFleet.Code, rrFleet.Body.String())
	}
	if !contains(rrFleet.Body.String(), "chachy") || !contains(rrFleet.Body.String(), "DMZ_INGRESS") {
		t.Fatalf("GET /api/fleet output missing chachy node: %s", rrFleet.Body.String())
	}

	// 3. Test GET /api/audit/report/pdf unauthenticated (expect 401)
	reqPDFUnauth := httptest.NewRequest(http.MethodGet, "/api/audit/report/pdf", nil)
	rrPDFUnauth := httptest.NewRecorder()
	handler.ServeHTTP(rrPDFUnauth, reqPDFUnauth)

	if rrPDFUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing API key, got %d", rrPDFUnauth.Code)
	}

	// 4. Test GET /api/audit/report/pdf authenticated (expect 200 and %PDF-)
	reqPDFAuth := httptest.NewRequest(http.MethodGet, "/api/audit/report/pdf", nil)
	reqPDFAuth.Header.Set("X-API-Key", "test_api_key")
	rrPDFAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrPDFAuth, reqPDFAuth)

	if rrPDFAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authenticated PDF export, got %d: %s", rrPDFAuth.Code, rrPDFAuth.Body.String())
	}

	contentType := rrPDFAuth.Header().Get("Content-Type")
	if contentType != "application/pdf" {
		t.Errorf("expected Content-Type application/pdf, got %s", contentType)
	}

	disp := rrPDFAuth.Header().Get("Content-Disposition")
	if !contains(disp, "attachment") || !contains(disp, "CoPSeC_Compliance_Audit_") || !contains(disp, ".pdf") {
		t.Errorf("unexpected Content-Disposition header: %s", disp)
	}

	body := rrPDFAuth.Body.Bytes()
	if len(body) < 5 || string(body[:5]) != "%PDF-" {
		t.Fatalf("expected %%PDF- header, got: %s", string(body[:min(10, len(body))]))
	}

	t.Logf("GET /api/audit/report/pdf successfully generated %d bytes PDF with %%PDF- magic header", len(body))
}

func contains(s, substr string) bool {
	return filepath.Clean(s) != "" && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || len(substr) > 0 && len(s) > 0 && (substr == s || len(substr) < len(s) && (s[len(s)-len(substr):] == substr || (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()))))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
