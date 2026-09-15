package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/copsec/pkg/rules"
)

func createTestServer(t *testing.T) (*rules.RuleManager, *WebServer) {
	t.Helper()
	rm, err := rules.NewRuleManager("", "")
	if err != nil {
		t.Fatalf("Failed to initialize RuleManager: %v", err)
	}

	ws := NewWebServer(&ServerConfig{ListenAddr: ":0"}, rm)
	return rm, ws
}

func TestWebServer_Status(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	_ = rm.BlockCIDR("192.0.2.0/24", "Test block")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	ws.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", w.Code)
	}

	var status map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if status["status"] != "operational" {
		t.Errorf("Expected status operational, got %v", status["status"])
	}
	if status["lpm_blocks"] != float64(1) {
		t.Errorf("Expected 1 lpm_block, got %v", status["lpm_blocks"])
	}
}

func TestWebServer_Blocks_CRUD(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	// 1. Initial GET -> empty
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/blocks", nil)
	wGet := httptest.NewRecorder()
	ws.mux.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", wGet.Code)
	}

	// 2. POST /api/v1/blocks -> Add prefix
	postPayload := []byte(`{"cidr":"198.51.100.0/24","description":"Malicious range"}`)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/v1/blocks", bytes.NewReader(postPayload))
	wPost := httptest.NewRecorder()
	ws.mux.ServeHTTP(wPost, reqPost)

	if wPost.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d: %s", wPost.Code, wPost.Body.String())
	}

	// 3. Verify prefix present
	wGet2 := httptest.NewRecorder()
	ws.mux.ServeHTTP(wGet2, reqGet)
	var blocks []rules.BlockEntry
	if err := json.Unmarshal(wGet2.Body.Bytes(), &blocks); err != nil {
		t.Fatalf("Failed to unmarshal blocks: %v", err)
	}
	if len(blocks) != 1 || blocks[0].CIDR != "198.51.100.0/24" {
		t.Errorf("Unexpected blocks response: %v", blocks)
	}

	// 4. DELETE /api/v1/blocks
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/blocks?cidr=198.51.100.0/24", nil)
	wDel := httptest.NewRecorder()
	ws.mux.ServeHTTP(wDel, reqDel)

	if wDel.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on delete, got %d", wDel.Code)
	}

	// 5. Verify evicted
	wGet3 := httptest.NewRecorder()
	ws.mux.ServeHTTP(wGet3, reqGet)
	var blocksAfter []rules.BlockEntry
	_ = json.Unmarshal(wGet3.Body.Bytes(), &blocksAfter)
	if len(blocksAfter) != 0 {
		t.Errorf("Expected 0 blocks after delete, got %d", len(blocksAfter))
	}
}

func TestWebServer_Healthz(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	ws.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestWebServer_Dashboard(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	_ = rm.BlockCIDR("203.0.113.5/32", "Attacker host")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ws.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on dashboard, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "CoPSeC Open-Core Security Cockpit") {
		t.Errorf("Dashboard missing title")
	}
	if !strings.Contains(body, "203.0.113.5/32") {
		t.Errorf("Dashboard missing blocked CIDR prefix")
	}
}

func TestWebServer_Metrics(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	ws.UpdateMetrics(15, 85000)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	w := httptest.NewRecorder()
	ws.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on metrics, got %d", w.Code)
	}

	metricsText := w.Body.String()
	if !strings.Contains(metricsText, "copsec_active_bans 15") {
		t.Errorf("Expected copsec_active_bans 15 in metrics, got:\n%s", metricsText)
	}
	if !strings.Contains(metricsText, "copsec_events_per_second 85000") {
		t.Errorf("Expected copsec_events_per_second 85000 in metrics, got:\n%s", metricsText)
	}
}

func TestWebServer_GracefulShutdown(t *testing.T) {
	rm, ws := createTestServer(t)
	defer rm.Close()

	ws.cfg.ListenAddr = "127.0.0.1:0"
	if err := ws.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := ws.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}
