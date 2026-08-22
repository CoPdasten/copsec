package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc/metadata"
)

func TestRuleEngineAnalysis(t *testing.T) {
	engine := NewRuleEngine("") // Load built-ins

	// 1. SQL Injection attempt
	sqli := `198.51.100.1 - - [22/Aug/2026:12:00:00 +0300] "GET /login?user=admin%27%20or%201=1-- HTTP/1.1" 403`
	ruleID, techID, score, matched := engine.Analyze(sqli, 403, "nginx")
	if !matched || techID != "T1190" || score < 70 {
		t.Errorf("Expected SQLi match T1190 (score>=70), got: match=%v, rule=%s, tech=%s, score=%d",
			matched, ruleID, techID, score)
	}

	// 2. Command Injection / RCE
	rce := `203.0.113.50 - - [22/Aug/2026:12:00:00 +0300] "GET /cgi-bin/test?cmd=%3B%20id HTTP/1.1" 500`
	ruleID, techID, score, matched = engine.Analyze(rce, 500, "nginx")
	if !matched || techID != "T1059.004" || score < 80 {
		t.Errorf("Expected RCE match T1059.004, got: match=%v, rule=%s, tech=%s, score=%d",
			matched, ruleID, techID, score)
	}

	// 3. Status code filtering: 200 OK should not match when restricted to error codes
	normal := `127.0.0.1 - - [22/Aug/2026:12:00:00 +0300] "GET /index.html HTTP/1.1" 200`
	_, _, _, matched = engine.Analyze(normal, 200, "nginx")
	if matched {
		t.Errorf("Expected normal 200 OK traffic to not match, but matched")
	}
}

func TestStorageEngine(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_controller.db")

	store, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	ev := &StoredEvent{
		NodeID:           "node-vps-1",
		Source:           "nginx",
		RawLine:          `GET /admin HTTP/1.1 404`,
		ClientIP:         "198.51.100.25",
		StatusCode:       404,
		TimestampMs:      time.Now().UnixMilli(),
		RuleID:           "nginx-web-scan",
		MitreTechniqueID: "T1595.002",
		ThreatScore:      45,
	}

	if err := store.InsertEvent(ev); err != nil {
		t.Fatalf("InsertEvent failed: %v", err)
	}

	events, err := store.GetRecentEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d (err: %v)", len(events), err)
	}
	if events[0].ClientIP != "198.51.100.25" {
		t.Errorf("ClientIP mismatch: %s", events[0].ClientIP)
	}

	stats, err := store.GetMITREStats()
	if err != nil || len(stats) != 1 {
		t.Fatalf("Expected 1 mitre stat, got %d", len(stats))
	}
	if stats[0].TechniqueID != "T1595.002" || stats[0].Count != 1 {
		t.Errorf("MITRE stat mismatch: %+v", stats[0])
	}
}

func TestCentralServerAuthAndHeartbeat(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-node-id", "node-vps-test",
		"x-api-key", "cps_live_secret123",
	))

	hb := &copsecproto.Heartbeat{
		NodeId:          "node-vps-test",
		UptimeSeconds:   3600,
		CpuUsage:        1.5,
		MemoryUsage:     12.0,
		ActiveBansCount: 2,
	}

	resp, err := server.SendHeartbeat(ctx, hb)
	if err != nil || !resp.Acknowledged {
		t.Fatalf("SendHeartbeat failed: %v", err)
	}

	nodes := server.GetNodesSnapshot()
	if len(nodes) != 1 || nodes[0].NodeID != "node-vps-test" {
		t.Errorf("Expected registered node in snapshot, got %v", nodes)
	}

	dispatched := server.BroadcastSOARCommand("BAN_IP", "203.0.113.99", 86400)
	if dispatched != 1 {
		t.Errorf("Expected 1 dispatched command, got %d", dispatched)
	}
}
