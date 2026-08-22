package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc/metadata"
)

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

	server := NewCentralServer(store)

	// Valid authentication metadata
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

	// Test fleet command broadcast
	dispatched := server.BroadcastSOARCommand("BAN_IP", "203.0.113.99", 86400)
	if dispatched != 1 {
		t.Errorf("Expected 1 dispatched command, got %d", dispatched)
	}
}

func TestTelegramAlertFormat(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	server := NewCentralServer(store)
	bot := NewTelegramSOARBot(TelegramBotConfig{
		BotToken: "dummy_token",
		ChatID:   "123456",
		Enabled:  false, // Keep network disabled for unit test
	}, server)

	evLow := &StoredEvent{
		NodeID:      "vps-1",
		ThreatScore: 10, // Under threshold
	}
	bot.ProcessEvent(evLow) // Should safely ignore without panic

	evHigh := &StoredEvent{
		NodeID:           "vps-1",
		Source:           "nginx",
		RawLine:          "GET /wp-login.php HTTP/1.1",
		ClientIP:         "198.51.100.88",
		MitreTechniqueID: "T1595.002",
		ThreatScore:      60,
		TimestampMs:      time.Now().UnixMilli(),
	}
	bot.ProcessEvent(evHigh)
}
