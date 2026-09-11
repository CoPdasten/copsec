package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFleetAgentsStorage(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_copsec.db")

	store, err := NewSecurityStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create SecurityStorage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Test UpsertAgentHeartbeat for node chachy
	now := time.Now().UnixMilli()
	agent1 := AgentTelemetry{
		NodeID:              "chachy",
		NodeGroup:           "DMZ_INGRESS",
		IPAddress:           "192.168.1.10",
		ActiveInterface:     "wlan0",
		XDPStatus:           "ACTIVE",
		LastSeenMs:          now,
		CPUUsagePct:         15.4,
		MemoryUsageMB:       128.5,
		TotalPacketsDropped: 42000,
	}

	if err := store.UpsertAgentHeartbeat(ctx, agent1); err != nil {
		t.Fatalf("UpsertAgentHeartbeat failed: %v", err)
	}

	// 2. Test GetFleetStatus returns active node
	fleet, err := store.GetFleetStatus(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("GetFleetStatus failed: %v", err)
	}
	if len(fleet) != 1 {
		t.Fatalf("expected 1 agent in fleet, got %d", len(fleet))
	}
	if fleet[0].NodeID != "chachy" || fleet[0].XDPStatus != "ACTIVE" {
		t.Fatalf("unexpected agent telemetry: %+v", fleet[0])
	}
	if fleet[0].TotalPacketsDropped != 42000 {
		t.Fatalf("expected 42000 drops, got %d", fleet[0].TotalPacketsDropped)
	}

	// 3. Test Upsert update on conflict
	agent1.TotalPacketsDropped = 50000
	agent1.CPUUsagePct = 25.0
	if err := store.UpsertAgentHeartbeat(ctx, agent1); err != nil {
		t.Fatalf("UpsertAgentHeartbeat update failed: %v", err)
	}

	fleet, _ = store.GetFleetStatus(ctx, 30*time.Second)
	if len(fleet) != 1 || fleet[0].TotalPacketsDropped != 50000 {
		t.Fatalf("expected updated drops 50000, got %+v", fleet[0])
	}

	// 4. Test Dynamic OFFLINE flag for stale node (> 30s)
	staleAgent := AgentTelemetry{
		NodeID:              "stale-node-02",
		NodeGroup:           "EDGE_FLEET",
		IPAddress:           "192.168.1.99",
		ActiveInterface:     "eth0",
		XDPStatus:           "ACTIVE",
		LastSeenMs:          now - 45000, // 45s ago
		CPUUsagePct:         5.0,
		MemoryUsageMB:       64.0,
		TotalPacketsDropped: 100,
	}
	if err := store.UpsertAgentHeartbeat(ctx, staleAgent); err != nil {
		t.Fatalf("UpsertAgentHeartbeat for stale agent failed: %v", err)
	}

	fleet, _ = store.GetFleetStatus(ctx, 30*time.Second)
	if len(fleet) != 2 {
		t.Fatalf("expected 2 agents in fleet, got %d", len(fleet))
	}

	var foundStale *AgentTelemetry
	for i := range fleet {
		if fleet[i].NodeID == "stale-node-02" {
			foundStale = &fleet[i]
		}
	}
	if foundStale == nil {
		t.Fatal("stale agent not found in fleet")
	}
	if foundStale.XDPStatus != "OFFLINE" {
		t.Fatalf("expected stale agent xdp_status to be dynamically flagged OFFLINE, got %s", foundStale.XDPStatus)
	}
}
