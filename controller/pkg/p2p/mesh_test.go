package p2p

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGossipMeshThreatPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var receivedThreat atomic.Value

	// Peer 1 (Receiver)
	cfg1 := MeshConfig{
		NodeID:         "node-receiver",
		BindAddr:       "127.0.0.1:17946",
		ClusterSecret:  "test-secret-key",
		GossipInterval: 500 * time.Millisecond,
	}
	mesh1 := NewGossipMesh(cfg1, func(tb ThreatBroadcast) {
		receivedThreat.Store(tb)
	}, nil)

	err := mesh1.Start(ctx)
	if err != nil {
		t.Fatalf("mesh1 start failed: %v", err)
	}
	defer mesh1.Close()

	// Peer 2 (Sender)
	cfg2 := MeshConfig{
		NodeID:         "node-sender",
		BindAddr:       "127.0.0.1:17947",
		BootstrapPeers: []string{"127.0.0.1:17946"},
		ClusterSecret:  "test-secret-key",
		GossipInterval: 500 * time.Millisecond,
	}
	mesh2 := NewGossipMesh(cfg2, nil, nil)

	err = mesh2.Start(ctx)
	if err != nil {
		t.Fatalf("mesh2 start failed: %v", err)
	}
	defer mesh2.Close()

	// Broadcast threat from Peer 2
	targetIP := "203.0.113.88"
	mesh2.BroadcastThreat(ThreatBroadcast{
		TargetIP:     targetIP,
		ThreatScore:  95,
		RuleID:       "ssh_brute_force",
		MitreID:      "T1110",
		TTLSeconds:   3600,
		Reason:       "Active automated dictionary attack",
		OriginNodeID: "node-sender",
	})

	// Wait for gossip propagation
	var passed bool
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		val := receivedThreat.Load()
		if val != nil {
			tb := val.(ThreatBroadcast)
			if tb.TargetIP == targetIP {
				passed = true
				break
			}
		}
	}

	if !passed {
		t.Errorf("Threat broadcast was not gossiped to mesh1 within timeout")
	}

	// Verify CRDT Jail in receiver
	if mesh1.GetCRDTJail().Count() != 1 {
		t.Errorf("Expected 1 CRDT ban in mesh1, got %d", mesh1.GetCRDTJail().Count())
	}
}
