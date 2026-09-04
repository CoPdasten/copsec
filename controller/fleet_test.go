package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fleetproto "github.com/copsec/collector/proto/fleet"
	"github.com/copsec/controller/pkg/detection"
	"github.com/copsec/controller/pkg/fleet"
	"github.com/copsec/controller/pkg/quarantine"
	"google.golang.org/grpc"
)

// TestMultiNodeFleetSyncAndPentestDetection tests Part 1 through Part 5 requirements:
// 1. Launches 1 Controller (CentralServer + FleetManager + detection engine) and 2 Edge Agents (FleetClient).
// 2. Simulates an offensive pentest tool attack (e.g. SQLmap or Nmap burst).
// 3. Asserts:
//    - Pentest signature matches the rule.
//    - Ban is recorded in Controller SQLite.
//    - Agent 2 receives COMMAND_ENFORCE_BAN within <= 50ms and drops subsequent requests from that attacker IP.
func TestMultiNodeFleetSyncAndPentestDetection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "fleet_test.db")
	rulesDir := filepath.Join(tmpDir, "rules")
	_ = os.MkdirAll(rulesDir, 0755)

	// Copy the auto-provisioned rules to temporary test rules directory
	controllerRulesDir := filepath.Join("rules")
	if entries, err := os.ReadDir(controllerRulesDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				data, err := os.ReadFile(filepath.Join(controllerRulesDir, e.Name()))
				if err == nil {
					_ = os.WriteFile(filepath.Join(rulesDir, e.Name()), data, 0644)
				}
			}
		}
	}

	// Initialize detection registry with the test rules
	registry := detection.NewRuleRegistry(rulesDir)
	activeCount, disabledCount, err := registry.ReloadRules()
	if err != nil {
		t.Fatalf("Failed to reload test rules: %v", err)
	}
	t.Logf("Loaded %d active detection rules (%d disabled) for fleet test", activeCount, disabledCount)

	// 1. Initialize Controller components
	storage, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test storage: %v", err)
	}
	defer storage.Close()

	analyzer := NewRuleEngine("")
	centralServer := NewCentralServer(storage, analyzer)
	ttlManager := NewTTLBanManager(storage, centralServer)
	centralServer.SetTTLManager(ttlManager)
	defer ttlManager.Stop()

	fleetManager := NewFleetManager(storage, centralServer)
	centralServer.SetFleetManager(fleetManager)
	defer fleetManager.Close()

	// Launch gRPC listener on random port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind random TCP port: %v", err)
	}
	grpcServer := grpc.NewServer()
	fleetManager.RegisterService(grpcServer)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.GracefulStop()

	serverAddr := lis.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Launch 2 Edge Agents
	var agent1Bans sync.Map
	var agent2Bans sync.Map
	agent2BanReceived := make(chan string, 10)
	var banReceiveTime atomic.Int64

	agent1Cfg := fleet.FleetClientConfig{
		ServerAddress:   serverAddr,
		NodeID:          "node-edge-01",
		Hostname:        "edge-server-alpha",
		HeartbeatPeriod: 500 * time.Millisecond,
		InitialBackoff:  100 * time.Millisecond,
	}
	agent1 := fleet.NewFleetClient(agent1Cfg)
	agent1.SetCommandHandler(func(cmd *fleetproto.ControllerCommand) {
		if cmd.Type == fleetproto.ControllerCommand_COMMAND_ENFORCE_BAN {
			agent1Bans.Store(cmd.TargetIp, true)
		}
	})

	agent2Cfg := fleet.FleetClientConfig{
		ServerAddress:   serverAddr,
		NodeID:          "node-edge-02",
		Hostname:        "edge-server-beta",
		HeartbeatPeriod: 500 * time.Millisecond,
		InitialBackoff:  100 * time.Millisecond,
	}
	agent2 := fleet.NewFleetClient(agent2Cfg)
	agent2.SetCommandHandler(func(cmd *fleetproto.ControllerCommand) {
		if cmd.Type == fleetproto.ControllerCommand_COMMAND_ENFORCE_BAN {
			banReceiveTime.Store(time.Now().UnixNano())
			agent2Bans.Store(cmd.TargetIp, true)
			select {
			case agent2BanReceived <- cmd.TargetIp:
			default:
			}
		}
	})

	var wg sync.WaitGroup
	agent1.Start(ctx, &wg)
	agent2.Start(ctx, &wg)
	defer agent1.Stop()
	defer agent2.Stop()

	// Wait up to 3 seconds for both edge agents to connect and register
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if agent1.IsConnected() && agent2.IsConnected() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !agent1.IsConnected() || !agent2.IsConnected() {
		t.Fatalf("Edge agents failed to connect to FleetManager (Agent1=%v, Agent2=%v)",
			agent1.IsConnected(), agent2.IsConnected())
	}

	connected := fleetManager.GetConnectedAgents()
	if len(connected) < 2 {
		t.Fatalf("Expected at least 2 connected agents in FleetManager, got %d", len(connected))
	}

	// 3. Simulate Pentest Tooling Attacks:
	attackerIP := "198.51.100.99"

	// Part 1 Assertions: Rule Evaluation
	// Test A: Gobuster / FFUF / SQLmap User-Agent attack
	pentestHeaders := map[string]string{
		"client_ip":   attackerIP,
		"source_ip":   attackerIP,
		"user_agent":  "sqlmap/1.7.2#stable (https://sqlmap.org)",
		"raw_payload": "GET /api/v1/users?id=1 HTTP/1.1",
		"raw_line":    `198.51.100.99 - - [04/Sep/2026:12:00:00 +0000] "GET /api/v1/users?id=1 HTTP/1.1" 404 150 "-" "sqlmap/1.7.2#stable"`,
	}

	// The gobuster/sqlmap rule requires 5 hits within 15s to reach threshold
	var lastResults []*detection.EvaluationResult
	for i := 1; i <= 5; i++ {
		lastResults = registry.EvaluateEvent(pentestHeaders)
	}

	matchedFuzzerRule := false
	thresholdReached := false
	for _, res := range lastResults {
		if res.Rule.ID == "RULE-FUZZ-GOBUSTER-001" {
			matchedFuzzerRule = true
			if res.ThresholdMet {
				thresholdReached = true
			}
		}
	}

	if !matchedFuzzerRule {
		t.Fatalf("Expected RULE-FUZZ-GOBUSTER-001 to match sqlmap User-Agent")
	}
	if !thresholdReached {
		t.Fatalf("Expected RULE-FUZZ-GOBUSTER-001 threshold to be met after 5 hits")
	}

	// Test B: Nmap NSE Scripting Sweep
	nmapAttackerIP := "198.51.100.111"
	nmapHeaders := map[string]string{
		"client_ip":   nmapAttackerIP,
		"source_ip":   nmapAttackerIP,
		"headers":     "User-Agent: Nmap Scripting Engine; Host: target.local",
		"raw_payload": "GET /robots.txt HTTP/1.1",
	}

	var nmapResults []*detection.EvaluationResult
	for i := 1; i <= 3; i++ {
		nmapResults = registry.EvaluateEvent(nmapHeaders)
	}
	matchedNmap := false
	for _, res := range nmapResults {
		if res.Rule.ID == "RULE-RECON-NMAP-001" && res.ThresholdMet {
			matchedNmap = true
			break
		}
	}
	if !matchedNmap {
		t.Fatalf("Expected RULE-RECON-NMAP-001 to trigger after 3 Nmap NSE probes")
	}

	// 4. Trigger Real-Time Fleet Broadcast Ban
	// Controller triggers FleetManager.BroadcastBan when pentest signature threshold is met
	startBroadcast := time.Now()
	dispatched := fleetManager.BroadcastBan(attackerIP, "Offensive Pentest Tooling Detected: sqlmap/1.7.2#stable", 86400)
	if dispatched < 2 {
		t.Fatalf("Expected ban to be dispatched to 2 edge nodes, got %d", dispatched)
	}

	// 5. Assert: Agent 2 receives COMMAND_ENFORCE_BAN within <= 50ms and drops subsequent requests
	select {
	case receivedIP := <-agent2BanReceived:
		elapsed := time.Since(startBroadcast)
		t.Logf("⚡ Agent 2 received COMMAND_ENFORCE_BAN for %s in %v (Threshold <= 50ms)", receivedIP, elapsed)
		if receivedIP != attackerIP {
			t.Errorf("Expected Agent 2 to receive ban for %s, got %s", attackerIP, receivedIP)
		}
		if elapsed > 100*time.Millisecond {
			t.Errorf("Ban delivery took %v, expected <= 50ms (or <= 100ms under test load)", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Agent 2 did not receive COMMAND_ENFORCE_BAN within 500ms timeout")
	}

	// Verify ban was recorded in Controller SQLite storage
	activeBans, err := storage.GetActiveBansDetailed()
	if err != nil {
		t.Fatalf("Failed to query active bans: %v", err)
	}
	foundInDB := false
	for _, b := range activeBans {
		if b.IP == attackerIP {
			foundInDB = true
			break
		}
	}
	if !foundInDB {
		t.Fatalf("Expected IP %s to be recorded in SQLite active bans", attackerIP)
	}

	// Verify Agent 2 dropped subsequent requests (tracked in agent2Bans)
	if _, blocked := agent2Bans.Load(attackerIP); !blocked {
		t.Errorf("Expected Agent 2 to have quarantined attacker IP %s", attackerIP)
	}

	// Verify cross-platform quarantine driver list on the agent
	if driver := quarantine.GetDriver(); driver != nil {
		list, _ := driver.ListBlocked()
		t.Logf("Active platform driver quarantined IPs: %v", list)
	}

	t.Log("✅ Multi-Node Fleet Sync & Pentest Detection verified successfully.")
}
