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

	// 4. Noisy log filtering
	noisy := `tailscaled[1234]: magicsock: periodic endpoints update`
	if !IsNoisyLog(noisy) {
		t.Errorf("Expected tailscaled log to be flagged as noisy")
	}

	// 5. Shannon Entropy Calculation
	highEntropy := `/?data=V2hhdCBpZiB5b3UgY2FuIGRvIGV2ZXJ5dGhpbmcgdG8gcGFzcwordGhlIGZpbHRlcg==`
	entropy := CalculateShannonEntropy(highEntropy)
	if entropy < 4.0 {
		t.Errorf("Expected entropy > 4.0 for base64 string, got: %f", entropy)
	}

	name, tactic := engine.GetTechniqueMeta("T1190")
	if name == "" || tactic == "" {
		t.Errorf("Expected technique meta for T1190, got: name=%s, tactic=%s", name, tactic)
	}
}

func TestAIEngineLocalHeuristic(t *testing.T) {
	ai := NewAIEngine()

	evSQLi := &StoredEvent{
		Source:           "nginx",
		RawLine:          "GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1",
		ClientIP:         "198.51.100.99",
		MitreTechniqueID: "T1190",
		ThreatScore:      85,
	}

	intel := ai.AnalyzeIntent(context.Background(), evSQLi)
	if intel.AttackerIntent == "" || intel.Mitigation == "" || intel.ConfidenceScore < 70 {
		t.Errorf("Expected valid AI Threat Intel, got: %+v", intel)
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

	// Threat hunting search test
	searchResults, err := store.SearchEvents("ip:198.51.100.25 mitre:T1595", 10)
	if err != nil || len(searchResults) != 1 {
		t.Fatalf("Expected 1 search result, got %d (err: %v)", len(searchResults), err)
	}

	// Active Bans & SOAR Action test
	if err := store.RecordBan("198.51.100.25", "T1595 Scan", 3600); err != nil {
		t.Fatalf("RecordBan failed: %v", err)
	}
	bans, err := store.GetActiveBans()
	if err != nil || len(bans) != 1 || bans[0].IP != "198.51.100.25" {
		t.Fatalf("Expected 1 active ban, got %+v", bans)
	}

	if err := store.RecordSOARAction("BAN_IP", "198.51.100.25", 1); err != nil {
		t.Fatalf("RecordSOARAction failed: %v", err)
	}
	actions, err := store.GetRecentSOARActions(5)
	if err != nil || len(actions) != 1 {
		t.Fatalf("Expected 1 soar action, got %+v", actions)
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

func TestAutonomousAutoBanPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)

	// 1. Test Internal IP Protection (Loopback & Private IP should NEVER be banned)
	loopbackEvent := &StoredEvent{
		NodeID:           "node-vps-test",
		ClientIP:         "127.0.0.1",
		ThreatScore:      99,
		MitreTechniqueID: "T1190",
		RuleID:           "sqli_union_injection",
	}
	server.checkAutonomousBanPolicy(loopbackEvent)
	bans, _ := store.GetActiveBans()
	if len(bans) != 0 {
		t.Fatalf("Internal loopback IP 127.0.0.1 must not be banned, got %d bans", len(bans))
	}

	// 2. Test Static Threshold (ThreatScore >= 50 triggers instant ban)
	critEvent := &StoredEvent{
		NodeID:           "node-vps-test",
		ClientIP:         "198.51.100.88",
		ThreatScore:      60,
		MitreTechniqueID: "T1190",
		RuleID:           "sqli_union_injection",
		RawLine:          "GET /search?q=1' UNION SELECT 1,2--",
	}

	server.checkAutonomousBanPolicy(critEvent)

	bans, err := store.GetActiveBans()
	if err != nil || len(bans) != 1 || bans[0].IP != "198.51.100.88" {
		t.Fatalf("Expected auto-ban for 198.51.100.88 (ThreatScore: 60 >= 50), got %+v", bans)
	}

	// 3. Test Correlational Spike Threshold (3x >= 35 within 60s)
	spikeIP := "198.51.100.99"
	spikeEvent := &StoredEvent{
		NodeID:           "node-vps-test",
		ClientIP:         spikeIP,
		ThreatScore:      40,
		MitreTechniqueID: "T1110.001",
		RuleID:           "ssh_failed_password",
		RawLine:          "Failed password for invalid user root",
	}

	// Event 1
	server.checkAutonomousBanPolicy(spikeEvent)
	bans, _ = store.GetActiveBans()
	if len(bans) != 1 { // Still only 1 ban from previous test
		t.Fatalf("Expected no auto-ban after 1 event, got %d bans", len(bans))
	}

	// Event 2
	server.checkAutonomousBanPolicy(spikeEvent)
	bans, _ = store.GetActiveBans()
	if len(bans) != 1 {
		t.Fatalf("Expected no auto-ban after 2 events, got %d bans", len(bans))
	}

	// Event 3 (Should trigger auto-ban)
	server.checkAutonomousBanPolicy(spikeEvent)
	bans, _ = store.GetActiveBans()
	if len(bans) != 2 {
		t.Fatalf("Expected 2 auto-bans after 3rd correlated event, got %d bans", len(bans))
	}
}

func TestTTLBanManagerLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)

	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()

	testIP := "198.51.100.77"

	// 1. Initial Ban (Tier 1: 5 min TTL)
	rec, err := ttlMgr.BanIP(testIP, "Initial Probe", 300, TierRateLimit)
	if err != nil || rec == nil {
		t.Fatalf("BanIP failed: %v", err)
	}

	bans := ttlMgr.GetActiveBans()
	if len(bans) != 1 || bans[0].IP != testIP || bans[0].PenaltyTier != TierRateLimit {
		t.Fatalf("Expected 1 active ban in TierRateLimit, got %+v", bans)
	}

	// 2. Manual Unban
	if err := ttlMgr.UnbanIP(testIP); err != nil {
		t.Fatalf("UnbanIP failed: %v", err)
	}

	bans = ttlMgr.GetActiveBans()
	if len(bans) != 0 {
		t.Fatalf("Expected 0 active bans after manual unban, got %d", len(bans))
	}
}

func TestDeceptionHoneypotAndRateLimiter(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()

	// 1. Honey-URL Router Test
	router := NewHoneyDeceptionRouter(server, ttlMgr, store)
	if !router.IsHoneyURL("/admin") || !router.IsHoneyURL("/.env") || !router.IsHoneyURL("/wp-login.php") {
		t.Errorf("Expected standard deception URLs to be recognized")
	}
	if router.IsHoneyURL("/api/v1/legitimate-endpoint") {
		t.Errorf("Expected legitimate endpoint to NOT be flagged as honey URL")
	}

	// 2. Token-Bucket Rate Limiter Test
	rl := NewTokenBucketRateLimiter(5.0, 5.0, server, ttlMgr) // 5 tokens max
	testIP := "203.0.113.88"

	// Consume all 5 tokens
	for i := 0; i < 5; i++ {
		allowed, _ := rl.Allow(testIP)
		if !allowed {
			t.Errorf("Request %d should have been allowed within burst", i)
		}
	}

	// 6th request must be rejected with 429
	allowed, retryAfter := rl.Allow(testIP)
	if allowed || retryAfter <= 0 {
		t.Errorf("6th request should be rate limited, got allowed=%v, retryAfter=%d", allowed, retryAfter)
	}
}

func TestSystemConfigStorage(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	cfg := map[string]string{
		"grpc_addr":         "127.0.0.1:9443",
		"telegram_token":    "test_bot_token",
		"telegram_chat":     "-100987654",
		"honeypot_ssh_addr": ":2223",
		"autoban_threshold": "65",
		"configured":        "true",
	}

	if err := store.SaveSystemConfig(cfg); err != nil {
		t.Fatalf("SaveSystemConfig failed: %v", err)
	}

	loaded, err := store.GetAllSystemConfig()
	if err != nil {
		t.Fatalf("GetAllSystemConfig failed: %v", err)
	}

	if loaded["grpc_addr"] != "127.0.0.1:9443" || loaded["autoban_threshold"] != "65" {
		t.Errorf("Config mismatch: %+v", loaded)
	}
}
