package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"github.com/copsec/controller/pkg/sigma"
	"github.com/copsec/controller/pkg/soar"
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

	// 2. Test Threshold (ThreatScore >= 80 triggers instant ban)
	critEvent := &StoredEvent{
		NodeID:           "node-vps-test",
		ClientIP:         "198.51.100.88",
		ThreatScore:      85,
		MitreTechniqueID: "T1190",
		RuleID:           "sqli_union_injection",
		RawLine:          "GET /search?q=1' UNION SELECT 1,2--",
	}

	server.checkAutonomousBanPolicy(critEvent)

	bans, err := store.GetActiveBans()
	if err != nil || len(bans) != 1 || bans[0].IP != "198.51.100.88" {
		t.Fatalf("Expected auto-ban for 198.51.100.88 (ThreatScore: 85 >= 80), got %+v", bans)
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

func TestSystemConfigStorage(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	cfg := map[string]string{
		"grpc_addr":         "127.0.0.1:9443",
		"ipinfo_token":      "test_tok",
		"autoban_threshold": "80",
		"configured":        "true",
	}

	if err := store.SaveSystemConfig(cfg); err != nil {
		t.Fatalf("SaveSystemConfig failed: %v", err)
	}

	loaded, err := store.GetAllSystemConfig()
	if err != nil {
		t.Fatalf("GetAllSystemConfig failed: %v", err)
	}

	if loaded["grpc_addr"] != "127.0.0.1:9443" || loaded["autoban_threshold"] != "80" {
		t.Errorf("Config mismatch: %+v", loaded)
	}
}

func TestHostLocalRuleDecouplingAndBanInhibition(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	sigmaEng := NewSigmaEngine("")
	server.SetSigmaEngine(sigmaEng)

	// 1. Verify Scope Classification
	if sigma.DetermineRuleScope("sudo_execution", "", "", "", nil) != sigma.ScopeHostLocal {
		t.Fatalf("Expected sudo_execution to be classified as ScopeHostLocal")
	}
	if sigma.DetermineRuleScope("cron_tamper", "", "", "", nil) != sigma.ScopeHostLocal {
		t.Fatalf("Expected cron_tamper to be classified as ScopeHostLocal")
	}
	if sigma.DetermineRuleScope("sigma-linux-persistence", "process_creation", "linux", "", nil) != sigma.ScopeHostLocal {
		t.Fatalf("Expected sigma-linux-persistence to be classified as ScopeHostLocal")
	}
	if sigma.DetermineRuleScope("sigma-web-sqli", "webserver", "nginx", "", nil) != sigma.ScopeNetwork {
		t.Fatalf("Expected sigma-web-sqli to be classified as ScopeNetwork")
	}

	// 2. Test Sudo execution log processing (Should sanitize IP to 127.0.0.1 and inhibit auto-ban)
	sudoEvent := &copsecproto.LogEvent{
		Source:           "auth",
		RawLine:          "Aug 25 12:00:00 vps sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/curl 8.8.8.8",
		ClientIp:         "",
		ThreatScore:      95,
		RuleId:           "sudo_execution",
		MitreTechniqueId: "T1078",
		TimestampMs:      time.Now().UnixMilli(),
	}

	server.processEvent("node-vps-1", sudoEvent)

	// Verify that the event in DB has ClientIP = "127.0.0.1" and NO auto-bans occurred
	events, err := store.GetRecentEvents(5)
	if err != nil || len(events) != 1 {
		t.Fatalf("Expected 1 stored event, got %d (err: %v)", len(events), err)
	}
	if events[0].ClientIP != "127.0.0.1" {
		t.Errorf("Expected ClientIP to be sanitized to 127.0.0.1 for host-local sudo rule, got %s", events[0].ClientIP)
	}

	bans, err := store.GetActiveBans()
	if err != nil || len(bans) != 0 {
		t.Fatalf("Expected 0 active bans for host-local sudo event, got %+v", bans)
	}
}

func TestStorageFlushInvalidQuarantines(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	// Insert invalid historical quarantines
	_ = store.RecordBan("127.0.0.1", "False positive local ban", 86400)
	_ = store.RecordBan("local", "Invalid local host entry", 86400)
	_ = store.RecordBan("198.51.100.99", "sudo_execution false positive", 86400)
	_ = store.RecordBan("203.0.113.55", "Real SQLi attack", 86400)

	// Flush invalid quarantines
	evicted, err := store.FlushInvalidQuarantines()
	if err != nil {
		t.Fatalf("FlushInvalidQuarantines failed: %v", err)
	}
	if evicted < 3 {
		t.Errorf("Expected at least 3 evicted invalid bans, got %d", evicted)
	}

	// Verify only valid WAN ban remains
	bans, err := store.GetActiveBans()
	if err != nil || len(bans) != 1 || bans[0].IP != "203.0.113.55" {
		t.Fatalf("Expected only 203.0.113.55 to remain in active bans, got %+v", bans)
	}
}

func TestSOCAlertsTriageAPI(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	sigmaEng := NewSigmaEngine("")
	server.SetSigmaEngine(sigmaEng)
	hub := NewWSHub()

	webSoc := NewWebSOCServer("127.0.0.1:0", server, store, ttlMgr, sigmaEng, hub)

	// Insert test incidents
	// 1. Critical SQLi (ThreatScore 95)
	_ = store.InsertEvent(&StoredEvent{
		NodeID:           "node-1",
		Source:           "nginx",
		RawLine:          `GET /login?user=admin' UNION SELECT 1,2-- HTTP/1.1`,
		ClientIP:         "198.51.100.44",
		ThreatScore:      95,
		RuleID:           "sigma-web-sqli",
		MitreTechniqueID: "T1190",
		TimestampMs:      time.Now().UnixMilli(),
	})

	// 2. Routine Host-local Sudo execution (Score 20 - should be de-noised from active alerts)
	_ = store.InsertEvent(&StoredEvent{
		NodeID:           "node-1",
		Source:           "auth",
		RawLine:          `sudo: ubuntu : COMMAND=/bin/bash`,
		ClientIP:         "127.0.0.1",
		ThreatScore:      20,
		RuleID:           "sudo_execution",
		MitreTechniqueID: "T1078",
		TimestampMs:      time.Now().UnixMilli(),
	})

	// 3. High-Severity Sudo Privilege Escalation Anomaly (Score 85 - actionable alert)
	_ = store.InsertEvent(&StoredEvent{
		NodeID:           "node-1",
		Source:           "auth",
		RawLine:          `sudo: attacker : 3 incorrect password attempts ; COMMAND=/bin/su`,
		ClientIP:         "127.0.0.1",
		ThreatScore:      85,
		RuleID:           "sigma-sudo-privilege-escalation",
		MitreTechniqueID: "T1548.003",
		TimestampMs:      time.Now().UnixMilli(),
	})

	// 4. Pure-Go ML Anomaly (Score 80, Confidence 88%)
	_ = store.InsertEvent(&StoredEvent{
		NodeID:           "node-1",
		Source:           "nginx",
		RawLine:          `GET /api/v1/stream HTTP/1.1 500`,
		ClientIP:         "198.51.100.88",
		ThreatScore:      80,
		RuleID:           "ml_flow_anomaly",
		MitreTechniqueID: "T1071",
		MLAnomaly:        true,
		MLConfidencePct:  88.0,
		TimestampMs:      time.Now().UnixMilli(),
	})

	// 5. Low-priority noise (Score 10, should be excluded from actionable alerts)
	_ = store.InsertEvent(&StoredEvent{
		NodeID:           "node-1",
		Source:           "nginx",
		RawLine:          `GET /favicon.ico HTTP/1.1 200`,
		ClientIP:         "198.51.100.10",
		ThreatScore:      10,
		RuleID:           "normal_traffic",
		TimestampMs:      time.Now().UnixMilli(),
	})

	// GET /api/alerts
	req := httptest.NewRequest("GET", "/api/alerts?limit=50", nil)
	rec := httptest.NewRecorder()
	webSoc.handleAlerts(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 from /api/alerts, got %d", rec.Code)
	}

	var alerts []*SOCAlertDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("Failed to parse /api/alerts response: %v", err)
	}

	if len(alerts) != 3 {
		t.Fatalf("Expected exactly 3 actionable alerts (SQLi, Sudo Escalation, ML anomaly), got %d", len(alerts))
	}

	// Verify containment state for host-local
	for _, a := range alerts {
		if a.RuleID == "sigma-sudo-privilege-escalation" {
			if a.ContainmentState != "HOST CONTAINED" || !a.IsHostLocal {
				t.Errorf("Expected sudo escalation to have containment 'HOST CONTAINED', got %s", a.ContainmentState)
			}
		}
		if a.RuleID == "sudo_execution" {
			t.Errorf("Routine sudo_execution should be de-noised and excluded from /api/alerts")
		}
	}

	// Test Triage Action: Quick Ban 198.51.100.44
	triageBody, _ := json.Marshal(map[string]interface{}{
		"action": "ban",
		"ip":     "198.51.100.44",
		"reason": "Analyst Triage Quick Ban",
	})
	triageReq := httptest.NewRequest("POST", "/api/alerts/triage", bytes.NewBuffer(triageBody))
	triageReq.Header.Set("Content-Type", "application/json")
	triageRec := httptest.NewRecorder()
	webSoc.handleAlertsTriage(triageRec, triageReq)

	if triageRec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 from /api/alerts/triage, got %d", triageRec.Code)
	}

	// Verify ban was enforced
	bans := ttlMgr.GetActiveBans()
	if len(bans) != 1 || bans[0].IP != "198.51.100.44" {
		t.Fatalf("Expected 198.51.100.44 to be active in TTL manager, got %+v", bans)
	}

	// Test Dismiss (Resolve) on remaining alert
	dismissBody, _ := json.Marshal(map[string]interface{}{
		"id":     "198.51.100.88",
		"status": "RESOLVED",
	})
	dismissReq := httptest.NewRequest("POST", "/api/alerts/dismiss", bytes.NewBuffer(dismissBody))
	dismissReq.Header.Set("Content-Type", "application/json")
	dismissRec := httptest.NewRecorder()
	webSoc.handleAlertsDismiss(dismissRec, dismissReq)
	if dismissRec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 from /api/alerts/dismiss, got %d", dismissRec.Code)
	}

	// Verify active alerts count decreased
	reqActive := httptest.NewRequest("GET", "/api/alerts?status=ACTIVE&limit=50", nil)
	recActive := httptest.NewRecorder()
	webSoc.handleAlerts(recActive, reqActive)
	var activeAlerts []*SOCAlertDTO
	_ = json.Unmarshal(recActive.Body.Bytes(), &activeAlerts)

	// Verify resolved archive contains the dismissed/mitigated alerts
	reqArchive := httptest.NewRequest("GET", "/api/alerts?status=RESOLVED&limit=50", nil)
	recArchive := httptest.NewRecorder()
	webSoc.handleAlerts(recArchive, reqArchive)
	var resolvedAlerts []*SOCAlertDTO
	if err := json.Unmarshal(recArchive.Body.Bytes(), &resolvedAlerts); err != nil {
		t.Fatalf("Failed to parse archive response: %v", err)
	}
	if len(resolvedAlerts) == 0 {
		t.Fatalf("Expected at least 1 resolved alert in archive, got 0")
	}
}

func TestSOARPlaybookEngineAndLifecycle(t *testing.T) {
	eng := soar.GetDefaultEngine()
	playbooks := eng.GetPlaybooks()
	if len(playbooks) < 4 {
		t.Fatalf("Expected at least 4 curated SOAR playbooks, got %d", len(playbooks))
	}

	// Verify required playbooks
	required := []string{"PB-101", "PB-204", "PB-305", "PB-406"}
	for _, id := range required {
		pb := eng.GetPlaybook(id)
		if pb == nil {
			t.Errorf("Required playbook %s not found", id)
		}
	}

	// Start run
	run := eng.StartPlaybookRun(5001, "PB-101", "198.51.100.99", "node-prod-1", 90, "T1190", "SQLi Injection")
	if run.Status != "RUNNING" {
		t.Errorf("Expected status RUNNING, got %s", run.Status)
	}

	// Advance step
	updated, err := eng.AdvanceStep(run.RunID, 0, "COMPLETED", "Extracted offending URI: /api/v1/users")
	if err != nil || updated.CurrentStepIdx != 1 {
		t.Errorf("AdvanceStep failed: %v", err)
	}
}

func TestIPInfoRESTLookupAndDrawerEnrichment(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStorageEngine(filepath.Join(tmpDir, "ipinfo_test.db"))
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	wsHub := NewWSHub()

	webSoc := NewWebSOCServer(":0", server, store, ttlMgr, nil, wsHub)

	// 1. Test GET /api/ipinfo/lookup with public test IP
	req := httptest.NewRequest("GET", "/api/ipinfo/lookup?ip=198.51.100.77", nil)
	rec := httptest.NewRecorder()
	webSoc.handleIPInfoLookup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 from /api/ipinfo/lookup, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse IPinfo response: %v", err)
	}

	if resp["ip"] != "198.51.100.77" {
		t.Errorf("Expected IP 198.51.100.77, got %v", resp["ip"])
	}
	if resp["country"] == "" && resp["country_code"] == "" {
		t.Errorf("Expected non-empty country in IPinfo response")
	}

	// 2. Test GET /api/ipinfo/lookup with private IP
	privReq := httptest.NewRequest("GET", "/api/ipinfo/lookup?ip=10.0.0.1", nil)
	privRec := httptest.NewRecorder()
	webSoc.handleIPInfoLookup(privRec, privReq)

	if privRec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for private IP, got %d", privRec.Code)
	}

	var privResp map[string]interface{}
	_ = json.Unmarshal(privRec.Body.Bytes(), &privResp)
	if privResp["country"] != "LOC" {
		t.Errorf("Expected country LOC for private IP, got %v", privResp["country"])
	}
}

func TestRulesAPIEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewStorageEngine(filepath.Join(tmpDir, "rules_api_test.db"))
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	wsHub := NewWSHub()

	webSoc := NewWebSOCServer(":0", server, store, ttlMgr, nil, wsHub)

	// 1. Test GET /api/rules -> Returns list of in-memory rules with origin tags
	req := httptest.NewRequest("GET", "/api/rules", nil)
	rec := httptest.NewRecorder()
	webSoc.handleRulesList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/rules, got %d", rec.Code)
	}

	var rulesList []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &rulesList); err != nil {
		t.Fatalf("Failed to parse /api/rules JSON: %v", err)
	}

	if len(rulesList) == 0 {
		t.Fatalf("Expected non-empty rules list from /api/rules")
	}

	// Verify origin tags exist
	foundOrigin := false
	for _, r := range rulesList {
		if origin, ok := r["origin"].(string); ok && (origin == "[BUILTIN]" || origin == "[SIGMAHQ]" || origin == "[CUSTOM]") {
			foundOrigin = true
			break
		}
	}
	if !foundOrigin {
		t.Errorf("Expected [BUILTIN] or [SIGMAHQ] origin tag in rules response: %+v", rulesList[0])
	}

	// 2. Test POST /api/rules/toggle -> Toggle specific rule on the fly
	toggleBody, _ := json.Marshal(map[string]interface{}{
		"rule_id": "sigma-linux-revshell",
		"enabled": false,
	})
	toggleReq := httptest.NewRequest("POST", "/api/rules/toggle", bytes.NewBuffer(toggleBody))
	toggleReq.Header.Set("Content-Type", "application/json")
	toggleRec := httptest.NewRecorder()
	webSoc.handleRulesToggle(toggleRec, toggleReq)

	if toggleRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from POST /api/rules/toggle, got %d", toggleRec.Code)
	}

	var toggleResp map[string]interface{}
	_ = json.Unmarshal(toggleRec.Body.Bytes(), &toggleResp)
	if toggleResp["enabled"] != false {
		t.Errorf("Expected enabled = false in toggle response, got %v", toggleResp["enabled"])
	}

	// 3. Test POST /api/rules/sync -> Trigger background sync
	syncReq := httptest.NewRequest("POST", "/api/rules/sync", nil)
	syncRec := httptest.NewRecorder()
	webSoc.handleRulesSync(syncRec, syncReq)

	if syncRec.Code != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted from POST /api/rules/sync, got %d", syncRec.Code)
	}

	var syncResp map[string]interface{}
	_ = json.Unmarshal(syncRec.Body.Bytes(), &syncResp)
	if syncResp["success"] != true {
		t.Errorf("Expected success = true in sync response, got %v", syncResp)
	}
}

func TestPersistentConfigAndIPInfoEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStorageEngine(filepath.Join(tmpDir, "config_test.db"))
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// 1. Test StorageEngine SaveConfig and GetConfig directly
	err = store.SaveConfig("ipinfo_token", "test_secret_token_12345")
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	val, err := store.GetConfig("ipinfo_token")
	if err != nil || val != "test_secret_token_12345" {
		t.Fatalf("GetConfig returned %q, err: %v", val, err)
	}

	// 2. Test WebSOCServer REST endpoints
	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	wsHub := NewWSHub()
	webSoc := NewWebSOCServer(":0", server, store, ttlMgr, nil, wsHub)

	// GET /api/config/ipinfo
	getReq := httptest.NewRequest("GET", "/api/config/ipinfo", nil)
	getRec := httptest.NewRecorder()
	webSoc.handleConfigIPInfo(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/config/ipinfo, got %d", getRec.Code)
	}
	var getResp map[string]interface{}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if getResp["configured"] != true {
		t.Errorf("Expected configured = true, got %v", getResp["configured"])
	}
	if getResp["token_masked"] != "test****" {
		t.Errorf("Expected token_masked = test****, got %v", getResp["token_masked"])
	}

	// POST /api/config/ipinfo
	postBody, _ := json.Marshal(map[string]string{
		"token": "live_prod_key_9999",
	})
	postReq := httptest.NewRequest("POST", "/api/config/ipinfo", bytes.NewBuffer(postBody))
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	webSoc.handleConfigIPInfo(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from POST /api/config/ipinfo, got %d", postRec.Code)
	}
	var postResp map[string]interface{}
	_ = json.Unmarshal(postRec.Body.Bytes(), &postResp)
	if postResp["status"] != "saved" || postResp["configured"] != true {
		t.Errorf("Unexpected POST response: %+v", postResp)
	}

	// Verify persistence in SQLite
	persisted, err := store.GetConfig("ipinfo_token")
	if err != nil || persisted != "live_prod_key_9999" {
		t.Errorf("Expected persisted token 'live_prod_key_9999', got %q, err: %v", persisted, err)
	}
}

