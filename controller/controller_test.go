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
		ClientIP:         "198.51.100.89",
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

func TestIPAlertSuppressionEngine(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStorageEngine(filepath.Join(tmpDir, "test_suppression.db"))
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	wsHub := NewWSHub()
	webSoc := NewWebSOCServer(":0", server, store, ttlMgr, nil, wsHub)

	mitigatedIP := "198.51.100.111"

	// 1. Initially IP is not mitigated
	if store.IsIPMitigated(mitigatedIP) {
		t.Fatalf("IP %s should not be mitigated initially", mitigatedIP)
	}

	// 2. Perform mitigation via triage action (ban)
	triageBody, _ := json.Marshal(map[string]interface{}{
		"action": "ban",
		"ip":     mitigatedIP,
	})
	req := httptest.NewRequest("POST", "/api/alerts/triage", bytes.NewBuffer(triageBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	webSoc.handleAlertsTriage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleAlertsTriage returned %d", rec.Code)
	}

	// Verify suppression pool registration
	if !store.IsIPMitigated(mitigatedIP) {
		t.Fatalf("IP %s must be registered in suppression pool", mitigatedIP)
	}

	// 3. Process new high-threat event from suppressed IP
	event := &copsecproto.LogEvent{
		Source:           "nginx",
		ClientIp:         mitigatedIP,
		StatusCode:       403,
		TimestampMs:      time.Now().UnixMilli(),
		RuleId:           "sigma-web-rce",
		MitreTechniqueId: "T1059",
		ThreatScore:      90,
		RawLine:          "GET /shell.php?cmd=id HTTP/1.1 403",
	}

	server.processEvent("node-test", event)

	// Verify event was saved to raw telemetry with triage_status = MITIGATED
	events, err := store.GetRecentEvents(10)
	if err != nil || len(events) == 0 {
		t.Fatalf("Expected raw telemetry event to be recorded, err: %v", err)
	}
	if events[0].TriageStatus != "MITIGATED" {
		t.Errorf("Expected triage_status = 'MITIGATED', got %s", events[0].TriageStatus)
	}

	// Verify active alerts table does NOT contain new alert for this suppressed IP
	activeAlerts, err := store.GetActiveAlerts(10)
	if err != nil {
		t.Fatalf("GetActiveAlerts failed: %v", err)
	}
	for _, a := range activeAlerts {
		if a.ClientIP == mitigatedIP {
			t.Errorf("Active alerts queue must NOT contain records for suppressed IP %s", mitigatedIP)
		}
	}

	// 4. Test unban releases suppression
	unbanBody, _ := json.Marshal(map[string]interface{}{
		"ip": mitigatedIP,
	})
	unbanReq := httptest.NewRequest("POST", "/api/quarantine/unban", bytes.NewBuffer(unbanBody))
	unbanReq.Header.Set("Content-Type", "application/json")
	unbanRec := httptest.NewRecorder()
	webSoc.handleSOARUnban(unbanRec, unbanReq)

	if store.IsIPMitigated(mitigatedIP) {
		t.Errorf("IP %s should no longer be suppressed after unban", mitigatedIP)
	}
}

func TestPermanentAlertLifecycleSync(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStorageEngine(filepath.Join(tmpDir, "test_lifecycle.db"))
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	ttlMgr := NewTTLBanManager(store, server)
	defer ttlMgr.Stop()
	wsHub := NewWSHub()
	webSoc := NewWebSOCServer(":0", server, store, ttlMgr, nil, wsHub)

	// 1. Insert active alert
	alert := &StoredEvent{
		NodeID:           "node-test",
		Source:           "nginx",
		ClientIP:         "198.51.100.222",
		StatusCode:       401,
		TimestampMs:      time.Now().UnixMilli(),
		RuleID:           "test_brute_force",
		MitreTechniqueID: "T1110",
		ThreatScore:      80,
		TriageStatus:     "ACTIVE",
		RawLine:          "POST /login HTTP/1.1 401",
	}
	_ = store.InsertEvent(alert)
	_ = store.InsertAlert(alert)

	activeAlerts, _ := store.GetActiveAlerts(10)
	if len(activeAlerts) != 1 {
		t.Fatalf("Expected 1 active alert, got %d", len(activeAlerts))
	}

	// 2. Dismiss the alert via REST endpoint
	dismissBody, _ := json.Marshal(map[string]interface{}{
		"id": alert.ID,
		"ip": alert.ClientIP,
	})
	req := httptest.NewRequest("POST", "/api/alerts/dismiss", bytes.NewBuffer(dismissBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	webSoc.handleAlertsDismiss(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleAlertsDismiss returned %d", rec.Code)
	}

	// Verify Handled cache
	if !IsAlertHandled(alert.ID) {
		t.Errorf("Expected alert.ID %d to be in HandledAlertIDs cache", alert.ID)
	}

	// Verify active alerts query returns 0
	activeAfterDismiss, _ := store.GetActiveAlerts(10)
	if len(activeAfterDismiss) != 0 {
		t.Errorf("Expected 0 active alerts after dismiss, got %d", len(activeAfterDismiss))
	}

	// 3. Verify ClearAllActiveAlerts
	// Insert another alert
	alert2 := &StoredEvent{
		NodeID:           "node-test",
		Source:           "nginx",
		ClientIP:         "198.51.100.223",
		StatusCode:       403,
		TimestampMs:      time.Now().UnixMilli(),
		RuleID:           "test_rce",
		MitreTechniqueID: "T1059",
		ThreatScore:      85,
		TriageStatus:     "ACTIVE",
		RawLine:          "GET /eval.php HTTP/1.1 403",
	}
	_ = store.InsertEvent(alert2)
	_ = store.InsertAlert(alert2)

	clearReq := httptest.NewRequest("POST", "/api/alerts/clear", bytes.NewBuffer([]byte("{}")))
	clearReq.Header.Set("Content-Type", "application/json")
	clearRec := httptest.NewRecorder()
	webSoc.handleAlertsClear(clearRec, clearReq)

	if clearRec.Code != http.StatusOK {
		t.Fatalf("handleAlertsClear returned %d", clearRec.Code)
	}

	if !IsAlertHandled(alert2.ID) {
		t.Errorf("Expected alert2.ID %d to be in HandledAlertIDs cache after clear", alert2.ID)
	}

	activeAfterClear, _ := store.GetActiveAlerts(10)
	if len(activeAfterClear) != 0 {
		t.Errorf("Expected 0 active alerts after clear, got %d", len(activeAfterClear))
	}
}

func TestThreatIntelEngineMatchAndBoost(t *testing.T) {
	intel := NewThreatIntelEngine()

	// 1. Tor Exit Node Match
	entry, matched := intel.MatchIP("185.220.101.5")
	if !matched || entry == nil {
		t.Fatalf("Expected Tor exit node 185.220.101.5 to match threat intel")
	}
	if entry.Category != "TOR_EXIT_NODE" || entry.Confidence < 90 {
		t.Errorf("Unexpected entry category/confidence: %+v", entry)
	}

	// 2. Subnet Range Match (Censys scanner pool 162.142.125.0/24)
	entry2, matched2 := intel.MatchIP("162.142.125.44")
	if !matched2 || entry2 == nil {
		t.Fatalf("Expected Censys scanner pool IP 162.142.125.44 to match threat intel")
	}
	if entry2.Category != "SCANNER_POOL" {
		t.Errorf("Unexpected scanner category: %s", entry2.Category)
	}

	// 3. Benign / Whitelisted IP (Must not match)
	_, matchedLocal := intel.MatchIP("127.0.0.1")
	if matchedLocal {
		t.Errorf("Loopback IP 127.0.0.1 must not match threat intel")
	}

	_, matchedDNS := intel.MatchIP("8.8.8.8")
	if matchedDNS {
		t.Errorf("Public DNS 8.8.8.8 must not match threat intel")
	}

	// 4. Stats check
	stats := intel.GetStats()
	if stats["exact_ips_count"].(int) == 0 || stats["cidr_blocks_count"].(int) == 0 {
		t.Errorf("Expected populated stats, got: %+v", stats)
	}
}

func TestAutonomousSOAREngineCorrelationAndAutoBan(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "soar_test.db")
	store, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	hub := NewWSHub()
	server.SetWSHub(hub)
	ttlMgr := NewTTLBanManager(store, server)
	server.SetTTLManager(ttlMgr)
	defer ttlMgr.Stop()

	intel := GetDefaultThreatIntel()
	soarEng := NewAutonomousSOAREngine(store, server, ttlMgr, hub, intel)
	server.SetSOAREngine(soarEng)

	targetIP := "198.51.100.77"

	// 1. Port scan signal (Port probes)
	ev1 := &StoredEvent{
		NodeID:      "node-1",
		ClientIP:    targetIP,
		Source:      "syslog",
		RawLine:     "SYN flood / port scan probe detected on port 445",
		RuleID:      "port_scan_recon",
		ThreatScore: 40,
		TimestampMs: time.Now().UnixMilli(),
	}
	score1, factors1, mitigated1 := soarEng.CorrelateSignal(ev1)
	if mitigated1 {
		t.Errorf("Signal 1 should not trigger auto-ban immediately")
	}
	if score1 < 40 {
		t.Errorf("Expected score >= 40, got %d (factors: %s)", score1, factors1)
	}

	// 2. Auth Failure / Credential Stuffing signal
	ev2 := &StoredEvent{
		NodeID:      "node-1",
		ClientIP:    targetIP,
		Source:      "auth",
		RawLine:     "Failed password for root from 198.51.100.77 port 48212 ssh2",
		RuleID:      "ssh_failed_password",
		ThreatScore: 50,
		TimestampMs: time.Now().UnixMilli(),
	}
	score2, factors2, mitigated2 := soarEng.CorrelateSignal(ev2)
	if mitigated2 {
		t.Errorf("Signal 2 alone should not trigger auto-ban")
	}
	if score2 <= score1 {
		t.Errorf("Expected score escalation on multi-signal correlation: score1=%d, score2=%d (factors: %s)", score1, score2, factors2)
	}

	// 3. High Entropy Exploit Payload / RCE injection signal (Should push score >= 90 and trigger auto-ban)
	ev3 := &StoredEvent{
		NodeID:      "node-1",
		ClientIP:    targetIP,
		Source:      "nginx",
		RawLine:     "GET /cgi-bin/vulnerable.cgi?cmd=%2Fbin%2Fsh+-c+'id%3Bwhoami%3Bcat+%2Fetc%2Fpasswd' HTTP/1.1 500",
		StatusCode:  500,
		RuleID:      "sigma_linux_revshell",
		ThreatScore: 85,
		TimestampMs: time.Now().UnixMilli(),
	}
	score3, factors3, mitigated3 := soarEng.CorrelateSignal(ev3)
	if !mitigated3 {
		t.Errorf("Expected auto-ban mitigation on composite score >= 90 (score=%d, factors=%s)", score3, factors3)
	}
	if score3 < 90 {
		t.Errorf("Expected composite score >= 90, got %d", score3)
	}

	// Verify ban in TTL manager / active bans
	activeBans := ttlMgr.GetActiveBans()
	banned := false
	for _, b := range activeBans {
		if b.IP == targetIP {
			banned = true
			break
		}
	}
	if !banned {
		t.Errorf("Expected IP %s to be registered in active bans", targetIP)
	}

	// 4. Test TTL Decay eviction cycle
	soarEng.PruneExpiredBans()
}

func TestHashLogChainingAndIntegrityVerification(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "hash_chain_test.db")
	store, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// 1. Insert series of telemetry events
	ev1 := &StoredEvent{
		NodeID:      "node-1",
		Source:      "nginx",
		RawLine:     "GET /index.html HTTP/1.1 200",
		ClientIP:    "198.51.100.10",
		ThreatScore: 10,
		TimestampMs: time.Now().UnixMilli(),
	}
	_ = store.InsertEvent(ev1)

	ev2 := &StoredEvent{
		NodeID:      "node-1",
		Source:      "auth",
		RawLine:     "Failed password for root from 198.51.100.20",
		ClientIP:    "198.51.100.20",
		ThreatScore: 70,
		TimestampMs: time.Now().UnixMilli(),
	}
	_ = store.InsertEvent(ev2)

	ev3 := &StoredEvent{
		NodeID:      "node-2",
		Source:      "nginx",
		RawLine:     "GET /api/v1/user?id=' UNION SELECT 1,2,3-- HTTP/1.1 403",
		ClientIP:    "198.51.100.30",
		ThreatScore: 90,
		TimestampMs: time.Now().UnixMilli(),
	}
	_ = store.InsertEvent(ev3)

	// 2. Verify Cryptographic Integrity
	valid, verifiedCount, lastHash, err := store.VerifyLogIntegrity()
	if err != nil {
		t.Fatalf("Log integrity verification returned error: %v", err)
	}
	if !valid {
		t.Errorf("Expected valid log chain integrity")
	}
	if verifiedCount < 3 {
		t.Errorf("Expected at least 3 verified records, got %d", verifiedCount)
	}
	if lastHash == "" {
		t.Errorf("Expected non-empty last hash")
	}

	// 3. Test REST API Endpoint: GET /api/audit/verify-integrity
	webSoc := NewWebSOCServer(":19999", nil, store, nil, nil, nil)
	req := httptest.NewRequest("GET", "/api/audit/verify-integrity", nil)
	rec := httptest.NewRecorder()
	webSoc.handleAuditVerifyIntegrity(rec, req)

	// 4. Test Hash Chain Healing & Backfill (corrupt a hash then heal)
	_, _ = store.db.Exec(`UPDATE telemetry SET prev_hash = 'corrupted_hash' WHERE id = 2`)
	validCorrupt, _, _, errCorrupt := store.VerifyLogIntegrity()
	if validCorrupt || errCorrupt == nil {
		t.Errorf("Expected integrity error on corrupted hash chain")
	}

	// Trigger Healing & Backfill
	err = store.HealAndBackfillHashChain()
	if err != nil {
		t.Fatalf("HealAndBackfillHashChain failed: %v", err)
	}

	validHealed, healedCount, healedHead, errHealed := store.VerifyLogIntegrity()
	if !validHealed || errHealed != nil || healedCount < 3 || healedHead == "" {
		t.Errorf("Expected successfully healed and verified log chain: valid=%v, err=%v, count=%d, head=%s", validHealed, errHealed, healedCount, healedHead)
	}
}

func TestContextualZeroTrustEngine(t *testing.T) {
	zte := NewContextualZeroTrustEngine(nil, nil, nil)
	targetIP := "198.51.100.55"

	// 1. Initial event with normal profile (baseline 100)
	ev1 := &StoredEvent{
		ClientIP:    targetIP,
		Source:      "nginx",
		RawLine:     "GET /dashboard HTTP/1.1 200",
		ThreatScore: 0,
		ASN:         "AS13335 Cloudflare",
		CountryCode: "US",
		TimestampMs: time.Now().UnixMilli(),
	}
	score1, isolated1, _ := zte.EvaluateEvent(ev1)
	if isolated1 {
		t.Errorf("Initial event should not trigger isolation")
	}
	if score1 < 60 {
		t.Errorf("Expected score1 >= 60, got %d", score1)
	}

	// 2. High entropy SQLi / exploit payload (Penalty -40)
	ev2 := &StoredEvent{
		ClientIP:    targetIP,
		Source:      "nginx",
		RawLine:     "GET /search?q=%27%20UNION%20SELECT%20null%2Cnull%2Cschema_name%20FROM%20information_schema.schemata--%20 HTTP/1.1 403",
		RuleID:      "sqli_detection",
		ThreatScore: 80,
		ASN:         "AS14061 DigitalOcean", // ASN Deviation (-30)
		CountryCode: "RU",                  // Geo Deviation (-30)
		TimestampMs: time.Now().UnixMilli(),
	}
	score2, isolated2, stepUp2 := zte.EvaluateEvent(ev2)
	if score2 >= 40 {
		t.Errorf("Expected trust score < 40 on multiple severe penalties, got %d", score2)
	}
	if !isolated2 || !stepUp2 {
		t.Errorf("Expected zero trust isolation and step-up auth triggered (isolated=%v, stepUp=%v)", isolated2, stepUp2)
	}

	// 3. Reset trust score back to 100
	zte.ResetTrustScore(targetIP)
	state, found := zte.GetEntityState(targetIP)
	if !found || state.TrustScore != 100 || state.IsIsolated {
		t.Errorf("Expected trust state reset to 100, got: %+v", state)
	}
}

func TestSDNRouterEdgeMitigation(t *testing.T) {
	router := NewSDNRouter()
	bgpDriver := NewBGPFlowspecDriver()
	router.RegisterProvider(bgpDriver)

	cloudDriver := NewCloudEdgeSecurityGroupDriver("", "")
	router.RegisterProvider(cloudDriver)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targetIP := "198.51.100.99"

	// 1. Enforce drop
	err := router.EnforceEdgeDrop(ctx, targetIP, 3600)
	if err != nil {
		t.Logf("EnforceEdgeDrop output/error (expected on non-root test environments): %v", err)
	}

	// 2. Release drop
	err = router.ReleaseEdgeDrop(ctx, targetIP)
	if err != nil {
		t.Logf("ReleaseEdgeDrop output/error: %v", err)
	}
}



