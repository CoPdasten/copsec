package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSeverityCalculation(t *testing.T) {
	cases := []struct {
		score    int
		expected Severity
	}{
		{0, SeverityInfo},
		{-5, SeverityInfo},
		{1, SeverityLow},
		{29, SeverityLow},
		{30, SeverityMedium},
		{59, SeverityMedium},
		{60, SeverityHigh},
		{84, SeverityHigh},
		{85, SeverityCritical},
		{100, SeverityCritical},
	}

	for _, c := range cases {
		got := CalculateSeverity(c.score)
		if got != c.expected {
			t.Errorf("CalculateSeverity(%d) = %s; want %s", c.score, got, c.expected)
		}
	}
}

func TestUnifiedTelemetryJSONTags(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tel := UnifiedTelemetry{
		ID:          "tel-12345",
		Timestamp:   now,
		SourceNode:  "node-prod-01",
		Layer:       "WAF",
		SourceIP:    "198.51.100.42",
		SourcePort:  54321,
		DestIP:      "192.168.1.10",
		DestPort:    443,
		Protocol:    "TCP",
		ThreatScore: 95,
		Severity:    SeverityCritical,
		MitreID:     "T1190",
		RuleMatched: "sigma-web-sqli",
		RawPayload:  "GET /login?user=admin' UNION SELECT 1,2-- HTTP/1.1",
		Metadata: map[string]interface{}{
			"user_agent": "sqlmap/1.5",
			"status_code": 403,
		},
	}

	data, err := tel.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	jsonStr := string(data)

	// Verify required canonical JSON fields
	requiredFields := []string{
		`"id":"tel-12345"`,
		`"timestamp":`,
		`"source_node":"node-prod-01"`,
		`"layer":"WAF"`,
		`"source_ip":"198.51.100.42"`,
		`"source_port":54321`,
		`"dest_ip":"192.168.1.10"`,
		`"dest_port":443`,
		`"protocol":"TCP"`,
		`"threat_score":95`,
		`"severity":"CRITICAL"`,
		`"mitre_id":"T1190"`,
		`"rule_matched":"sigma-web-sqli"`,
		`"raw_payload":`,
	}

	for _, rf := range requiredFields {
		if !strings.Contains(jsonStr, rf) {
			t.Errorf("Expected JSON to contain %s, got:\n%s", rf, jsonStr)
		}
	}

	// Verify Unmarshal
	var unmarshaled UnifiedTelemetry
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if unmarshaled.SourceIP != tel.SourceIP {
		t.Errorf("SourceIP mismatch: got %s, want %s", unmarshaled.SourceIP, tel.SourceIP)
	}
	if unmarshaled.ThreatScore != 95 {
		t.Errorf("ThreatScore mismatch: got %d, want 95", unmarshaled.ThreatScore)
	}
	if unmarshaled.Severity != SeverityCritical {
		t.Errorf("Severity mismatch: got %s, want %s", unmarshaled.Severity, SeverityCritical)
	}
	if unmarshaled.MitreID != "T1190" {
		t.Errorf("MitreID mismatch: got %s, want T1190", unmarshaled.MitreID)
	}
	if unmarshaled.RuleMatched != "sigma-web-sqli" {
		t.Errorf("RuleMatched mismatch: got %s, want sigma-web-sqli", unmarshaled.RuleMatched)
	}
}

func TestUnifiedTelemetryValidation(t *testing.T) {
	now := time.Now()

	valid := UnifiedTelemetry{
		ID:          "tel-1",
		Timestamp:   now,
		SourceNode:  "node-1",
		Layer:       "NET",
		SourceIP:    "1.2.3.4",
		ThreatScore: 50,
		Severity:    SeverityMedium,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Expected valid telemetry, got error: %v", err)
	}

	invalidScore := valid
	invalidScore.ThreatScore = 150
	if err := invalidScore.Validate(); err == nil {
		t.Errorf("Expected error for threat_score = 150, got nil")
	}

	invalidSeverity := valid
	invalidSeverity.Severity = "EXTREME"
	if err := invalidSeverity.Validate(); err == nil {
		t.Errorf("Expected error for invalid severity, got nil")
	}

	invalidIP := valid
	invalidIP.SourceIP = "999.999.999.999"
	if err := invalidIP.Validate(); err == nil {
		t.Errorf("Expected error for invalid IP, got nil")
	}
}

func TestNormalizeLayer(t *testing.T) {
	if got := NormalizeLayer("waf"); got != "WAF" {
		t.Errorf("NormalizeLayer('waf') = %s, want WAF", got)
	}
	if got := NormalizeLayer("nginx"); got != "WAF" {
		t.Errorf("NormalizeLayer('nginx') = %s, want WAF", got)
	}
	if got := NormalizeLayer("ebpf"); got != "EDR" {
		t.Errorf("NormalizeLayer('ebpf') = %s, want EDR", got)
	}
	if got := NormalizeLayer("ssh"); got != "AUTH" {
		t.Errorf("NormalizeLayer('ssh') = %s, want AUTH", got)
	}
	if got := NormalizeLayer("suricata"); got != "NET" {
		t.Errorf("NormalizeLayer('suricata') = %s, want NET", got)
	}
}
