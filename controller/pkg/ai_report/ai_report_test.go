package ai_report

import (
	"strings"
	"testing"
	"time"

	"github.com/copsec/controller/pkg/geoip"
)

func TestGenerateIncidentReportAndExport(t *testing.T) {
	geoEngine := geoip.NewEngine()
	rg := NewReportGenerator(geoEngine)

	report := rg.GenerateIncidentReport(
		"INC-TEST-001",
		"198.51.100.45",
		"vds-node-1",
		"suricata",
		90,
		"sqli_union_injection",
		"T1190",
		"GET /api/v1/users?id=1' UNION SELECT username,password FROM users-- HTTP/1.1",
		"• Intent: Extract backend SQL database records\n• Root Cause: Unsanitized input parameter",
		time.Now().UnixMilli(),
		nil,
	)

	if report == nil {
		t.Fatal("Failed to generate IncidentForensicReport")
	}

	if report.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", report.Severity)
	}

	if report.TargetIP != "198.51.100.45" {
		t.Errorf("Expected target IP 198.51.100.45, got %s", report.TargetIP)
	}

	// Markdown Export
	md := report.ToMarkdown()
	if !strings.Contains(md, "CoPSeC Executive SOC Incident Forensic Report") {
		t.Errorf("Markdown export missing title")
	}
	if !strings.Contains(md, "T1190") {
		t.Errorf("Markdown export missing MITRE ID")
	}

	// HTML Export
	html := report.ToHTML()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("HTML export missing doctype")
	}
	if !strings.Contains(html, "CoPSeC CYBER DEFENSE CENTER") {
		t.Errorf("HTML export missing brand header")
	}
	if !strings.Contains(html, "198.51.100.45") {
		t.Errorf("HTML export missing target IP")
	}
}
