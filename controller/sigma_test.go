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
