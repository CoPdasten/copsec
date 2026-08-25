package soar

import (
	"testing"
)

func TestPlaybookRegistryAndDefinitions(t *testing.T) {
	eng := NewEngine()
	playbooks := eng.GetPlaybooks()
	if len(playbooks) < 5 {
		t.Fatalf("Expected at least 5 curated playbooks, got %d", len(playbooks))
	}

	pb101 := eng.GetPlaybook("PB-101")
	if pb101 == nil {
		t.Fatalf("Expected PB-101 to exist")
	}
	if len(pb101.Steps) != 4 {
		t.Errorf("Expected 4 steps in PB-101, got %d", len(pb101.Steps))
	}
}

func TestAntiNoiseGatingAndHighFidelityTriggers(t *testing.T) {
	eng := NewEngine()

	// 1. Static Asset / Benign Request Gating (Should NOT trigger)
	benignEvents := []struct {
		score   int
		ip      string
		rule    string
		mitre   string
		raw     string
		history int
	}{
		{50, "198.51.100.1", "web_access", "T1190", "GET /robots.txt HTTP/1.1", 1},
		{45, "198.51.100.2", "web_access", "", "GET /favicon.ico HTTP/1.1", 1},
		{60, "198.51.100.3", "static_probe", "", "GET /static/app.js HTTP/1.1", 1},
		{30, "198.51.100.4", "health_check", "", "GET /health HTTP/1.1", 1},
		{20, "-", "internal_stats", "", `{"event_type":"stats"}`, 0},
	}

	for _, tt := range benignEvents {
		shouldTrigger, reason, pbID := eng.ShouldTriggerSOAR(tt.score, tt.ip, tt.rule, tt.mitre, tt.raw, tt.history)
		if shouldTrigger {
			t.Errorf("Expected benign event %s to be discarded by anti-noise filter, but triggered %s (Playbook: %s)", tt.raw, reason, pbID)
		}
	}

	// 2. High-Severity & Confirmed Threat Triggers (MUST Trigger)
	criticalEvents := []struct {
		score          int
		ip             string
		rule           string
		mitre          string
		raw            string
		history        int
		expectedPB     string
	}{
		{90, "198.51.100.45", "rce_exploit", "T1190", "POST /api/exec cmd=/bin/sh -i HTTP/1.1", 1, "PB-101"},
		{85, "198.51.100.50", "ssh_auth_burst", "T1110", "Failed password for root from 198.51.100.50", 6, "PB-204"},
		{95, "198.51.100.60", "c2_beacon", "T1071", "DNS query tunnel.c2.attacker.com", 1, "PB-305"},
		{95, "127.0.0.1", "rootkit_tamper", "T1014", "eBPF ptrace injection detected on PID 1234", 1, "PB-402"},
	}

	for _, tt := range criticalEvents {
		shouldTrigger, reason, pbID := eng.ShouldTriggerSOAR(tt.score, tt.ip, tt.rule, tt.mitre, tt.raw, tt.history)
		if !shouldTrigger {
			t.Errorf("Expected critical event %s to trigger SOAR, but was filtered", tt.raw)
		}
		if pbID != tt.expectedPB {
			t.Errorf("Expected Playbook %s, got %s (Reason: %s)", tt.expectedPB, pbID, reason)
		}
	}
}

func TestPlaybookExecutionLifecycle(t *testing.T) {
	eng := NewEngine()
	run := eng.StartPlaybookRun(1001, "PB-101", "198.51.100.45", "node-edge-01", 90, "T1190", "Confirmed RCE Injection")

	if run.Status != "RUNNING" {
		t.Fatalf("Expected status RUNNING, got %s", run.Status)
	}
	if run.CurrentStepIdx != 0 {
		t.Fatalf("Expected current step 0, got %d", run.CurrentStepIdx)
	}

	// Advance Step 0
	run, err := eng.AdvanceStep(run.RunID, 0, "COMPLETED", "Extracted offending URI: /api/exec")
	if err != nil {
		t.Fatalf("Failed to advance step: %v", err)
	}
	if run.CurrentStepIdx != 1 {
		t.Errorf("Expected current step 1, got %d", run.CurrentStepIdx)
	}

	// Advance Remaining Steps
	eng.AdvanceStep(run.RunID, 1, "COMPLETED", "Verified no interactive shell spawned")
	eng.AdvanceStep(run.RunID, 2, "COMPLETED", "Injected IP into XDP drop map")
	run, _ = eng.AdvanceStep(run.RunID, 3, "COMPLETED", "WAF rule deployed and Nginx reloaded")

	if run.Status != "CONTAINED" {
		t.Errorf("Expected final status CONTAINED, got %s", run.Status)
	}
}

func TestRemediationActionExecution(t *testing.T) {
	eng := NewEngine()
	eng.SetActionHook(func(actionType, actorIP, nodeID, param string) (string, error) {
		return "NIC XDP fast-path blackhole active", nil
	})

	res, err := eng.ExecuteRemediationAction("XDP_BLACKHOLE", "198.51.100.45", "node-01", "")
	if err != nil {
		t.Fatalf("Action execution failed: %v", err)
	}
	if res["message"] != "NIC XDP fast-path blackhole active" {
		t.Errorf("Unexpected message: %v", res["message"])
	}
}
