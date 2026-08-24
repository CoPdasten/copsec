package healing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFIMSelfHealingAutoRemediation(t *testing.T) {
	tmpDir := t.TempDir()
	testTarget := filepath.Join(tmpDir, "sshd_config")

	originalContent := []byte("Port 22\nPermitRootLogin no\nPasswordAuthentication no\n")
	err := os.WriteFile(testTarget, originalContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write initial file: %v", err)
	}

	var healedEvents []FIMDriftEvent
	engine := NewFIMHealingEngine(func(ev FIMDriftEvent) {
		healedEvents = append(healedEvents, ev)
	})

	engine.RegisterTarget(testTarget, originalContent, 0644)

	// 1. Verify clean file (no drift)
	ev1, drifted1 := engine.VerifyAndHeal(testTarget)
	if drifted1 || ev1 != nil {
		t.Fatalf("Expected no drift on unaltered baseline file")
	}

	// 2. Simulate Attacker Tampering (Adding backdoor backdoor ssh config)
	tamperedContent := []byte("Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n# BACKDOOR INJECTED\n")
	err = os.WriteFile(testTarget, tamperedContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}

	// 3. Trigger Verification & Auto-Healing
	ev2, drifted2 := engine.VerifyAndHeal(testTarget)
	if !drifted2 || ev2 == nil {
		t.Fatalf("Expected configuration drift to be detected")
	}
	if !ev2.Remediated {
		t.Errorf("Expected file to be marked remediated")
	}

	// 4. Verify file was restored to original content
	restoredData, err := os.ReadFile(testTarget)
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}
	if string(restoredData) != string(originalContent) {
		t.Errorf("Restored content mismatch: expected %q, got %q", string(originalContent), string(restoredData))
	}
}
