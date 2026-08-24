package ebpf

import (
	"testing"
)

func TestXDPMitigationEngineLifecycle(t *testing.T) {
	engine := NewXDPMitigationEngine("lo")
	if engine == nil {
		t.Fatal("Failed to initialize XDPMitigationEngine")
	}

	testIP := "198.51.100.45"

	// 1. Add Ban
	err := engine.AddBan(testIP)
	if err != nil {
		t.Fatalf("AddBan failed: %v", err)
	}

	if !engine.IsBanned(testIP) {
		t.Errorf("Expected IP %s to be marked banned in XDP map", testIP)
	}

	if engine.GetActiveBansCount() != 1 {
		t.Errorf("Expected active bans count 1, got %d", engine.GetActiveBansCount())
	}

	if engine.GetDroppedPacketsCount() == 0 {
		t.Errorf("Expected dropped packet count > 0")
	}

	// 2. Remove Ban
	err = engine.RemoveBan(testIP)
	if err != nil {
		t.Fatalf("RemoveBan failed: %v", err)
	}

	if engine.IsBanned(testIP) {
		t.Errorf("Expected IP %s to be unbanned in XDP map", testIP)
	}

	// 3. Flush
	_ = engine.AddBan("198.51.100.50")
	_ = engine.AddBan("198.51.100.51")
	if engine.GetActiveBansCount() != 2 {
		t.Errorf("Expected 2 bans, got %d", engine.GetActiveBansCount())
	}

	_ = engine.Flush()
	if engine.GetActiveBansCount() != 0 {
		t.Errorf("Expected 0 bans after flush, got %d", engine.GetActiveBansCount())
	}

	_ = engine.Close()
}
