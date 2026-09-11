package ebpf

import (
	"testing"
	"time"
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

	// 4. Dynamic TTL Expiration
	_ = engine.AddBanWithTTL("198.51.100.99", 50*time.Millisecond, 4, "Short TTL Test")
	if !engine.IsBanned("198.51.100.99") {
		t.Errorf("Expected 198.51.100.99 to be banned immediately after insertion")
	}
	time.Sleep(70 * time.Millisecond)
	if engine.IsBanned("198.51.100.99") {
		t.Errorf("Expected 198.51.100.99 to be expired and unbanned")
	}

	// 5. Asymmetric Tarpit Engine Tests
	tarpitIP := "203.0.113.88"
	if err := engine.AddTarpit(tarpitIP); err != nil {
		t.Fatalf("AddTarpit failed: %v", err)
	}
	if !engine.IsTarpitted(tarpitIP) {
		t.Errorf("Expected IP %s to be marked as tarpitted", tarpitIP)
	}
	if engine.GetTarpitPacketsCount() == 0 {
		t.Errorf("Expected tarpit packet count > 0")
	}
	_ = engine.RemoveTarpit(tarpitIP)
	if engine.IsTarpitted(tarpitIP) {
		t.Errorf("Expected IP %s to be removed from tarpit registry", tarpitIP)
	}

	// 6. SYN-Proxy Toggle Tests
	if err := engine.EnableSynProxy(8080); err != nil {
		t.Errorf("EnableSynProxy failed: %v", err)
	}
	if err := engine.DisableSynProxy(); err != nil {
		t.Errorf("DisableSynProxy failed: %v", err)
	}

	// 7. Whitelist Tests
	wlIP := "10.0.0.1"
	_ = engine.AddWhitelistIP(wlIP)
	if !engine.IsWhitelisted(wlIP) {
		t.Errorf("Expected %s to be whitelisted", wlIP)
	}
	_ = engine.RemoveWhitelistIP(wlIP)
	if engine.IsWhitelisted(wlIP) {
		t.Errorf("Expected %s to be un-whitelisted", wlIP)
	}

	_ = engine.Close()
}
