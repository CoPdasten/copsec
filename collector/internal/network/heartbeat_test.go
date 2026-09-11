package network

import (
	"testing"
	"time"
)

func TestHeartbeatTelemetryCollection(t *testing.T) {
	cfg := HeartbeatConfig{
		NodeID:          "test-collector-01",
		NodeGroup:       "DMZ_INGRESS",
		Interval:        1 * time.Second,
	}

	worker := NewHeartbeatWorker(cfg)
	if worker == nil {
		t.Fatal("expected non-nil HeartbeatWorker")
	}

	// 1. Test interface detection
	iface, ip := worker.DetectActiveInterface()
	if iface == "" {
		t.Error("expected non-empty active interface")
	}
	if ip == "" {
		t.Error("expected non-empty IP address")
	}

	// 2. Test CPU calculation
	cpu := worker.ReadCPUUsage()
	if cpu < 0 || cpu > 100 {
		t.Errorf("CPU percent out of range [0, 100]: %f", cpu)
	}

	// 3. Test RSS Memory
	rss := worker.ReadRSSMemoryMB()
	if rss <= 0 {
		t.Errorf("expected positive RSS memory in MB, got: %f", rss)
	}

	// 4. Test Drops
	drops := worker.ReadXDPDrops(iface)
	if drops < 0 {
		t.Errorf("expected non-negative drops, got: %d", drops)
	}

	// 5. Test XDP Status
	status := worker.DetectXDPStatus(iface)
	if status != "ACTIVE" && status != "BYPASS" && status != "OFFLINE" {
		t.Errorf("unexpected XDP status: %s", status)
	}
}
