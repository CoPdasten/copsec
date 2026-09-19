package bpf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestTTLBanManager_Lifecycle(t *testing.T) {
	// Create an in-kernel or mock LRU hash map
	spec := &ebpf.MapSpec{
		Name:       "dynamic_ttl_ban",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  16, // uint64 ExpireAtNs + uint32 Reason + 4 byte padding
		MaxEntries: 1024,
	}

	bpfMap, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("skipping test: kernel BPF map creation requires root/CAP_BPF privileges: %v", err)
	}
	defer bpfMap.Close()

	mgr, err := NewTTLBanManager(bpfMap)
	if err != nil {
		t.Fatalf("failed to initialize TTLBanManager: %v", err)
	}

	testIP := net.ParseIP("198.51.100.50")
	duration := 10 * time.Minute
	reason := uint32(2) // e.g. RATE_LIMIT

	// 1. Ban IP
	before := uint64(time.Now().UnixNano())
	if err := mgr.BanIP(testIP, duration, reason); err != nil {
		t.Fatalf("BanIP failed: %v", err)
	}
	after := uint64(time.Now().UnixNano())

	// 2. Check direct map contents
	key := binary.NativeEndian.Uint32(testIP.To4())
	var entry BanEntry
	if err := bpfMap.Lookup(key, &entry); err != nil {
		t.Fatalf("map lookup failed for banned IP: %v", err)
	}

	if entry.Reason != reason {
		t.Errorf("expected reason %d, got %d", reason, entry.Reason)
	}

	expectedMin := before + uint64(duration.Nanoseconds())
	expectedMax := after + uint64(duration.Nanoseconds())
	if entry.ExpireAtNs < expectedMin || entry.ExpireAtNs > expectedMax {
		t.Errorf("ExpireAtNs out of range: got %d, want between %d and %d", entry.ExpireAtNs, expectedMin, expectedMax)
	}

	// 3. IsBanned check
	isBanned, e, err := mgr.IsBanned(testIP)
	if err != nil {
		t.Fatalf("IsBanned failed: %v", err)
	}
	if !isBanned || e == nil {
		t.Errorf("expected IP to be reported as banned")
	}

	// 4. GetActiveBans snapshot
	active, err := mgr.GetActiveBans()
	if err != nil {
		t.Fatalf("GetActiveBans failed: %v", err)
	}
	if _, ok := active["198.51.100.50"]; !ok {
		t.Errorf("active bans snapshot missing banned IP: %+v", active)
	}

	// 5. Unban IP
	if err := mgr.UnbanIP(testIP); err != nil {
		t.Fatalf("UnbanIP failed: %v", err)
	}

	// Verify evicted from map
	isBannedAfter, _, _ := mgr.IsBanned(testIP)
	if isBannedAfter {
		t.Errorf("expected IP to be unbanned")
	}

	// 6. Idempotent unban of non-existent IP should succeed
	if err := mgr.UnbanIP(net.ParseIP("192.0.2.1")); err != nil {
		t.Errorf("idempotent UnbanIP failed: %v", err)
	}
}
