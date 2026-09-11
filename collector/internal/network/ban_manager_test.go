package network

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	copsecproto "github.com/copsec/collector/proto"
)

// TestDynamicBanTTLAndReaper simulates a 1-second TTL ban, asserts immediate drop,
// and confirms automated eviction after 1.5s with cryptographic audit record.
func TestDynamicBanTTLAndReaper(t *testing.T) {
	bm := NewBanManager()
	testIP := "198.51.100.55"

	var auditCaptured atomic.Bool
	var capturedAudit UnbanAuditEvent
	var grpcAuditSent atomic.Bool

	bm.SetAuditHook(func(event UnbanAuditEvent) {
		capturedAudit = event
		auditCaptured.Store(true)
	})

	bm.SetGRPCSender(func(event *copsecproto.LogEvent) error {
		if event.ClientIp == testIP {
			grpcAuditSent.Store(true)
		}
		return nil
	})

	// 1. Inject ban with a 1-second dynamic TTL
	ttl := 1 * time.Second
	err := bm.AddBan(testIP, ttl, 101, "Simulated Banking Intrusion")
	if err != nil {
		t.Fatalf("Failed to add ban: %v", err)
	}

	// 2. Assert IP is immediately banned
	if !bm.IsBanned(testIP) {
		t.Fatalf("Expected IP %s to be immediately quarantined in eBPF banned_ips map", testIP)
	}

	banInfo, exists := bm.GetBan(testIP)
	if !exists {
		t.Fatalf("Expected ban record to exist for %s", testIP)
	}
	if banInfo.TTLNs != uint64(ttl.Nanoseconds()) {
		t.Errorf("Expected TTL %d ns, got %d ns", ttl.Nanoseconds(), banInfo.TTLNs)
	}

	// 3. Start background reaper with 200ms tick interval for fast test turnaround
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bm.StartBanReaper(ctx, 200*time.Millisecond)

	// 4. Wait 1.5 seconds to ensure TTL expires and reaper runs
	time.Sleep(1500 * time.Millisecond)

	// 5. Assert IP has been automatically unbanned
	if bm.IsBanned(testIP) {
		t.Fatalf("Expected IP %s to be unbanned after 1.5s TTL expiration", testIP)
	}

	// 6. Assert unban audit telemetry was captured
	if !auditCaptured.Load() {
		t.Fatal("Expected unban audit event to be dispatched on TTL expiry")
	}

	if capturedAudit.Actor != "SYSTEM_TTL_REAPER" {
		t.Errorf("Expected Actor 'SYSTEM_TTL_REAPER', got %q", capturedAudit.Actor)
	}
	if capturedAudit.Reason != "Dynamic TTL Expired" {
		t.Errorf("Expected Reason 'Dynamic TTL Expired', got %q", capturedAudit.Reason)
	}
	if capturedAudit.TargetIP != testIP {
		t.Errorf("Expected TargetIP %s, got %s", testIP, capturedAudit.TargetIP)
	}
	if capturedAudit.ActionType != "AUTO_UNBAN" {
		t.Errorf("Expected ActionType 'AUTO_UNBAN', got %s", capturedAudit.ActionType)
	}
	if !grpcAuditSent.Load() {
		t.Error("Expected mTLS gRPC unban event to be dispatched to Controller")
	}
}

// TestManualUnbanAudit verifies that manual administrative unbans generate appropriate audit events.
func TestManualUnbanAudit(t *testing.T) {
	bm := NewBanManager()
	testIP := "198.51.100.77"

	var auditReceived atomic.Bool
	var auditEv UnbanAuditEvent

	bm.SetAuditHook(func(event UnbanAuditEvent) {
		auditEv = event
		auditReceived.Store(true)
	})

	_ = bm.AddBan(testIP, 0, 100, "Permanent Ban")
	if !bm.IsBanned(testIP) {
		t.Fatal("Expected IP to be banned")
	}

	err := bm.RemoveBan(testIP, "SOC_ANALYST_ALICE", "Confirmed False Positive on Audit Gateway")
	if err != nil {
		t.Fatalf("RemoveBan failed: %v", err)
	}

	if bm.IsBanned(testIP) {
		t.Fatal("Expected IP to be unbanned after RemoveBan")
	}

	if !auditReceived.Load() {
		t.Fatal("Expected audit event on manual unban")
	}

	if auditEv.Actor != "SOC_ANALYST_ALICE" {
		t.Errorf("Expected Actor 'SOC_ANALYST_ALICE', got %s", auditEv.Actor)
	}
	if auditEv.ActionType != "MANUAL_UNBAN" {
		t.Errorf("Expected ActionType 'MANUAL_UNBAN', got %s", auditEv.ActionType)
	}
}
