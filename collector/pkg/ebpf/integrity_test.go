package ebpf

import (
	"sync"
	"testing"
)

func TestIntegrityGuardPtraceAndModuleInspection(t *testing.T) {
	var mu sync.Mutex
	var capturedEvents []IntegrityEvent
	guard := NewIntegrityGuard("/tmp/test_quarantine", func(ev IntegrityEvent) {
		mu.Lock()
		capturedEvents = append(capturedEvents, ev)
		mu.Unlock()
	})

	// 1. Test Ptrace Injection Interception
	ev1, blocked1 := guard.InspectSyscallPtrace(12345, 1000, 16)
	if !blocked1 || ev1 == nil {
		t.Fatalf("Expected ptrace injection attempt to be blocked")
	}
	if ev1.ThreatScore < 90 {
		t.Errorf("Expected high threat score for ptrace injection, got %d", ev1.ThreatScore)
	}

	// 2. Test Process VM Writev Interception
	ev2, blocked2 := guard.InspectProcessVMWritev(12346, 1001, 4096)
	if !blocked2 || ev2 == nil {
		t.Fatalf("Expected process_vm_writev injection attempt to be blocked")
	}
	if ev2.EventType != "PROCESS_VM_WRITEV" {
		t.Errorf("Expected event type PROCESS_VM_WRITEV, got %s", ev2.EventType)
	}

	// 3. Test Kernel Module Rootkit Injection Interception
	ev3, blocked3 := guard.InspectKernelModuleLoad(12347, "diamorphine.ko", "/tmp/diamorphine.ko")
	if !blocked3 || ev3 == nil {
		t.Fatalf("Expected rogue kernel module loading to be blocked")
	}
	if ev3.ThreatScore != 100 {
		t.Errorf("Expected threat score 100 for rootkit module, got %d", ev3.ThreatScore)
	}

	// Verify stats
	stats := guard.GetStats()
	if stats["injections_blocked"].(uint64) != 2 {
		t.Errorf("Expected 2 injections blocked, got %v", stats["injections_blocked"])
	}
	if stats["rogue_modules_blocked"].(uint64) != 1 {
		t.Errorf("Expected 1 rogue module blocked, got %v", stats["rogue_modules_blocked"])
	}
}
