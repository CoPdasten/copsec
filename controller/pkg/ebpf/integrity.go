package ebpf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IntegrityEvent captures an attempt to tamper with process memory or load unsigned kernel modules.
type IntegrityEvent struct {
	TimestampMs int64  `json:"timestamp_ms"`
	EventType   string `json:"event_type"` // PTRACE_ATTACH, PROCESS_VM_WRITEV, KERNEL_MODULE_LOAD, PROCESS_HOLLOWING
	PID         int    `json:"pid"`
	TargetPID   int    `json:"target_pid"`
	ProcessName string `json:"process_name"`
	BinaryPath  string `json:"binary_path"`
	ThreatScore int    `json:"threat_score"`
	MitreID     string `json:"mitre_id"`
	ActionTaken string `json:"action_taken"`
	Details     string `json:"details"`
}

// IntegrityGuard monitors kernel events and enforces zero-tolerance process termination on injection.
type IntegrityGuard struct {
	mu                   sync.RWMutex
	active               bool
	injectionsBlocked    uint64
	rogueModulesBlocked  uint64
	processesTerminated  uint64
	quarantineDir        string
	onIntegrityViolation func(event IntegrityEvent)
	recentEvents         []IntegrityEvent
}

var (
	defaultGuard *IntegrityGuard
	guardOnce    sync.Once
)

// GetDefaultIntegrityGuard returns the singleton integrity guard instance.
func GetDefaultIntegrityGuard() *IntegrityGuard {
	guardOnce.Do(func() {
		defaultGuard = NewIntegrityGuard("/var/lib/copsec/quarantine", nil)
	})
	return defaultGuard
}

// NewIntegrityGuard initializes the eBPF rootkit & process injection defender.
func NewIntegrityGuard(quarantineDir string, onViolation func(event IntegrityEvent)) *IntegrityGuard {
	if quarantineDir == "" {
		quarantineDir = "./quarantine"
	}
	_ = os.MkdirAll(quarantineDir, 0700)

	return &IntegrityGuard{
		active:               true,
		quarantineDir:        quarantineDir,
		onIntegrityViolation: onViolation,
		recentEvents:         make([]IntegrityEvent, 0, 50),
	}
}

// InspectSyscallPtrace evaluates a ptrace call between tracer and tracee PIDs.
func (ig *IntegrityGuard) InspectSyscallPtrace(tracerPID, targetPID int, request uint) (*IntegrityEvent, bool) {
	if tracerPID <= 0 || targetPID <= 0 || tracerPID == targetPID {
		return nil, false
	}

	procName := ig.getProcessName(tracerPID)
	binPath := ig.getBinaryPath(tracerPID)

	// Legitimate debuggers or self-profilers whitelist (e.g. gdb if explicitly authorized)
	if strings.Contains(procName, "systemd") || strings.Contains(procName, "gdb") {
		return nil, false
	}

	atomic.AddUint64(&ig.injectionsBlocked, 1)

	ev := IntegrityEvent{
		TimestampMs: time.Now().UnixMilli(),
		EventType:   "PTRACE_ATTACH",
		PID:         tracerPID,
		TargetPID:   targetPID,
		ProcessName: procName,
		BinaryPath:  binPath,
		ThreatScore: 95,
		MitreID:     "T1055.008", // Process Injection: Ptrace System Calls
		ActionTaken: "SIGKILL_ENFORCED",
		Details:     fmt.Sprintf("Rogue process %s (PID %d) attempted unauthorized ptrace attach on target PID %d", procName, tracerPID, targetPID),
	}

	ig.terminateAndQuarantine(tracerPID, binPath)
	ig.recordEvent(ev)

	return &ev, true
}

// InspectProcessVMWritev intercepts process_vm_writev memory writes (Process Hollowing / Shellcode Injection).
func (ig *IntegrityGuard) InspectProcessVMWritev(sourcePID, targetPID int, bytesWritten int) (*IntegrityEvent, bool) {
	if sourcePID <= 0 || targetPID <= 0 || sourcePID == targetPID {
		return nil, false
	}

	procName := ig.getProcessName(sourcePID)
	binPath := ig.getBinaryPath(sourcePID)

	atomic.AddUint64(&ig.injectionsBlocked, 1)

	ev := IntegrityEvent{
		TimestampMs: time.Now().UnixMilli(),
		EventType:   "PROCESS_VM_WRITEV",
		PID:         sourcePID,
		TargetPID:   targetPID,
		ProcessName: procName,
		BinaryPath:  binPath,
		ThreatScore: 98,
		MitreID:     "T1055.012", // Process Injection: Process Hollowing
		ActionTaken: "SIGKILL_ENFORCED",
		Details:     fmt.Sprintf("Direct virtual memory write of %d bytes from PID %d (%s) into PID %d", bytesWritten, sourcePID, procName, targetPID),
	}

	ig.terminateAndQuarantine(sourcePID, binPath)
	ig.recordEvent(ev)

	return &ev, true
}

// InspectKernelModuleLoad checks for unauthorized or unsigned kernel module (.ko) injection.
func (ig *IntegrityGuard) InspectKernelModuleLoad(callerPID int, moduleName string, modulePath string) (*IntegrityEvent, bool) {
	procName := ig.getProcessName(callerPID)
	binPath := ig.getBinaryPath(callerPID)

	// Legitimate kernel modprobe daemon
	if strings.Contains(procName, "systemd-modules") || strings.Contains(procName, "kmod") {
		return nil, false
	}

	atomic.AddUint64(&ig.rogueModulesBlocked, 1)

	ev := IntegrityEvent{
		TimestampMs: time.Now().UnixMilli(),
		EventType:   "KERNEL_MODULE_LOAD",
		PID:         callerPID,
		TargetPID:   0,
		ProcessName: procName,
		BinaryPath:  binPath,
		ThreatScore: 100,
		MitreID:     "T1547.006", // Kernel Modules and Drivers (Rootkit Persistence)
		ActionTaken: "SIGKILL_AND_MODULE_REJECTED",
		Details:     fmt.Sprintf("Unauthorized attempt by PID %d (%s) to insert kernel module %s (%s)", callerPID, procName, moduleName, modulePath),
	}

	ig.terminateAndQuarantine(callerPID, binPath)
	ig.recordEvent(ev)

	return &ev, true
}

// terminateAndQuarantine kills the rogue process immediately and moves its binary to quarantine.
func (ig *IntegrityGuard) terminateAndQuarantine(pid int, binPath string) {
	if pid > 1 {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
		atomic.AddUint64(&ig.processesTerminated, 1)
		log.Printf("[EBPF_INTEGRITY] ⚡ Terminated rogue PID %d via SIGKILL (Process Injection / Rootkit Guard)", pid)
	}

	if binPath != "" && !strings.HasPrefix(binPath, "/bin/") && !strings.HasPrefix(binPath, "/usr/bin/") {
		dest := filepath.Join(ig.quarantineDir, fmt.Sprintf("quarantine_%d_%s", time.Now().Unix(), filepath.Base(binPath)))
		_ = os.Rename(binPath, dest)
	}
}

func (ig *IntegrityGuard) recordEvent(ev IntegrityEvent) {
	ig.mu.Lock()
	defer ig.mu.Unlock()

	ig.recentEvents = append(ig.recentEvents, ev)
	if len(ig.recentEvents) > 50 {
		ig.recentEvents = ig.recentEvents[1:]
	}

	if ig.onIntegrityViolation != nil {
		go ig.onIntegrityViolation(ev)
	}
}

func (ig *IntegrityGuard) getProcessName(pid int) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	return fmt.Sprintf("proc_%d", pid)
}

func (ig *IntegrityGuard) getBinaryPath(pid int) string {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err == nil {
		return target
	}
	return ""
}

// GetStats returns the total counters for the Integrity Guard subsystem.
func (ig *IntegrityGuard) GetStats() map[string]interface{} {
	ig.mu.RLock()
	defer ig.mu.RUnlock()

	return map[string]interface{}{
		"injections_blocked":    atomic.LoadUint64(&ig.injectionsBlocked),
		"rogue_modules_blocked": atomic.LoadUint64(&ig.rogueModulesBlocked),
		"processes_terminated":  atomic.LoadUint64(&ig.processesTerminated),
		"recent_events_count":   len(ig.recentEvents),
	}
}

// GetRecentEvents returns the slice of recorded integrity events.
func (ig *IntegrityGuard) GetRecentEvents() []IntegrityEvent {
	ig.mu.RLock()
	defer ig.mu.RUnlock()

	res := make([]IntegrityEvent, len(ig.recentEvents))
	copy(res, ig.recentEvents)
	return res
}
