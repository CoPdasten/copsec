package ebpf

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SocketTuple represents a 4-tuple network connection identifier.
type SocketTuple struct {
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"` // TCP, UDP
}

// Key formats the socket tuple into a normalized bidirectional index key.
func (s SocketTuple) Key() string {
	return fmt.Sprintf("%s:%d->%s:%d", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort)
}

// ReverseKey returns the reverse orientation of the socket.
func (s SocketTuple) ReverseKey() string {
	return fmt.Sprintf("%s:%d->%s:%d", s.DstIP, s.DstPort, s.SrcIP, s.SrcPort)
}

// ProcessContext stores kernel process metadata correlated with network connections.
type ProcessContext struct {
	PID          int           `json:"pid"`
	PPID         int           `json:"ppid"`
	UID          int           `json:"uid"`
	Comm         string        `json:"comm"`
	BinaryPath   string        `json:"binary_path"`
	CommandLine  string        `json:"command_line"`
	StartTimeMs  int64         `json:"start_time_ms"`
	SocketTuples []SocketTuple `json:"socket_tuples,omitempty"`
}

// EDRTelemetryEvent represents an EDR enforcement event emitted upon autonomous isolation.
type EDRTelemetryEvent struct {
	TimestampMs  int64          `json:"timestamp_ms"`
	EventType    string         `json:"event_type"` // EDR_KILL, ROGUE_PROCESS_TERMINATED
	PID          int            `json:"pid"`
	PPID         int            `json:"ppid"`
	Comm         string         `json:"comm"`
	BinaryPath   string         `json:"binary_path"`
	CommandLine  string         `json:"command_line"`
	AttackerIP   string         `json:"attacker_ip"`
	ThreatScore  int            `json:"threat_score"`
	MitreID      string         `json:"mitre_id"`
	ActionTaken  string         `json:"action_taken"`
	LogMessage   string         `json:"log_message"`
	SocketTuple  SocketTuple    `json:"socket_tuple,omitempty"`
}

// EDREngine manages kernel tracepoint hooks (connect/execve), socket-to-PID correlation,
// and autonomous termination of rogue exploitation shells and downloaders.
type EDREngine struct {
	mu                sync.RWMutex
	active            bool
	socketToProcess   map[string]*ProcessContext // socketKey -> proc
	ipToProcesses     map[string]map[int]*ProcessContext // ip -> map[pid]*proc
	pidToProcess      map[int]*ProcessContext
	rogueBinaries     map[string]bool
	killedCount       uint64
	scannedCount      uint64
	onEDREvent        func(event EDRTelemetryEvent)
	stopChan          chan struct{}
}

var (
	defaultEDREngine *EDREngine
	edrOnce          sync.Once
)

// GetDefaultEDREngine returns the singleton EDREngine.
func GetDefaultEDREngine() *EDREngine {
	edrOnce.Do(func() {
		defaultEDREngine = NewEDREngine(nil)
	})
	return defaultEDREngine
}

// NewEDREngine creates a new EDR engine instance.
func NewEDREngine(onEvent func(EDRTelemetryEvent)) *EDREngine {
	engine := &EDREngine{
		active:          true,
		socketToProcess: make(map[string]*ProcessContext),
		ipToProcesses:   make(map[string]map[int]*ProcessContext),
		pidToProcess:    make(map[int]*ProcessContext),
		rogueBinaries: map[string]bool{
			"bash":    true,
			"sh":      true,
			"zsh":     true,
			"dash":    true,
			"ksh":     true,
			"nc":      true,
			"ncat":    true,
			"netcat":  true,
			"socat":   true,
			"python":  true,
			"python2": true,
			"python3": true,
			"curl":    true,
			"wget":    true,
			"perl":    true,
			"ruby":    true,
			"php":     true,
			"lua":     true,
		},
		onEDREvent: onEvent,
		stopChan:   make(chan struct{}),
	}
	return engine
}

// SetEventHandler configures the telemetry listener for EDR mitigation actions.
func (e *EDREngine) SetEventHandler(handler func(EDRTelemetryEvent)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onEDREvent = handler
}

// Start launches background socket-to-process kernel correlation.
func (e *EDREngine) Start(ctx context.Context) error {
	go e.runCorrelationLoop(ctx)
	return nil
}

// Stop halts the EDR engine background routines.
func (e *EDREngine) Stop() {
	select {
	case <-e.stopChan:
		return
	default:
		close(e.stopChan)
	}
}

func (e *EDREngine) runCorrelationLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Initial scan
	_ = e.RefreshKernelSocketMap()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case <-ticker.C:
			_ = e.RefreshKernelSocketMap()
		}
	}
}

// RegisterSocketProcess manually registers a socket-to-process mapping (used by tracepoints and tests).
func (e *EDREngine) RegisterSocketProcess(proc ProcessContext, tuple SocketTuple) {
	e.mu.Lock()
	defer e.mu.Unlock()

	pCopy := proc
	pCopy.SocketTuples = append(pCopy.SocketTuples, tuple)

	e.socketToProcess[tuple.Key()] = &pCopy
	e.socketToProcess[tuple.ReverseKey()] = &pCopy
	e.pidToProcess[proc.PID] = &pCopy

	// Register IP mappings
	if tuple.SrcIP != "" && tuple.SrcIP != "127.0.0.1" {
		if e.ipToProcesses[tuple.SrcIP] == nil {
			e.ipToProcesses[tuple.SrcIP] = make(map[int]*ProcessContext)
		}
		e.ipToProcesses[tuple.SrcIP][proc.PID] = &pCopy
	}
	if tuple.DstIP != "" && tuple.DstIP != "127.0.0.1" {
		if e.ipToProcesses[tuple.DstIP] == nil {
			e.ipToProcesses[tuple.DstIP] = make(map[int]*ProcessContext)
		}
		e.ipToProcesses[tuple.DstIP][proc.PID] = &pCopy
	}
}

// LookupProcessBySocket resolves a socket 4-tuple to its active process context.
func (e *EDREngine) LookupProcessBySocket(srcIP string, srcPort int, dstIP string, dstPort int) (*ProcessContext, bool) {
	tuple := SocketTuple{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}

	e.mu.RLock()
	proc, ok := e.socketToProcess[tuple.Key()]
	if !ok {
		proc, ok = e.socketToProcess[tuple.ReverseKey()]
	}
	e.mu.RUnlock()

	if ok {
		return proc, true
	}

	// Dynamic fallback: scan active kernel procfs/tracepoint tables
	_ = e.RefreshKernelSocketMap()

	e.mu.RLock()
	defer e.mu.RUnlock()
	proc, ok = e.socketToProcess[tuple.Key()]
	if !ok {
		proc, ok = e.socketToProcess[tuple.ReverseKey()]
	}
	return proc, ok
}

// LookupProcessByIP finds all processes communicating with a given remote IP.
func (e *EDREngine) LookupProcessByIP(ip string) ([]*ProcessContext, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	procMap, ok := e.ipToProcesses[ip]
	if !ok || len(procMap) == 0 {
		return nil, false
	}

	list := make([]*ProcessContext, 0, len(procMap))
	for _, p := range procMap {
		list = append(list, p)
	}
	return list, true
}

// IsRogueProcess checks if a process command name or binary path matches interactive shells or downloaders.
func (e *EDREngine) IsRogueProcess(comm, exePath string) bool {
	cleanComm := strings.ToLower(strings.TrimSpace(comm))
	baseExe := strings.ToLower(filepath.Base(exePath))

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.rogueBinaries[cleanComm] || e.rogueBinaries[baseExe] {
		return true
	}

	for rogue := range e.rogueBinaries {
		if cleanComm == rogue || baseExe == rogue {
			return true
		}
		if strings.HasPrefix(cleanComm, rogue+".") || strings.HasPrefix(baseExe, rogue+".") ||
			strings.HasPrefix(cleanComm, rogue+"-") || strings.HasPrefix(baseExe, rogue+"-") {
			return true
		}
	}
	return false
}

// MitigateSocketAttack isolates and terminates rogue processes correlated with an exploitation attempt.
func (e *EDREngine) MitigateSocketAttack(srcIP string, srcPort int, dstIP string, dstPort int, attackerIP string, reason string) (*EDRTelemetryEvent, error) {
	proc, found := e.LookupProcessBySocket(srcIP, srcPort, dstIP, dstPort)
	if !found {
		// Try resolving via IP
		if procs, ok := e.LookupProcessByIP(attackerIP); ok && len(procs) > 0 {
			for _, p := range procs {
				if e.IsRogueProcess(p.Comm, p.BinaryPath) {
					proc = p
					found = true
					break
				}
			}
			if !found {
				proc = procs[0]
				found = true
			}
		}
	}

	if !found || proc == nil {
		return nil, fmt.Errorf("no correlated process found for socket %s:%d->%s:%d (attacker: %s)", srcIP, srcPort, dstIP, dstPort, attackerIP)
	}

	return e.KillRogueProcess(proc.PID, attackerIP, reason)
}

// KillRogueProcess enforces immediate SIGKILL process termination and emits EDR telemetry.
func (e *EDREngine) KillRogueProcess(pid int, attackerIP string, reason string) (*EDRTelemetryEvent, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("refusing to terminate protected system PID %d", pid)
	}

	e.mu.RLock()
	proc, ok := e.pidToProcess[pid]
	comm := ""
	exePath := ""
	cmdline := ""
	ppid := 0
	if ok && proc != nil {
		comm = proc.Comm
		exePath = proc.BinaryPath
		cmdline = proc.CommandLine
		ppid = proc.PPID
	}
	cb := e.onEDREvent
	e.mu.RUnlock()

	if comm == "" {
		comm = fmt.Sprintf("proc_%d", pid)
	}

	// 1. Enforce kernel SIGKILL termination
	killErr := sendSIGKILL(pid)

	atomic.AddUint64(&e.killedCount, 1)

	logMsg := fmt.Sprintf("[EDR_KILL] Terminated rogue execution PID=%d, Comm=%s spawned by attacker %s", pid, comm, attackerIP)
	log.Printf("[EDR_ALERT] ⚡ %s (Reason: %s)", logMsg, reason)

	event := EDRTelemetryEvent{
		TimestampMs: time.Now().UnixMilli(),
		EventType:   "EDR_KILL",
		PID:         pid,
		PPID:        ppid,
		Comm:        comm,
		BinaryPath:  exePath,
		CommandLine: cmdline,
		AttackerIP:  attackerIP,
		ThreatScore: 100,
		MitreID:     "T1059.004", // Command and Scripting Interpreter: Unix Shell
		ActionTaken: "SIGKILL_ENFORCED",
		LogMessage:  logMsg,
	}

	if cb != nil {
		cb(event)
	}

	// Purge from tracking
	e.mu.Lock()
	delete(e.pidToProcess, pid)
	e.mu.Unlock()

	return &event, killErr
}

// GetStats returns EDR engine telemetry counters.
func (e *EDREngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"active_socket_mappings": len(e.socketToProcess),
		"tracked_processes":      len(e.pidToProcess),
		"rogue_kills_total":      atomic.LoadUint64(&e.killedCount),
	}
}
