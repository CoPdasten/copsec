package yara

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// YARARule defines a signature pattern for in-memory threat detection.
type YARARule struct {
	ID          string
	Name        string
	Category    string // "SHELLCODE", "COBALT_STRIKE", "METERPRETER", "WEBSHELL", "ROOTKIT"
	ThreatScore int
	MitreID     string
	Patterns    [][]byte
	Regex       *regexp.Regexp
	Description string
}

// YARADetection records an in-memory signature hit.
type YARADetection struct {
	TimestampMs int64  `json:"timestamp_ms"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Category    string `json:"category"`
	ThreatScore int    `json:"threat_score"`
	MitreID     string `json:"mitre_id"`
	MatchedData string `json:"matched_data"`
	MemoryOffset string `json:"memory_offset"`
	ActionTaken string `json:"action_taken"`
}

// MemoryScanner executes pattern matching against process memory buffers and live anonymous RAM maps.
type MemoryScanner struct {
	mu           sync.RWMutex
	rules        []YARARule
	scansTotal   uint64
	hitsTotal    uint64
	recentHits   []YARADetection
	onDetection  func(detection YARADetection)
}

var (
	defaultScanner *MemoryScanner
	scannerOnce    sync.Once
)

// GetDefaultScanner returns the singleton in-memory scanner.
func GetDefaultScanner() *MemoryScanner {
	scannerOnce.Do(func() {
		defaultScanner = NewMemoryScanner(nil)
	})
	return defaultScanner
}

// NewMemoryScanner initializes the in-memory YARA detection engine.
func NewMemoryScanner(onDetection func(detection YARADetection)) *MemoryScanner {
	scanner := &MemoryScanner{
		rules:       make([]YARARule, 0),
		recentHits:  make([]YARADetection, 0, 50),
		onDetection: onDetection,
	}
	scanner.loadBuiltinSignatures()
	return scanner
}

func (ms *MemoryScanner) loadBuiltinSignatures() {
	ms.rules = []YARARule{
		{
			ID:          "YARA-MEM-001",
			Name:        "CobaltStrike_Beacon_Stager",
			Category:    "COBALT_STRIKE",
			ThreatScore: 95,
			MitreID:     "T1059.001",
			Patterns: [][]byte{
				[]byte("%s as %s\\%s: %d"),
				[]byte("IEX (New-Object Net.WebClient).DownloadString"),
				[]byte("\\\\.\\pipe\\msagent_"),
			},
			Description: "Cobalt Strike beacon memory artifact and named pipe stager",
		},
		{
			ID:          "YARA-MEM-002",
			Name:        "Meterpreter_Reverse_TCP_Payload",
			Category:    "METERPRETER",
			ThreatScore: 90,
			MitreID:     "T1059.004",
			Patterns: [][]byte{
				[]byte("/bin/sh\x00-c\x00"),
				[]byte("socket;dup2;execve"),
				[]byte("metsrv.dll"),
				[]byte("ReflectiveLoader"),
			},
			Description: "Metasploit Meterpreter POSIX/DLL stager payload in memory",
		},
		{
			ID:          "YARA-MEM-003",
			Name:        "Linux_x64_Execve_Shellcode",
			Category:    "SHELLCODE",
			ThreatScore: 95,
			MitreID:     "T1055",
			Patterns: [][]byte{
				// \x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68 (standard 64-bit /bin/sh execve opcode)
				{0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68},
				// \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3 (standard 32-bit /bin/sh)
				{0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3},
			},
			Description: "Raw x86/x64 execve /bin/sh binary shellcode sequence",
		},
		{
			ID:          "YARA-MEM-004",
			Name:        "Obfuscated_Webshell_Memory_Buffer",
			Category:    "WEBSHELL",
			ThreatScore: 85,
			MitreID:     "T1505.003",
			Regex:       regexp.MustCompile(`(?i)(eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate|passthru\s*\(\s*\$_POST|b374k|c99shell|r57shell)`),
			Description: "Obfuscated PHP / Python / CGI in-memory webshell execution",
		},
		{
			ID:          "YARA-MEM-005",
			Name:        "Diamorphine_Reptile_LKM_Rootkit",
			Category:    "ROOTKIT",
			ThreatScore: 100,
			MitreID:     "T1014",
			Patterns: [][]byte{
				[]byte("diamorphine_secret"),
				[]byte("reptile_cmd"),
				[]byte("hooked_sys_call_table"),
				[]byte("give_root"),
			},
			Description: "Known Linux kernel rootkit hooking function signatures",
		},
	}
}

// ScanBuffer inspects a byte array against loaded in-memory signatures.
func (ms *MemoryScanner) ScanBuffer(data []byte, procName string, pid int) *YARADetection {
	atomic.AddUint64(&ms.scansTotal, 1)

	if len(data) == 0 {
		return nil
	}

	for _, rule := range ms.rules {
		// 1. Literal pattern match
		for _, pat := range rule.Patterns {
			if idx := bytes.Index(data, pat); idx != -1 {
				matchSnippet := fmt.Sprintf("Offset 0x%X: Matched pattern %q", idx, string(pat))
				return ms.triggerHit(rule, pid, procName, matchSnippet, fmt.Sprintf("0x%X", idx))
			}
		}

		// 2. Regex pattern match
		if rule.Regex != nil {
			if loc := rule.Regex.FindIndex(data); loc != nil {
				matchedSnippet := string(data[loc[0]:loc[1]])
				if len(matchedSnippet) > 60 {
					matchedSnippet = matchedSnippet[:60] + "..."
				}
				return ms.triggerHit(rule, pid, procName, matchedSnippet, fmt.Sprintf("0x%X", loc[0]))
			}
		}
	}

	return nil
}

// ScanProcessMemory inspects the anonymous and executable memory maps of a PID.
func (ms *MemoryScanner) ScanProcessMemory(pid int) (*YARADetection, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID %d", pid)
	}

	procName := ms.getProcessName(pid)
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s (permission or exited): %w", mapsPath, err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", memPath, err)
	}
	defer memFile.Close()

	// Parse maps for RWX or RX anonymous segments
	lines := strings.Split(string(mapsData), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		perms := fields[1]
		// Focus on executable or writable-executable memory (rwxp, r-xp)
		if !strings.Contains(perms, "x") {
			continue
		}

		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		startAddr, err1 := strconv.ParseInt(addrRange[0], 16, 64)
		endAddr, err2 := strconv.ParseInt(addrRange[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		size := endAddr - startAddr
		if size <= 0 || size > 8*1024*1024 { // Cap scan at 8MB per segment
			continue
		}

		buf := make([]byte, size)
		n, err := memFile.ReadAt(buf, startAddr)
		if err == nil && n > 0 {
			if hit := ms.ScanBuffer(buf[:n], procName, pid); hit != nil {
				hit.MemoryOffset = fmt.Sprintf("0x%X - 0x%X (%s)", startAddr, endAddr, perms)
				return hit, nil
			}
		}
	}

	return nil, nil
}

func (ms *MemoryScanner) triggerHit(rule YARARule, pid int, procName, matchedData, offset string) *YARADetection {
	atomic.AddUint64(&ms.hitsTotal, 1)

	hit := YARADetection{
		TimestampMs:  time.Now().UnixMilli(),
		PID:          pid,
		ProcessName:  procName,
		RuleID:       rule.ID,
		RuleName:     rule.Name,
		Category:     rule.Category,
		ThreatScore:  rule.ThreatScore,
		MitreID:      rule.MitreID,
		MatchedData:  matchedData,
		MemoryOffset: offset,
		ActionTaken:  "MEM_INSPECTION_ALERT",
	}

	ms.mu.Lock()
	ms.recentHits = append(ms.recentHits, hit)
	if len(ms.recentHits) > 50 {
		ms.recentHits = ms.recentHits[1:]
	}
	ms.mu.Unlock()

	log.Printf("[YARA_MEM] 🚨 IN-MEMORY THREAT DETECTED: %s (PID: %d, Rule: %s, Score: %d)",
		rule.Name, pid, rule.ID, rule.ThreatScore)

	if ms.onDetection != nil {
		go ms.onDetection(hit)
	}

	return &hit
}

func (ms *MemoryScanner) getProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	return fmt.Sprintf("proc_%d", pid)
}

// GetStats returns telemetry metrics for the in-memory scanner.
func (ms *MemoryScanner) GetStats() map[string]interface{} {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return map[string]interface{}{
		"scans_total":       atomic.LoadUint64(&ms.scansTotal),
		"hits_total":        atomic.LoadUint64(&ms.hitsTotal),
		"active_rules":      len(ms.rules),
		"recent_hits_count": len(ms.recentHits),
	}
}

// GetRecentHits returns the recent in-memory threat matches.
func (ms *MemoryScanner) GetRecentHits() []YARADetection {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	res := make([]YARADetection, len(ms.recentHits))
	copy(res, ms.recentHits)
	return res
}
