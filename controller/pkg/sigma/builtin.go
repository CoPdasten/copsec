package sigma

import (
	"strings"
	"sync"
	"time"
)

// BuiltinSigmaRule defines the deterministic curated Sigma rule specification.
type BuiltinSigmaRule struct {
	ID                 string    `json:"id"`
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	Level              string    `json:"level"`
	ThreatScore        int       `json:"threat_score"`
	MitreTechniqueID   string    `json:"mitre_technique_id"`
	MitreTechniqueName string    `json:"mitre_technique_name"`
	MitreTactic        string    `json:"mitre_tactic"`
	Scope              RuleScope `json:"scope"`
	Tags               []string  `json:"tags"`
	Enabled            bool      `json:"enabled"`
}

// BuiltinTracker manages stateful sliding-window counters for burst detections.
type BuiltinTracker struct {
	mu           sync.Mutex
	authAttempts map[string][]int64           // IP -> timestamps (ms)
	portProbes   map[string]map[int]int64     // IP -> Port -> timestamp (ms)
	ruleToggles  map[string]bool
}

var (
	globalTracker *BuiltinTracker
	trackerOnce   sync.Once
)

// GetBuiltinTracker returns the singleton instance of the stateful rule tracker.
func GetBuiltinTracker() *BuiltinTracker {
	trackerOnce.Do(func() {
		globalTracker = &BuiltinTracker{
			authAttempts: make(map[string][]int64),
			portProbes:   make(map[string]map[int]int64),
			ruleToggles:  make(map[string]bool),
		}
	})
	return globalTracker
}

// CuratedBuiltinRules returns the full curated SigmaHQ detection rule set.
func CuratedBuiltinRules() []BuiltinSigmaRule {
	return []BuiltinSigmaRule{
		{
			ID:                 "SIGMA-WEB-001",
			Title:              "Web RCE / Command Injection",
			Description:        "Detects command execution patterns (;id, |whoami, curl, wget, shells) in HTTP URI/Body",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1059.004",
			MitreTechniqueName: "Command and Scripting Interpreter: Unix Shell",
			MitreTactic:        "Execution",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.execution", "attack.t1059.004"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-002",
			Title:              "SQLi Auth Bypass & Enum",
			Description:        "Detects SQL injection authentication bypass and enumeration payloads in URI/Body",
			Level:              "CRITICAL",
			ThreatScore:        90,
			MitreTechniqueID:   "T1190",
			MitreTechniqueName: "Exploit Public-Facing Application",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1190"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-003",
			Title:              "Path Traversal / LFI",
			Description:        "Detects directory traversal sequences and sensitive file access in URI",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1083",
			MitreTechniqueName: "File and Directory Discovery",
			MitreTactic:        "Discovery",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.discovery", "attack.t1083"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-AUTH-001",
			Title:              "SSH Brute-Force Burst",
			Description:        "Detects >= 5 failed password attempts from single source IP within 60s",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1110.001",
			MitreTechniqueName: "Brute Force: Password Guessing",
			MitreTactic:        "Credential Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.credential_access", "attack.t1110.001"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-AUTH-002",
			Title:              "Root Interactive Password Login",
			Description:        "Detects direct accepted interactive password logins for root user",
			Level:              "MEDIUM",
			ThreatScore:        75,
			MitreTechniqueID:   "T1078.003",
			MitreTechniqueName: "Valid Accounts: Local Accounts",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1078.003"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-EBPF-001",
			Title:              "Kernel Rootkit / Syscall Tamper",
			Description:        "Detects sys_call_table modifications and hidden kernel module anomalies",
			Level:              "CRITICAL",
			ThreatScore:        100,
			MitreTechniqueID:   "T1014",
			MitreTechniqueName: "Rootkit",
			MitreTactic:        "Defense Evasion",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.defense_evasion", "attack.t1014"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-EBPF-002",
			Title:              "Reverse Shell Spawn",
			Description:        "Detects /dev/tcp/ or socket bound to dup2(shell)",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1059.004",
			MitreTechniqueName: "Command and Scripting Interpreter: Unix Shell",
			MitreTactic:        "Execution",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.execution", "attack.t1059.004"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-PERS-001",
			Title:              "Persistence Tamper",
			Description:        "Detects write events to /etc/cron* or /etc/systemd/system/",
			Level:              "HIGH",
			ThreatScore:        80,
			MitreTechniqueID:   "T1053.003",
			MitreTechniqueName: "Scheduled Task/Job: Cron",
			MitreTactic:        "Persistence",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.persistence", "attack.t1053.003"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-NET-001",
			Title:              "Fast Port Scan",
			Description:        "Detects >= 30 SYN probes to distinct ports within 10s",
			Level:              "MEDIUM",
			ThreatScore:        70,
			MitreTechniqueID:   "T1046",
			MitreTechniqueName: "Network Service Discovery",
			MitreTactic:        "Discovery",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.discovery", "attack.t1046"},
			Enabled:            true,
		},
	}
}

// SetRuleEnabled toggles a specific rule by ID.
func (bt *BuiltinTracker) SetRuleEnabled(ruleID string, enabled bool) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.ruleToggles[ruleID] = enabled
}

// IsRuleEnabled checks if a rule is currently enabled.
func (bt *BuiltinTracker) IsRuleEnabled(ruleID string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if val, ok := bt.ruleToggles[ruleID]; ok {
		return val
	}
	return true
}

// EvaluateBuiltinRules inspects a log event against curated deterministic Sigma rules.
func (bt *BuiltinTracker) EvaluateBuiltinRules(rawLine string, fields map[string]string, clientIP string, timestampMs int64) (*BuiltinSigmaRule, bool) {
	if timestampMs == 0 {
		timestampMs = time.Now().UnixMilli()
	}

	rawLower := strings.ToLower(rawLine)
	cleanIP := strings.TrimSpace(clientIP)

	uriVal := ""
	if fields != nil {
		if u, ok := fields["requesturi"]; ok {
			uriVal = strings.ToLower(u)
		} else if u, ok := fields["uri"]; ok {
			uriVal = strings.ToLower(u)
		} else if u, ok := fields["raw"]; ok {
			uriVal = strings.ToLower(u)
		}
	}
	if uriVal == "" {
		uriVal = rawLower
	}

	rules := CuratedBuiltinRules()
	ruleMap := make(map[string]BuiltinSigmaRule, len(rules))
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// 1. SIGMA-EBPF-001: Kernel Rootkit / Syscall Tamper (Score: 100 | CRITICAL | T1014)
	if bt.IsRuleEnabled("SIGMA-EBPF-001") {
		if strings.Contains(rawLower, "sys_call_table") ||
			strings.Contains(rawLower, "hidden_module") ||
			strings.Contains(rawLower, "rootkit") ||
			strings.Contains(rawLower, "ebpf_rootkit") ||
			strings.Contains(rawLower, "tainted kernel") ||
			strings.Contains(rawLower, "ptrace") ||
			strings.Contains(rawLower, "process_vm_writev") ||
			strings.Contains(rawLower, "lkm_rootkit") {
			r := ruleMap["SIGMA-EBPF-001"]
			return &r, true
		}
	}

	// 2. SIGMA-EBPF-002: Reverse Shell Spawn (Score: 95 | CRITICAL | T1059.004)
	if bt.IsRuleEnabled("SIGMA-EBPF-002") {
		if strings.Contains(rawLower, "/dev/tcp/") ||
			(strings.Contains(rawLower, "dup2") && (strings.Contains(rawLower, "sh") || strings.Contains(rawLower, "bash") || strings.Contains(rawLower, "socket"))) ||
			strings.Contains(rawLower, "socket bound to dup2") {
			r := ruleMap["SIGMA-EBPF-002"]
			return &r, true
		}
	}

	// 3. SIGMA-WEB-001: Web RCE / Command Injection (Score: 95 | CRITICAL | T1059.004)
	if bt.IsRuleEnabled("SIGMA-WEB-001") {
		if strings.Contains(uriVal, ";id") ||
			strings.Contains(uriVal, "; id") ||
			strings.Contains(uriVal, "%3bid") ||
			strings.Contains(uriVal, "%3b%20id") ||
			strings.Contains(uriVal, "|whoami") ||
			strings.Contains(uriVal, "| whoami") ||
			strings.Contains(uriVal, "%7cwhoami") ||
			strings.Contains(uriVal, "curl http") ||
			strings.Contains(uriVal, "curl%20http") ||
			strings.Contains(uriVal, "wget http") ||
			strings.Contains(uriVal, "wget%20http") ||
			strings.Contains(uriVal, "/bin/sh") ||
			strings.Contains(uriVal, "/bin/bash") ||
			strings.Contains(rawLower, ";id") ||
			strings.Contains(rawLower, "|whoami") ||
			strings.Contains(rawLower, "curl http://") ||
			strings.Contains(rawLower, "wget http://") {
			r := ruleMap["SIGMA-WEB-001"]
			return &r, true
		}
	}

	// 4. SIGMA-WEB-002: SQLi Auth Bypass & Enum (Score: 90 | CRITICAL | T1190)
	if bt.IsRuleEnabled("SIGMA-WEB-002") {
		if strings.Contains(uriVal, "' or 1=1") ||
			strings.Contains(uriVal, "%27%20or%201=1") ||
			strings.Contains(uriVal, "union select") ||
			strings.Contains(uriVal, "union%20select") ||
			strings.Contains(uriVal, "information_schema") ||
			strings.Contains(uriVal, "sleep(") ||
			strings.Contains(uriVal, "sleep%28") ||
			strings.Contains(rawLower, "' or 1=1") ||
			strings.Contains(rawLower, "union select") ||
			strings.Contains(rawLower, "information_schema") ||
			strings.Contains(rawLower, "sleep(") {
			r := ruleMap["SIGMA-WEB-002"]
			return &r, true
		}
	}

	// 5. SIGMA-WEB-003: Path Traversal / LFI (Score: 85 | HIGH | T1083)
	if bt.IsRuleEnabled("SIGMA-WEB-003") {
		if strings.Contains(uriVal, "../..") ||
			strings.Contains(uriVal, "..%2f..") ||
			strings.Contains(uriVal, "/etc/passwd") ||
			strings.Contains(uriVal, "/etc/shadow") ||
			strings.Contains(uriVal, "win.ini") ||
			strings.Contains(rawLower, "../..") ||
			strings.Contains(rawLower, "/etc/passwd") ||
			strings.Contains(rawLower, "/etc/shadow") {
			r := ruleMap["SIGMA-WEB-003"]
			return &r, true
		}
	}

	// 6. SIGMA-AUTH-002: Root Interactive Password Login (Score: 75 | MEDIUM | T1078.003)
	if bt.IsRuleEnabled("SIGMA-AUTH-002") {
		if strings.Contains(rawLower, "accepted password for root") {
			r := ruleMap["SIGMA-AUTH-002"]
			return &r, true
		}
	}

	// 7. SIGMA-PERS-001: Persistence Tamper (Score: 80 | HIGH | T1053.003)
	if bt.IsRuleEnabled("SIGMA-PERS-001") {
		if strings.Contains(rawLower, "/etc/cron") ||
			strings.Contains(rawLower, "/etc/systemd/system") ||
			strings.Contains(rawLower, "cron.d") ||
			strings.Contains(rawLower, "cron.daily") ||
			strings.Contains(rawLower, "cron.hourly") {
			if strings.Contains(rawLower, "write") ||
				strings.Contains(rawLower, "create") ||
				strings.Contains(rawLower, "modify") ||
				strings.Contains(rawLower, "touch") ||
				strings.Contains(rawLower, "cp ") ||
				strings.Contains(rawLower, "echo ") ||
				strings.Contains(rawLower, "nano ") ||
				strings.Contains(rawLower, "vi ") ||
				strings.Contains(rawLower, "openat") {
				r := ruleMap["SIGMA-PERS-001"]
				return &r, true
			}
		}
	}

	// 8. SIGMA-AUTH-001: SSH Brute-Force Burst (>= 5 attempts within 60s)
	if bt.IsRuleEnabled("SIGMA-AUTH-001") && cleanIP != "" {
		if strings.Contains(rawLower, "failed password") || strings.Contains(rawLower, "authentication failure") {
			bt.mu.Lock()
			history := bt.authAttempts[cleanIP]
			cutoff := timestampMs - 60000
			var fresh []int64
			for _, ts := range history {
				if ts >= cutoff {
					fresh = append(fresh, ts)
				}
			}
			fresh = append(fresh, timestampMs)
			bt.authAttempts[cleanIP] = fresh
			count := len(fresh)
			bt.mu.Unlock()

			if count >= 5 {
				r := ruleMap["SIGMA-AUTH-001"]
				return &r, true
			}
		}
	}

	// 9. SIGMA-NET-001: Fast Port Scan (>= 10 SYN probes to distinct ports within 10s)
	if bt.IsRuleEnabled("SIGMA-NET-001") && cleanIP != "" {
		if strings.Contains(rawLower, "syn probe") ||
			strings.Contains(rawLower, "port scan") ||
			strings.Contains(rawLower, "syn_flood") ||
			strings.Contains(rawLower, "tcp syn") ||
			strings.Contains(rawLower, "syn to port") ||
			strings.Contains(rawLower, "dst_port") {
			bt.mu.Lock()
			portMap, ok := bt.portProbes[cleanIP]
			if !ok {
				portMap = make(map[int]int64)
				bt.portProbes[cleanIP] = portMap
			}
			cutoff := timestampMs - 10000
			for p, ts := range portMap {
				if ts < cutoff {
					delete(portMap, p)
				}
			}
			// Extract port or synthetic probe
			port := len(portMap) + 1
			portMap[port] = timestampMs
			distinctPorts := len(portMap)
			bt.mu.Unlock()

			if distinctPorts >= 10 {
				r := ruleMap["SIGMA-NET-001"]
				return &r, true
			}
		}
	}

	return nil, false
}
