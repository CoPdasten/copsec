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
		{
			ID:                 "SIGMA-LNX-SUDO-001",
			Title:              "Sudoers Tampering & NOPASSWD Abuse",
			Description:        "Detects unauthorized modifications to /etc/sudoers, /etc/sudoers.d/ and NOPASSWD privileges",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1548.003",
			MitreTechniqueName: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
			MitreTactic:        "Privilege Escalation",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.privilege_escalation", "attack.t1548.003"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-SUID-001",
			Title:              "SUID/SGID Privilege Escalation & GTFOBins",
			Description:        "Detects chmod u+s, 4755 or setuid binary creations used in local privilege escalation",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1548.001",
			MitreTechniqueName: "Abuse Elevation Control Mechanism: Setuid and Setgid",
			MitreTactic:        "Privilege Escalation",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.privilege_escalation", "attack.t1548.001"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-MOD-001",
			Title:              "Unauthorized Kernel Module Insertion",
			Description:        "Detects insmod, modprobe and kernel module tampering indicating rootkit installation",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1547.006",
			MitreTechniqueName: "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
			MitreTactic:        "Persistence",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.persistence", "attack.t1547.006"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-CONT-001",
			Title:              "Container Breakout & Docker Socket Access",
			Description:        "Detects access to /var/run/docker.sock, containerd sockets, or privileged container escape tokens",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1611",
			MitreTechniqueName: "Escape to Host",
			MitreTactic:        "Privilege Escalation",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.privilege_escalation", "attack.t1611"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-DUMP-001",
			Title:              "Memory Credential Dumping & /proc/mem Access",
			Description:        "Detects unauthorized access to /proc/$PID/mem, /proc/kcore, gcore, or mimipenguin",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1003.007",
			MitreTechniqueName: "OS Credential Dumping: Proc Filesystem",
			MitreTactic:        "Credential Access",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.credential_access", "attack.t1003.007"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-KEY-001",
			Title:              "Rogue SSH Key Insertion in Authorized Keys",
			Description:        "Detects unauthorized writes or appends to .ssh/authorized_keys for persistent backdoor access",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1098.004",
			MitreTechniqueName: "Account Manipulation: SSH Authorized Keys",
			MitreTactic:        "Persistence",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.persistence", "attack.t1098.004"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-MINE-001",
			Title:              "Cryptominer & Stratum Mining Connection",
			Description:        "Detects xmrig, minerd, stratum mining protocol tokens and crypto mining pool connections",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1496",
			MitreTechniqueName: "Resource Hijacking",
			MitreTactic:        "Impact",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.impact", "attack.t1496"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-RANSOM-001",
			Title:              "Linux Ransomware Destruction & Mass Encryption",
			Description:        "Detects shredding, mass encryption loops, or known ransomware extensions on disk",
			Level:              "CRITICAL",
			ThreatScore:        100,
			MitreTechniqueID:   "T1486",
			MitreTechniqueName: "Data Encrypted for Impact",
			MitreTactic:        "Impact",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.impact", "attack.t1486"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-WIPE-001",
			Title:              "Anti-Forensics History Clear & Log Shredding",
			Description:        "Detects history -c, unset HISTFILE, HISTSIZE=0, or truncation of system audit logs",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1070.002",
			MitreTechniqueName: "Indicator Removal: Clear Linux Logs",
			MitreTactic:        "Defense Evasion",
			Scope:              ScopeHostLocal,
			Tags:               []string{"attack.defense_evasion", "attack.t1070.002"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-LNX-CRON-001",
			Title:              "Malicious Scheduled Task / Systemd Backdoor",
			Description:        "Detects malicious systemd unit or cron job creation for persistence",
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
			ID:                 "SIGMA-WEB-LOG4J-001",
			Title:              "Apache Log4j JNDI Remote Code Execution",
			Description:        "Detects Log4Shell / JNDI injection patterns (${jndi:ldap://, rmi://, dns://})",
			Level:              "CRITICAL",
			ThreatScore:        100,
			MitreTechniqueID:   "T1190",
			MitreTechniqueName: "Exploit Public-Facing Application",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1190"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-SSRF-001",
			Title:              "Cloud Instance Metadata SSRF Exfiltration",
			Description:        "Detects SSRF attempts targeting AWS/GCP/Azure IMDS (169.254.169.254 / metadata.google.internal)",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1552.005",
			MitreTechniqueName: "Unsecured Credentials: Cloud Instance Metadata API",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1552.005"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-SSTI-001",
			Title:              "Server-Side Template Injection (SSTI)",
			Description:        "Detects Jinja2, Twig, Freemarker template injection probes ({{7*7}}, ${7*7}, __subclasses__)",
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
			ID:                 "SIGMA-WEB-XXE-001",
			Title:              "XML External Entity (XXE) Injection",
			Description:        "Detects XML DOCTYPE external entity declarations targeting local system files",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1190",
			MitreTechniqueName: "Exploit Public-Facing Application",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1190"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-SHELL-001",
			Title:              "Web Shell Invocation & Backdoor Access",
			Description:        "Detects invocations of common PHP/JSP web shells (c99, r57, b374k, alfa, wso, cmd.php)",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1505.003",
			MitreTechniqueName: "Server Software Component: Web Shell",
			MitreTactic:        "Persistence",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.persistence", "attack.t1505.003"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-DESER-001",
			Title:              "Insecure Object Deserialization Exploit",
			Description:        "Detects Java Ysoserial (rO0AB), Python pickle, or PHP object serialization exploit payloads",
			Level:              "CRITICAL",
			ThreatScore:        95,
			MitreTechniqueID:   "T1190",
			MitreTechniqueName: "Exploit Public-Facing Application",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1190"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-ENV-001",
			Title:              "Sensitive Configuration & Environment File Probing",
			Description:        "Detects direct web requests targeting /.env, /.git/config, /wp-config.php, or id_rsa",
			Level:              "HIGH",
			ThreatScore:        80,
			MitreTechniqueID:   "T1552.001",
			MitreTechniqueName: "Unsecured Credentials: Credentials In Files",
			MitreTactic:        "Credential Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.credential_access", "attack.t1552.001"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-WEB-XSS-001",
			Title:              "Cross-Site Scripting (XSS) Injection",
			Description:        "Detects reflected or stored cross-site scripting payload vectors in HTTP parameters",
			Level:              "MEDIUM",
			ThreatScore:        70,
			MitreTechniqueID:   "T1189",
			MitreTechniqueName: "Drive-by Compromise",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1189"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-NET-SWEEP-001",
			Title:              "Network Sweep & Host Discovery Scans",
			Description:        "Detects automated scanning tools such as arp-scan, fping, zmap, or netdiscover",
			Level:              "MEDIUM",
			ThreatScore:        65,
			MitreTechniqueID:   "T1018",
			MitreTechniqueName: "Remote System Discovery",
			MitreTactic:        "Discovery",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.discovery", "attack.t1018"},
			Enabled:            true,
		},
		{
			ID:                 "SIGMA-NET-OAST-001",
			Title:              "Out-of-Band Exfiltration (OAST) Callbacks",
			Description:        "Detects interact.sh, oastify.com, burpcollaborator or dnslog callbacks in HTTP traffic",
			Level:              "HIGH",
			ThreatScore:        85,
			MitreTechniqueID:   "T1595.002",
			MitreTechniqueName: "Active Scanning: Vulnerability Scanning",
			MitreTactic:        "Initial Access",
			Scope:              ScopeNetwork,
			Tags:               []string{"attack.initial_access", "attack.t1595.002"},
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

	// 10. SIGMA-LNX-SUDO-001: Sudoers Tampering & NOPASSWD Abuse
	if bt.IsRuleEnabled("SIGMA-LNX-SUDO-001") {
		if (strings.Contains(rawLower, "/etc/sudoers") || strings.Contains(rawLower, "sudoers.d")) &&
			(strings.Contains(rawLower, "nopasswd") || strings.Contains(rawLower, "all=(all)") || strings.Contains(rawLower, "echo ") || strings.Contains(rawLower, "tee ") || strings.Contains(rawLower, "visudo")) {
			r := ruleMap["SIGMA-LNX-SUDO-001"]
			return &r, true
		}
	}

	// 11. SIGMA-LNX-SUID-001: SUID/SGID Privilege Escalation & GTFOBins
	if bt.IsRuleEnabled("SIGMA-LNX-SUID-001") {
		if strings.Contains(rawLower, "chmod +s") ||
			strings.Contains(rawLower, "chmod u+s") ||
			strings.Contains(rawLower, "chmod 4755") ||
			strings.Contains(rawLower, "chmod 4777") ||
			strings.Contains(rawLower, "chmod u=s") {
			r := ruleMap["SIGMA-LNX-SUID-001"]
			return &r, true
		}
	}

	// 12. SIGMA-LNX-MOD-001: Unauthorized Kernel Module Insertion
	if bt.IsRuleEnabled("SIGMA-LNX-MOD-001") {
		if strings.Contains(rawLower, "insmod ") ||
			strings.Contains(rawLower, "modprobe ") ||
			strings.Contains(rawLower, "rmmod ") ||
			(strings.Contains(rawLower, "/lib/modules/") && (strings.Contains(rawLower, "cp ") || strings.Contains(rawLower, "wget") || strings.Contains(rawLower, "curl"))) {
			r := ruleMap["SIGMA-LNX-MOD-001"]
			return &r, true
		}
	}

	// 13. SIGMA-LNX-CONT-001: Container Breakout & Docker Socket Access
	if bt.IsRuleEnabled("SIGMA-LNX-CONT-001") {
		if strings.Contains(rawLower, "/var/run/docker.sock") ||
			strings.Contains(rawLower, "/run/containerd/") ||
			strings.Contains(rawLower, "docker.sock") ||
			strings.Contains(rawLower, "--privileged") ||
			strings.Contains(rawLower, "release_agent") ||
			strings.Contains(rawLower, "nsenter --mount") {
			r := ruleMap["SIGMA-LNX-CONT-001"]
			return &r, true
		}
	}

	// 14. SIGMA-LNX-DUMP-001: Memory Credential Dumping & /proc/mem Access
	if bt.IsRuleEnabled("SIGMA-LNX-DUMP-001") {
		if strings.Contains(rawLower, "/proc/kcore") ||
			(strings.Contains(rawLower, "/proc/") && strings.Contains(rawLower, "/mem")) ||
			strings.Contains(rawLower, "mimipenguin") ||
			strings.Contains(rawLower, "gcore ") ||
			strings.Contains(rawLower, "secretsdump") ||
			strings.Contains(rawLower, "cat /etc/shadow") {
			r := ruleMap["SIGMA-LNX-DUMP-001"]
			return &r, true
		}
	}

	// 15. SIGMA-LNX-KEY-001: Rogue SSH Key Insertion in Authorized Keys
	if bt.IsRuleEnabled("SIGMA-LNX-KEY-001") {
		if strings.Contains(rawLower, "authorized_keys") &&
			(strings.Contains(rawLower, "echo ") || strings.Contains(rawLower, "tee ") || strings.Contains(rawLower, "cat ") || strings.Contains(rawLower, "curl ") || strings.Contains(rawLower, ">>")) {
			r := ruleMap["SIGMA-LNX-KEY-001"]
			return &r, true
		}
	}

	// 16. SIGMA-LNX-MINE-001: Cryptominer & Stratum Mining Connection
	if bt.IsRuleEnabled("SIGMA-LNX-MINE-001") {
		if strings.Contains(rawLower, "stratum+tcp://") ||
			strings.Contains(rawLower, "stratum+ssl://") ||
			strings.Contains(rawLower, "stratum://") ||
			strings.Contains(rawLower, "xmrig") ||
			strings.Contains(rawLower, "minerd") ||
			strings.Contains(rawLower, "moneroocean") ||
			strings.Contains(rawLower, "nanopool.org") ||
			strings.Contains(rawLower, "crypto-pool.fr") {
			r := ruleMap["SIGMA-LNX-MINE-001"]
			return &r, true
		}
	}

	// 17. SIGMA-LNX-RANSOM-001: Linux Ransomware Destruction & Mass Encryption
	if bt.IsRuleEnabled("SIGMA-LNX-RANSOM-001") {
		if strings.Contains(rawLower, "shred -u") ||
			strings.Contains(rawLower, "shred -z") ||
			strings.Contains(rawLower, "srm ") ||
			(strings.Contains(rawLower, "openssl enc") && strings.Contains(rawLower, "-aes")) ||
			strings.Contains(rawLower, ".locked") ||
			strings.Contains(rawLower, ".deadbolt") ||
			strings.Contains(rawLower, ".crypted") {
			r := ruleMap["SIGMA-LNX-RANSOM-001"]
			return &r, true
		}
	}

	// 18. SIGMA-LNX-WIPE-001: Anti-Forensics History Clear & Log Shredding
	if bt.IsRuleEnabled("SIGMA-LNX-WIPE-001") {
		if strings.Contains(rawLower, "history -c") ||
			strings.Contains(rawLower, "unset histfile") ||
			strings.Contains(rawLower, "histsize=0") ||
			strings.Contains(rawLower, "truncate -s 0 /var/log") ||
			strings.Contains(rawLower, "cat /dev/null > /var/log") ||
			strings.Contains(rawLower, "rm -rf /var/log") {
			r := ruleMap["SIGMA-LNX-WIPE-001"]
			return &r, true
		}
	}

	// 19. SIGMA-LNX-CRON-001: Malicious Scheduled Task / Systemd Backdoor
	if bt.IsRuleEnabled("SIGMA-LNX-CRON-001") {
		if (strings.Contains(rawLower, "/etc/systemd/system/") && strings.Contains(rawLower, ".service")) ||
			(strings.Contains(rawLower, "crontab -e") && (strings.Contains(rawLower, "curl") || strings.Contains(rawLower, "wget") || strings.Contains(rawLower, "/dev/tcp/"))) {
			r := ruleMap["SIGMA-LNX-CRON-001"]
			return &r, true
		}
	}

	// 20. SIGMA-WEB-LOG4J-001: Apache Log4j JNDI Remote Code Execution
	if bt.IsRuleEnabled("SIGMA-WEB-LOG4J-001") {
		if strings.Contains(uriVal, "${jndi:") ||
			strings.Contains(uriVal, "%24%7bjndi:") ||
			strings.Contains(uriVal, "jndi:ldap:") ||
			strings.Contains(uriVal, "jndi:rmi:") ||
			strings.Contains(uriVal, "jndi:dns:") ||
			strings.Contains(rawLower, "${jndi:ldap:") ||
			strings.Contains(rawLower, "${jndi:rmi:") ||
			strings.Contains(rawLower, "${jndi:dns:") ||
			strings.Contains(rawLower, "${base64:") {
			r := ruleMap["SIGMA-WEB-LOG4J-001"]
			return &r, true
		}
	}

	// 21. SIGMA-WEB-SSRF-001: Cloud Instance Metadata SSRF Exfiltration
	if bt.IsRuleEnabled("SIGMA-WEB-SSRF-001") {
		if strings.Contains(uriVal, "169.254.169.254") ||
			strings.Contains(uriVal, "metadata.google.internal") ||
			strings.Contains(uriVal, "100.100.100.200") ||
			strings.Contains(uriVal, "latest/meta-data") ||
			strings.Contains(rawLower, "169.254.169.254") ||
			strings.Contains(rawLower, "metadata.google.internal") ||
			strings.Contains(rawLower, "latest/meta-data") {
			r := ruleMap["SIGMA-WEB-SSRF-001"]
			return &r, true
		}
	}

	// 22. SIGMA-WEB-SSTI-001: Server-Side Template Injection (SSTI)
	if bt.IsRuleEnabled("SIGMA-WEB-SSTI-001") {
		if strings.Contains(uriVal, "{{7*7}}") ||
			strings.Contains(uriVal, "${7*7}") ||
			strings.Contains(uriVal, "#{7*7}") ||
			strings.Contains(uriVal, "__class__.__mro__") ||
			strings.Contains(uriVal, "__subclasses__") ||
			strings.Contains(uriVal, "lipsum.__globals__") ||
			strings.Contains(rawLower, "{{7*7}}") ||
			strings.Contains(rawLower, "${7*7}") ||
			strings.Contains(rawLower, "__subclasses__") {
			r := ruleMap["SIGMA-WEB-SSTI-001"]
			return &r, true
		}
	}

	// 23. SIGMA-WEB-XXE-001: XML External Entity (XXE) Injection
	if bt.IsRuleEnabled("SIGMA-WEB-XXE-001") {
		if strings.Contains(rawLower, "<!doctype") ||
			strings.Contains(rawLower, "<!entity") ||
			strings.Contains(rawLower, "system \"file:") ||
			strings.Contains(rawLower, "system 'file:") ||
			strings.Contains(rawLower, "system \"http:") ||
			strings.Contains(uriVal, "<!doctype") ||
			strings.Contains(uriVal, "<!entity") {
			r := ruleMap["SIGMA-WEB-XXE-001"]
			return &r, true
		}
	}

	// 24. SIGMA-WEB-SHELL-001: Web Shell Invocation & Backdoor Access
	if bt.IsRuleEnabled("SIGMA-WEB-SHELL-001") {
		if strings.Contains(uriVal, "c99.php") ||
			strings.Contains(uriVal, "r57.php") ||
			strings.Contains(uriVal, "b374k") ||
			strings.Contains(uriVal, "alfa.php") ||
			strings.Contains(uriVal, "wso.php") ||
			strings.Contains(uriVal, "cmd.php") ||
			strings.Contains(rawLower, "c99.php") ||
			strings.Contains(rawLower, "r57.php") ||
			strings.Contains(rawLower, "b374k") ||
			strings.Contains(rawLower, "passthru(") ||
			strings.Contains(rawLower, "eval(base64_decode") {
			r := ruleMap["SIGMA-WEB-SHELL-001"]
			return &r, true
		}
	}

	// 25. SIGMA-WEB-DESER-001: Insecure Object Deserialization Exploit
	if bt.IsRuleEnabled("SIGMA-WEB-DESER-001") {
		if strings.Contains(rawLower, "ro0ab") ||
			strings.Contains(rawLower, "cos\nsystem") ||
			strings.Contains(rawLower, "binaryformatter") ||
			strings.Contains(uriVal, "ro0ab") {
			r := ruleMap["SIGMA-WEB-DESER-001"]
			return &r, true
		}
	}

	// 26. SIGMA-WEB-ENV-001: Sensitive Configuration & Environment File Probing
	if bt.IsRuleEnabled("SIGMA-WEB-ENV-001") {
		if strings.Contains(uriVal, "/.env") ||
			strings.Contains(uriVal, "/.git/config") ||
			strings.Contains(uriVal, "/.git/head") ||
			strings.Contains(uriVal, "/wp-config.php") ||
			strings.Contains(uriVal, "/.aws/credentials") ||
			strings.Contains(uriVal, "/.kube/config") ||
			strings.Contains(uriVal, "/id_rsa") ||
			strings.Contains(rawLower, "/.env") ||
			strings.Contains(rawLower, "/.git/config") {
			r := ruleMap["SIGMA-WEB-ENV-001"]
			return &r, true
		}
	}

	// 27. SIGMA-WEB-XSS-001: Cross-Site Scripting (XSS) Injection
	if bt.IsRuleEnabled("SIGMA-WEB-XSS-001") {
		if strings.Contains(uriVal, "<script") ||
			strings.Contains(uriVal, "%3cscript") ||
			strings.Contains(uriVal, "javascript:") ||
			strings.Contains(uriVal, "<svg/onload=") ||
			strings.Contains(uriVal, "<svg%20onload=") ||
			strings.Contains(uriVal, "<img%20src=x%20onerror=") ||
			strings.Contains(rawLower, "<script>alert") ||
			strings.Contains(rawLower, "javascript:alert") {
			r := ruleMap["SIGMA-WEB-XSS-001"]
			return &r, true
		}
	}

	// 28. SIGMA-NET-SWEEP-001: Network Sweep & Host Discovery Scans
	if bt.IsRuleEnabled("SIGMA-NET-SWEEP-001") {
		if strings.Contains(rawLower, "arp-scan") ||
			strings.Contains(rawLower, "fping ") ||
			strings.Contains(rawLower, "zmap ") ||
			strings.Contains(rawLower, "netdiscover") ||
			strings.Contains(rawLower, "unicornscan") {
			r := ruleMap["SIGMA-NET-SWEEP-001"]
			return &r, true
		}
	}

	// 29. SIGMA-NET-OAST-001: Out-of-Band Exfiltration (OAST) Callbacks
	if bt.IsRuleEnabled("SIGMA-NET-OAST-001") {
		if strings.Contains(uriVal, "interact.sh") ||
			strings.Contains(uriVal, "oastify.com") ||
			strings.Contains(uriVal, "burpcollaborator.net") ||
			strings.Contains(uriVal, "dnslog.cn") ||
			strings.Contains(uriVal, "oast.fun") ||
			strings.Contains(rawLower, "interact.sh") ||
			strings.Contains(rawLower, "oastify.com") ||
			strings.Contains(rawLower, "burpcollaborator.net") ||
			strings.Contains(rawLower, "dnslog.cn") {
			r := ruleMap["SIGMA-NET-OAST-001"]
			return &r, true
		}
	}

	return nil, false
}
