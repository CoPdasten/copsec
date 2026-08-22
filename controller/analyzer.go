package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// RuleDefinition represents an enterprise threat signature loaded from rules.json.
type RuleDefinition struct {
	ID                 string   `json:"id"`
	Category           string   `json:"category"`
	RegexStr           string   `json:"regex"`
	CompiledRegex      *regexp.Regexp
	StatusCodes        []int    `json:"status_codes"`
	MitreTactic        string   `json:"mitre_tactic"`
	MitreTacticID      string   `json:"mitre_tactic_id"`
	MitreTechniqueID   string   `json:"mitre_technique_id"`
	MitreTechniqueName string   `json:"mitre_technique_name"`
	ThreatScore        int      `json:"threat_score"`
}

// RulesConfigFile represents the JSON rules file schema.
type RulesConfigFile struct {
	Rules []struct {
		ID                 string `json:"id"`
		Category           string `json:"category"`
		Regex              string `json:"regex"`
		StatusCodes        []int  `json:"status_codes"`
		MitreTactic        string `json:"mitre_tactic"`
		MitreTacticID      string `json:"mitre_tactic_id"`
		MitreTechniqueID   string `json:"mitre_technique_id"`
		MitreTechniqueName string `json:"mitre_technique_name"`
		ThreatScore        int    `json:"threat_score"`
	} `json:"rules"`
}

// RuleEngine inspects incoming log lines against compiled detection rules & entropy anomaly scores.
type RuleEngine struct {
	mu          sync.RWMutex
	rules       []RuleDefinition
	techNameMap map[string]string
	techTactMap map[string]string
}

// NewRuleEngine initializes the rule engine with compiled signatures.
func NewRuleEngine(rulesPath string) *RuleEngine {
	engine := &RuleEngine{
		techNameMap: make(map[string]string),
		techTactMap: make(map[string]string),
	}
	if err := engine.LoadRules(rulesPath); err != nil {
		log.Printf("[WARN] Failed to load %s (%v), loading built-in default signatures", rulesPath, err)
		engine.loadDefaults()
	}
	return engine
}

// LoadRules parses and compiles rules from rules.json.
func (e *RuleEngine) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg RulesConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = nil
	for _, r := range cfg.Rules {
		rawRegex := r.Regex
		if strings.HasPrefix(rawRegex, "(?i)") {
			rawRegex = rawRegex[4:]
		}
		compiled, err := regexp.Compile("(?i)" + rawRegex)
		if err != nil {
			log.Printf("[WARN] Failed to compile regex for rule %s: %v", r.ID, err)
			continue
		}

		score := r.ThreatScore
		if score == 0 {
			score = 50
		}

		name := r.MitreTechniqueName
		if name == "" {
			name = r.ID
		}
		tactic := r.MitreTactic
		if tactic == "" {
			tactic = "Initial Access"
		}

		e.techNameMap[r.MitreTechniqueID] = name
		e.techTactMap[r.MitreTechniqueID] = tactic

		e.rules = append(e.rules, RuleDefinition{
			ID:                 r.ID,
			Category:           r.Category,
			RegexStr:           r.Regex,
			CompiledRegex:      compiled,
			StatusCodes:        r.StatusCodes,
			MitreTactic:        tactic,
			MitreTacticID:      r.MitreTacticID,
			MitreTechniqueID:   r.MitreTechniqueID,
			MitreTechniqueName: name,
			ThreatScore:        score,
		})
	}

	log.Printf("[INFO] Rule Engine loaded %d enterprise MITRE signatures", len(e.rules))
	return nil
}

func (e *RuleEngine) loadDefaults() {
	e.mu.Lock()
	defer e.mu.Unlock()

	defaultSignatures := []struct {
		id      string
		techID  string
		name    string
		tactic  string
		regex   string
		score   int
	}{
		{"t1190-exploit-sqli-rce", "T1190", "Exploit Public-Facing App", "Initial Access", `(?i)(union\s+select|select\s+.*from|concat\(|'--|%27%20or%20|or\s+1=1|waitfor\s+delay|sleep\(|\$\{jndi:|ognl|classLoader)`, 85},
		{"t1059-unix-shell-execution", "T1059.004", "Command Execution", "Execution", `(?i)(/bin/(sh|bash)|curl\s+https?://.*\|\s*(sh|bash)|;\s*(cat|id|whoami)\s+|\|\s*(cat|id)\s*|` + "`whoami`" + `|\$\(whoami\))`, 90},
		{"t1203-client-exploitation-ssti", "T1203", "Client Exploitation (SSTI)", "Execution", `(?i)(\{\{\s*(7\*7|config|self|request).*\}\}|\$\{\s*(7\*7|application).*\})`, 75},
		{"t1078-valid-accounts-root", "T1078", "Valid Accounts (Root Login)", "Persistence", `(?i)(Accepted (password|publickey) for root from)`, 50},
		{"t1053-cron-persistence", "T1053.003", "Cron Persistence", "Persistence", `(?i)(crontab\s+-e|/etc/cron\.)`, 70},
		{"t1548-abuse-elevation", "T1548.001", "Setuid/Sudoers Abuse", "Privilege Escalation", `(?i)(chmod\s+(\+s|[0-7]?[421]7[0-7]{2})\s+|/etc/sudoers\s+)`, 85},
		{"t1027-obfuscated-payload", "T1027", "Obfuscated Payload", "Defense Evasion", `(?i)(%25[0-9a-f]{2}|\\x[0-9a-f]{2}|base64_decode\s*\(|eval\s*\(|String\.fromCharCode)`, 65},
		{"t1070-clear-command-history", "T1070.003", "Clear History/Logs", "Defense Evasion", `(?i)(history\s+-c|unset\s+HISTFILE|rm\s+-rf\s+/var/log/)`, 90},
		{"t1562-impair-defenses", "T1562.001", "Disable Defense Tools", "Defense Evasion", `(?i)(systemctl\s+(stop|disable)\s+(ufw|iptables|copsec)|iptables\s+-F)`, 95},
		{"t1110-password-brute-forcing", "T1110.001", "Password Brute Force", "Credential Access", `(?i)(Failed password for (invalid user )?[a-zA-Z0-9_.-]+ from \d+\.\d+\.\d+\.\d+|Invalid user [a-zA-Z0-9_.-]+ from \d+\.\d+\.\d+\.\d+)`, 60},
		{"t1003-os-credential-dumping", "T1003.008", "OS Credential Dumping", "Credential Access", `(?i)(cat\s+/etc/shadow|/etc/security/opasswd|secretsdump)`, 90},
		{"t1552-unsecured-credentials", "T1552.001", "Unsecured Credentials", "Credential Access", `(?i)(/\.env|/wp-config\.php|/\.git/config|/id_rsa)`, 70},
		{"t1595-vulnerability-scanning", "T1595.002", "Active Vulnerability Scan", "Reconnaissance", `(?i)(sqlmap/|nikto/|nuclei|acunetix|gobuster/|dirsearch|wpscan|masscan/)`, 55},
		{"t1082-system-information-discovery", "T1082", "System Info Discovery", "Discovery", `(?i)(uname\s+-a|cat\s+/proc/version|lscpu)`, 50},
		{"t1087-account-discovery", "T1087.001", "Account Discovery", "Discovery", `(?i)(/etc/passwd\b|getent\s+passwd|cat\s+/etc/group)`, 60},
		{"t1046-network-service-discovery", "T1046", "Network Service Discovery", "Discovery", `(?i)(nmap\s+-|masscan\s+-|netstat\s+-tulpn)`, 50},
		{"t1071-c2-malicious-user-agents", "T1071.001", "C2 Web Protocols", "Command and Control", `(?i)(CobaltStrike|Metasploit|Empire/|Havoc|Sliver)`, 90},
		{"t1041-exfiltration-c2-channel", "T1041", "Exfiltration Over C2", "Exfiltration", `(?i)(POST\s+/upload.*\\.tar\\.gz|POST\s+/api/exfil)`, 85},
		{"t1567-cloud-metadata-exfiltration", "T1567", "Cloud Metadata Exfil", "Exfiltration", `(?i)(169\.254\.169\.254|metadata\.google\.internal)`, 80},
	}

	for _, s := range defaultSignatures {
		compiled, err := regexp.Compile(s.regex)
		if err == nil {
			e.techNameMap[s.techID] = s.name
			e.techTactMap[s.techID] = s.tactic
			e.rules = append(e.rules, RuleDefinition{
				ID:                 s.id,
				MitreTechniqueID:   s.techID,
				MitreTechniqueName: s.name,
				MitreTactic:        s.tactic,
				CompiledRegex:      compiled,
				ThreatScore:        s.score,
			})
		}
	}
}

// GetTechniqueMeta returns technique name and tactic for TUI rendering.
func (e *RuleEngine) GetTechniqueMeta(techID string) (name, tactic string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	name, ok := e.techNameMap[techID]
	if !ok {
		name = techID
	}
	tactic, ok2 := e.techTactMap[techID]
	if !ok2 {
		tactic = "Threat Intel"
	}
	return name, tactic
}

// CalculateShannonEntropy measures data randomness in strings.
func CalculateShannonEntropy(input string) float64 {
	if len(input) == 0 {
		return 0.0
	}
	charCounts := make(map[rune]int)
	for _, char := range input {
		charCounts[char]++
	}

	total := float64(len(input))
	entropy := 0.0
	for _, count := range charCounts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var hexEscapeRegex = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
var unicodeEscapeRegex = regexp.MustCompile(`\\u00([0-9a-fA-F]{2})`)

// NormalizePayload decodes multi-stage URL encodings and hex bypasses.
func NormalizePayload(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err == nil {
		if doubleDecoded, err2 := url.QueryUnescape(decoded); err2 == nil {
			decoded = doubleDecoded
		}
	} else {
		decoded = raw
	}

	// Hex unescape (\x2e -> .)
	decoded = hexEscapeRegex.ReplaceAllStringFunc(decoded, func(m string) string {
		bytes, err := hex.DecodeString(m[2:])
		if err == nil && len(bytes) == 1 {
			return string(bytes)
		}
		return m
	})

	// Unicode unescape (\u002e -> .)
	decoded = unicodeEscapeRegex.ReplaceAllStringFunc(decoded, func(m string) string {
		bytes, err := hex.DecodeString(m[4:])
		if err == nil && len(bytes) == 1 {
			return string(bytes)
		}
		return m
	})

	return decoded
}

// IsNoisyLog filters background systemd, cron sessions, and tailscale heartbeat lines.
func IsNoisyLog(rawLine string) bool {
	lower := strings.ToLower(rawLine)
	if strings.Contains(lower, "tailscaled") ||
		strings.Contains(lower, "magicsock") ||
		strings.Contains(lower, "open-conn-track") ||
		strings.Contains(lower, "sysstat-collect") ||
		strings.Contains(lower, "systemd-resolved") ||
		strings.Contains(lower, "systemd-logind") ||
		strings.Contains(lower, "systemd[") ||
		strings.Contains(lower, "pam_unix(sudo:session)") ||
		strings.Contains(lower, "pam_unix(cron:session)") ||
		strings.Contains(lower, "session closed for user") ||
		(strings.Contains(lower, "cron[") && strings.Contains(lower, "session closed")) ||
		(strings.Contains(lower, "session opened for user root") && strings.Contains(lower, "by (uid=0)")) ||
		strings.Contains(lower, "starting clean php session") {
		return true
	}
	return false
}

// Analyze inspects the raw log line and returns rule matching details + Shannon entropy anomalies.
func (e *RuleEngine) Analyze(rawLine string, statusCode int, source string) (ruleID, techID string, score int, matched bool) {
	if IsNoisyLog(rawLine) {
		return "", "", 0, false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	normalized := NormalizePayload(rawLine)

	// 1. Signature Inspection
	for _, r := range e.rules {
		if source == "ssh" && r.Category != "ssh" && r.Category != "credential-access" && r.Category != "privilege-escalation" {
			if r.Category == "web" || r.Category == "exfiltration" {
				continue
			}
		}

		if len(r.StatusCodes) > 0 && statusCode > 0 {
			statusMatch := false
			for _, code := range r.StatusCodes {
				if code == statusCode {
					statusMatch = true
					break
				}
			}
			if !statusMatch {
				continue
			}
		}

		if r.CompiledRegex.MatchString(normalized) || r.CompiledRegex.MatchString(rawLine) {
			return r.ID, r.MitreTechniqueID, r.ThreatScore, true
		}
	}

	// 2. Heuristic Shannon Entropy Anomaly Inspection
	entropy := CalculateShannonEntropy(normalized)
	if entropy > 4.6 && len(normalized) > 30 && (statusCode == 400 || statusCode == 403 || statusCode == 404 || statusCode == 500) {
		return "heuristic-high-entropy-anomaly", "T1027", 65, true
	}

	return "", "", 0, false
}
