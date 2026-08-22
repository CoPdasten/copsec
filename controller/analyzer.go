package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// RuleDefinition represents an enterprise threat signature loaded from rules.json.
type RuleDefinition struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	RegexStr         string   `json:"regex"`
	CompiledRegex    *regexp.Regexp
	StatusCodes      []int    `json:"status_codes"`
	MitreTactic      string   `json:"mitre_tactic"`
	MitreTacticID    string   `json:"mitre_tactic_id"`
	MitreTechniqueID string   `json:"mitre_technique_id"`
	MitreTechniqueName string `json:"mitre_technique_name"`
	ThreatScore      int      `json:"threat_score"`
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

// RuleEngine inspects incoming log lines against compiled detection rules.
type RuleEngine struct {
	mu    sync.RWMutex
	rules []RuleDefinition
}

// NewRuleEngine initializes the rule engine with compiled signatures.
func NewRuleEngine(rulesPath string) *RuleEngine {
	engine := &RuleEngine{}
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
		// Prefix with case-insensitive flag in Go regexp
		compiled, err := regexp.Compile("(?i)" + rawRegex)
		if err != nil {
			log.Printf("[WARN] Failed to compile regex for rule %s: %v", r.ID, err)
			continue
		}

		score := r.ThreatScore
		if score == 0 {
			score = 50
		}

		e.rules = append(e.rules, RuleDefinition{
			ID:                 r.ID,
			Category:           r.Category,
			RegexStr:           r.Regex,
			CompiledRegex:      compiled,
			StatusCodes:        r.StatusCodes,
			MitreTactic:        r.MitreTactic,
			MitreTacticID:      r.MitreTacticID,
			MitreTechniqueID:   r.MitreTechniqueID,
			MitreTechniqueName: r.MitreTechniqueName,
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
		regex   string
		score   int
	}{
		{"t1190-exploit-sqli-rce", "T1190", `(?i)(union\s+select|select.*from|concat\(|'--|%27%20or%20|or\s+1=1|waitfor\s+delay|sleep\(|\$\{jndi:|ognl|classLoader)`, 85},
		{"t1059-unix-shell-execution", "T1059.004", `(?i)(/bin/(sh|bash)|curl\s+.*\|\s*(sh|bash)|;\s*(cat|id|whoami)|\|\s*(cat|id))`, 90},
		{"t1078-valid-accounts-root", "T1078", `(?i)(Accepted password for root|Accepted publickey for root)`, 50},
		{"t1053-cron-persistence", "T1053.003", `(?i)(crontab\s+-e|/etc/cron\.)`, 70},
		{"t1548-abuse-elevation", "T1548.001", `(?i)(chmod\s+(\+s|[0-7]?[421]7[0-7]{2})|/etc/sudoers)`, 85},
		{"t1027-obfuscated-payload", "T1027", `(?i)(%25[0-9a-f]{2}|\\x[0-9a-f]{2}|base64_decode|eval\s*\()`, 65},
		{"t1070-clear-command-history", "T1070.003", `(?i)(history\s+-c|unset\s+HISTFILE|rm\s+-rf\s+/var/log)`, 90},
		{"t1562-impair-defenses", "T1562.001", `(?i)(systemctl\s+(stop|disable)\s+(ufw|iptables|copsec)|iptables\s+-F)`, 95},
		{"t1110-password-brute-forcing", "T1110.001", `(?i)(Failed password for|Invalid user|authentication failure)`, 60},
		{"t1003-os-credential-dumping", "T1003.008", `(?i)(/etc/shadow|/etc/security/opasswd|secretsdump)`, 90},
		{"t1552-unsecured-credentials", "T1552.001", `(?i)(\.env|wp-config\.php|\.git/config|id_rsa)`, 70},
		{"t1595-vulnerability-scanning", "T1595.002", `(?i)(sqlmap|nikto|nuclei|acunetix|gobuster|dirsearch|wpscan|masscan)`, 55},
		{"t1082-system-information-discovery", "T1082", `(?i)(uname\s+-a|cat\s+/proc/version|lscpu)`, 50},
		{"t1087-account-discovery", "T1087.001", `(?i)(/etc/passwd|getent\s+passwd|cat\s+/etc/group)`, 60},
		{"t1046-network-service-discovery", "T1046", `(?i)(nmap\s+|masscan\s+|netstat\s+-tulpn)`, 50},
		{"t1071-c2-malicious-user-agents", "T1071.001", `(?i)(CobaltStrike|Metasploit|Empire|Havoc|Sliver)`, 90},
		{"t1041-exfiltration-c2-channel", "T1041", `(?i)(POST\s+/upload.*\.tar\.gz|POST\s+/api/exfil)`, 85},
		{"t1567-cloud-metadata-exfiltration", "T1567", `(?i)(169\.254\.169\.254|metadata\.google\.internal)`, 80},
	}

	for _, s := range defaultSignatures {
		compiled, err := regexp.Compile(s.regex)
		if err == nil {
			e.rules = append(e.rules, RuleDefinition{
				ID:               s.id,
				MitreTechniqueID: s.techID,
				CompiledRegex:    compiled,
				ThreatScore:      s.score,
			})
		}
	}
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

// IsNoisyLog filters background systemd / tailscale heartbeat lines.
func IsNoisyLog(rawLine string) bool {
	if strings.Contains(rawLine, "systemd-resolved") ||
		strings.Contains(rawLine, "tailscaled: magicsock") ||
		strings.Contains(rawLine, "CRON[") && strings.Contains(rawLine, "session closed") ||
		strings.Contains(rawLine, "systemd: Starting Clean php session pool") {
		return true
	}
	return false
}

// Analyze inspects the raw log line and returns rule matching details.
func (e *RuleEngine) Analyze(rawLine string, statusCode int, source string) (ruleID, techID string, score int, matched bool) {
	if IsNoisyLog(rawLine) {
		return "", "", 0, false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	normalized := NormalizePayload(rawLine)

	for _, r := range e.rules {
		// Category targeting
		if source == "ssh" && r.Category != "ssh" && r.Category != "credential-access" && r.Category != "privilege-escalation" {
			// Skip irrelevant web signatures on ssh logs
			if r.Category == "web" || r.Category == "exfiltration" {
				continue
			}
		}

		// Check status code constraints if defined
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

	return "", "", 0, false
}
