package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// RuleDefinition represents a threat signature loaded from rules.json.
type RuleDefinition struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	RegexStr         string   `json:"regex"`
	CompiledRegex    *regexp.Regexp
	StatusCodes      []int    `json:"status_codes"`
	MitreTactic      string   `json:"mitre_tactic"`
	MitreTechniqueID string   `json:"mitre_technique_id"`
	ThreatScore      int      `json:"threat_score"`
}

// RulesConfigFile represents the JSON rules file schema.
type RulesConfigFile struct {
	Rules []struct {
		ID               string `json:"id"`
		Category         string `json:"category"`
		Regex            string `json:"regex"`
		StatusCodes      []int  `json:"status_codes"`
		MitreTactic      string `json:"mitre_tactic"`
		MitreTechniqueID string `json:"mitre_technique_id"`
		Mitre            struct {
			TechniqueID string `json:"technique_id"`
			Tactic      string `json:"tactic"`
		} `json:"mitre"`
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

		techID := r.MitreTechniqueID
		if techID == "" {
			techID = r.Mitre.TechniqueID
		}

		score := 25
		cat := strings.ToLower(r.Category)
		if cat == "rce" || strings.Contains(r.ID, "rce") || strings.Contains(r.ID, "command") {
			score = 85
		} else if cat == "sqli" || strings.Contains(r.ID, "sqli") {
			score = 75
		} else if cat == "ssrf" || strings.Contains(r.ID, "ssrf") {
			score = 70
		} else if cat == "lfi" || cat == "xxe" || strings.Contains(r.ID, "traversal") {
			score = 65
		} else if cat == "web" || strings.Contains(r.ID, "scan") || strings.Contains(r.ID, "bot") {
			score = 45
		} else if cat == "ssh" || strings.Contains(r.ID, "password") {
			score = 50
		}

		e.rules = append(e.rules, RuleDefinition{
			ID:               r.ID,
			Category:         r.Category,
			RegexStr:         r.Regex,
			CompiledRegex:    compiled,
			StatusCodes:      r.StatusCodes,
			MitreTactic:      r.MitreTactic,
			MitreTechniqueID: techID,
			ThreatScore:      score,
		})
	}

	log.Printf("[INFO] Rule Engine loaded %d compiled threat signatures", len(e.rules))
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
		{"rce-command-injection", "T1059.004", `(?i)(;\s*(cat|id|whoami|sh)|\|\s*id|\$\(whoami\)|/bin/(sh|bash)|nc\s+.*-e|/dev/tcp/)`, 85},
		{"sqli-attempt", "T1190", `(?i)(union\s+select|select%20|concat\(|'--|%27%20or%20|or\s+1=1|sleep\()`, 75},
		{"ssrf-metadata-attempt", "T1552.005", `(?i)(169\.254\.169\.254|metadata\.google|latest/meta-data)`, 70},
		{"path-traversal-lfi", "T1059", `(?i)(\.\./|%2e%2e%2f|/etc/passwd|/etc/shadow)`, 65},
		{"ssh-password-spraying", "T1110.001", `(?i)(Failed password for|Invalid user|authentication failure)`, 50},
		{"nginx-web-scan", "T1595.002", `(?i)(/admin|\.env|wp-login\.php|config\.php|\.git|\.htaccess|phpmyadmin)`, 45},
		{"bad-bot-scanner", "T1595.002", `(?i)(sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|masscan)`, 45},
		{"obfuscated-payload", "T1027", `(?i)(%25[0-9a-f]{2}|\\x[0-9a-f]{2}|\\\\u00[0-9a-f]{2}|base64_decode|eval\s*\()`, 60},
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

// NormalizePayload decodes multi-stage URL encodings.
func NormalizePayload(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err == nil {
		// Try second pass for double-encoded payloads (%252e%252e)
		if doubleDecoded, err2 := url.QueryUnescape(decoded); err2 == nil {
			return doubleDecoded
		}
		return decoded
	}
	return raw
}

// Analyze inspects the raw log line and returns rule matching details.
func (e *RuleEngine) Analyze(rawLine string, statusCode int) (ruleID, techID string, score int, matched bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	normalized := NormalizePayload(rawLine)

	for _, r := range e.rules {
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
