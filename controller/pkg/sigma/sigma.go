package sigma

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

// Curated SigmaHQ Detection-as-Code Rule Definitions (Embedded)
//
//go:embed rules/sigma-linux-revshell.yml
var RevshellRuleYAML string

//go:embed rules/sigma-linux-evasion.yml
var EvasionRuleYAML string

//go:embed rules/sigma-linux-persistence.yml
var PersistenceRuleYAML string

//go:embed rules/sigma-web-advanced.yml
var WebAdvancedRuleYAML string

// CuratedRulePack returns all embedded enterprise-grade SigmaHQ rules.
func GetCuratedRulePack() []string {
	return []string{
		strings.TrimSpace(RevshellRuleYAML),
		strings.TrimSpace(EvasionRuleYAML),
		strings.TrimSpace(PersistenceRuleYAML),
		strings.TrimSpace(WebAdvancedRuleYAML),
	}
}

// FieldAliases maps standard Sigma fields to normalized field keys.
var FieldAliases = map[string][]string{
	"commandline":     {"commandline", "cmdline", "command", "process.command_line", "exec", "arguments"},
	"rawlog":          {"rawlog", "raw", "_raw", "message", "log", "line"},
	"requesturi":      {"requesturi", "uri", "url", "path", "request", "cs-uri-stem", "cs-uri-query"},
	"httpmethod":      {"httpmethod", "method", "cs-method", "verb"},
	"sourceip":        {"sourceip", "src_ip", "client_ip", "c-ip", "source.ip", "src", "ip"},
	"destinationport": {"destinationport", "dest_port", "dst_port", "dport", "destination.port", "port"},
}

// ResolveField finds the corresponding value in a field map using standard Sigma aliases.
func ResolveField(fields map[string]string, targetField string) (string, bool) {
	if fields == nil {
		return "", false
	}

	targetLower := strings.ToLower(strings.TrimSpace(targetField))
	if val, ok := fields[targetLower]; ok && val != "" {
		return val, true
	}

	// Lookup aliases
	for canonical, aliases := range FieldAliases {
		if targetLower == canonical {
			for _, alias := range aliases {
				if val, ok := fields[alias]; ok && val != "" {
					return val, true
				}
			}
		}
		for _, alias := range aliases {
			if targetLower == alias {
				if val, ok := fields[canonical]; ok && val != "" {
					return val, true
				}
				for _, a := range aliases {
					if val, ok := fields[a]; ok && val != "" {
						return val, true
					}
				}
			}
		}
	}

	return "", false
}

// RuleScope categorizes rules into network-originating vs host-local executions.
type RuleScope string

const (
	ScopeNetwork   RuleScope = "SCOPE_NETWORK"    // Network-level triggers with authentic remote SourceIP (permits network SOAR quarantines)
	ScopeHostLocal RuleScope = "SCOPE_HOST_LOCAL" // Host-local OS events without remote socket (inhibits network-level quarantines)
)

// DetermineRuleScope classifies a rule based on its ID, logsource, or tags.
func DetermineRuleScope(ruleID, category, product, service string, tags []string) RuleScope {
	idLower := strings.ToLower(ruleID)
	catLower := strings.ToLower(category)
	prodLower := strings.ToLower(product)
	svcLower := strings.ToLower(service)

	// Explicit tag checks
	for _, tag := range tags {
		tLower := strings.ToLower(tag)
		if tLower == "scope.host_local" || tLower == "scope.host" || tLower == "scope.local" {
			return ScopeHostLocal
		}
		if tLower == "scope.network" || tLower == "scope.net" {
			return ScopeNetwork
		}
	}

	// Host-local known IDs
	if idLower == "sudo_execution" ||
		idLower == "cron_tamper" ||
		idLower == "cron_persistence" ||
		idLower == "fim_drift" ||
		idLower == "fim_tampering" ||
		idLower == "rootkit_lkm" ||
		idLower == "ebpf_rootkit" ||
		idLower == "process_injection" ||
		idLower == "sigma-linux-persistence" ||
		idLower == "sigma-linux-evasion" ||
		idLower == "sigma-linux-revshell" ||
		idLower == "sigma-credential-dumping" ||
		idLower == "sigma-impair-defenses" ||
		strings.HasPrefix(idLower, "t1070") ||
		strings.HasPrefix(idLower, "t1562") ||
		strings.HasPrefix(idLower, "t1003") ||
		strings.HasPrefix(idLower, "t1053") ||
		strings.HasPrefix(idLower, "t1548") ||
		strings.HasPrefix(idLower, "t1082") ||
		strings.HasPrefix(idLower, "t1087") {
		return ScopeHostLocal
	}

	// Network known log sources and categories
	if catLower == "webserver" ||
		catLower == "firewall" ||
		catLower == "ids" ||
		catLower == "network" ||
		catLower == "proxy" ||
		svcLower == "sshd" ||
		svcLower == "suricata" ||
		svcLower == "snort" ||
		svcLower == "nginx" ||
		svcLower == "apache" ||
		strings.Contains(idLower, "sqli") ||
		strings.Contains(idLower, "rce") ||
		strings.Contains(idLower, "bruteforce") ||
		strings.Contains(idLower, "scanner") ||
		strings.Contains(idLower, "oast") ||
		strings.Contains(idLower, "web") {
		return ScopeNetwork
	}

	// Host-local log sources
	if catLower == "process_creation" ||
		catLower == "file_change" ||
		catLower == "kernel" ||
		catLower == "audit" ||
		catLower == "syslog" ||
		prodLower == "linux" {
		return ScopeHostLocal
	}

	return ScopeNetwork
}

// RuleMetadata holds high-level summary info of a compiled Sigma rule.
type RuleMetadata struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Level       string    `json:"level"`
	ThreatScore int       `json:"threat_score"`
	MitreID     string    `json:"mitre_id"`
	Tags        []string  `json:"tags"`
	Scope       RuleScope `json:"scope"`
}

// CuratedCatalog keeps an in-memory catalog of all built-in curated detection rules.
type CuratedCatalog struct {
	mu    sync.RWMutex
	rules []RuleMetadata
}

var (
	defaultCatalog *CuratedCatalog
	catalogOnce    sync.Once
)

// GetDefaultCatalog returns the singleton catalog.
func GetDefaultCatalog() *CuratedCatalog {
	catalogOnce.Do(func() {
		defaultCatalog = &CuratedCatalog{
			rules: []RuleMetadata{
				{
					ID:          "sigma-linux-revshell",
					Title:       "Linux Interactive Reverse Shell and C2 Activity",
					Description: "Detects interactive bash, netcat, socat, python, perl, ruby, and encoded reverse shells",
					Level:       "critical",
					ThreatScore: 95,
					MitreID:     "T1059.004",
					Tags:        []string{"attack.execution", "attack.t1059.004", "attack.t1071"},
					Scope:       ScopeHostLocal,
				},
				{
					ID:          "sigma-linux-evasion",
					Title:       "Linux Defense Evasion and Anti-Forensics Activity",
					Description: "Detects history manipulation, log scrubbing, defense impairment, and timestamp spoofing",
					Level:       "critical",
					ThreatScore: 95,
					MitreID:     "T1070",
					Tags:        []string{"attack.defense_evasion", "attack.t1070", "attack.t1562"},
					Scope:       ScopeHostLocal,
				},
				{
					ID:          "sigma-linux-persistence",
					Title:       "Linux Persistence and Privilege Escalation Activity",
					Description: "Detects unauthorized sudoers modifications, cronjob injections, SUID abuse, and SSH key additions",
					Level:       "high",
					ThreatScore: 85,
					MitreID:     "T1053",
					Tags:        []string{"attack.persistence", "attack.privilege_escalation", "attack.t1053", "attack.t1548.003"},
					Scope:       ScopeHostLocal,
				},
				{
					ID:          "sigma-web-advanced",
					Title:       "Advanced Web Exploits and Modern Injection Vectors",
					Description: "Detects Server-Side Template Injection (SSTI), PHP Wrappers / LFI, Out-of-Band Exfiltration, and NoSQL Injection",
					Level:       "critical",
					ThreatScore: 95,
					MitreID:     "T1190",
					Tags:        []string{"attack.initial_access", "attack.t1190", "attack.persistence", "attack.t1505.003"},
					Scope:       ScopeNetwork,
				},
			},
		}
	})
	return defaultCatalog
}

func (c *CuratedCatalog) List() []RuleMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res := make([]RuleMetadata, len(c.rules))
	copy(res, c.rules)
	return res
}

func (c *CuratedCatalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

func (c *CuratedCatalog) GetRule(id string) (*RuleMetadata, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.rules {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("rule %s not found in catalog", id)
}
