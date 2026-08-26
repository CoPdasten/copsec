package rules

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/copsec/controller/pkg/models"
	"gopkg.in/yaml.v3"
)

// MatchModifier defines modifier evaluation types.
type MatchModifier int

const (
	ModifierExact MatchModifier = iota
	ModifierContains
	ModifierStartswith
	ModifierEndswith
	ModifierRegex
	ModifierBase64
	ModifierCIDR
)

// ValueMatcher encapsulates pattern matching on individual field values.
type ValueMatcher struct {
	RawValue   string
	Modifier   MatchModifier
	MatchAll   bool
	CompiledRe *regexp.Regexp
	ParsedCIDR *net.IPNet
}

// Match tests a candidate string against the value matcher.
func (vm *ValueMatcher) Match(fieldVal string) bool {
	lowerField := strings.ToLower(fieldVal)
	lowerTarget := strings.ToLower(vm.RawValue)

	switch vm.Modifier {
	case ModifierContains:
		return strings.Contains(lowerField, lowerTarget)
	case ModifierStartswith:
		return strings.HasPrefix(lowerField, lowerTarget)
	case ModifierEndswith:
		return strings.HasSuffix(lowerField, lowerTarget)
	case ModifierRegex:
		if vm.CompiledRe != nil {
			return vm.CompiledRe.MatchString(fieldVal) || vm.CompiledRe.MatchString(lowerField)
		}
		return false
	case ModifierBase64:
		if strings.Contains(lowerField, lowerTarget) {
			return true
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(vm.RawValue))
		return strings.Contains(fieldVal, b64) || strings.Contains(lowerField, strings.ToLower(b64))
	case ModifierCIDR:
		if vm.ParsedCIDR != nil {
			ip := net.ParseIP(strings.TrimSpace(fieldVal))
			if ip != nil {
				return vm.ParsedCIDR.Contains(ip)
			}
		}
		return false
	default:
		return lowerField == lowerTarget
	}
}

// FieldSelection represents a selection block within a Sigma detection definition.
type FieldSelection struct {
	FieldName string
	Matchers  []ValueMatcher
	MatchAll  bool
}

// Match evaluates whether a set of field selections match the event fields/raw line.
func (fs *FieldSelection) Match(fields map[string]string, rawLine string) bool {
	var candidates []string

	if fs.FieldName == "" || fs.FieldName == "keywords" || fs.FieldName == "raw" || fs.FieldName == "message" {
		candidates = append(candidates, rawLine)
	} else {
		val, found := ResolveField(fields, fs.FieldName)
		if found {
			candidates = append(candidates, val)
		}
		// Also fallback to rawLine if specific field was not extracted
		candidates = append(candidates, rawLine)
	}

	for _, cand := range candidates {
		if fs.MatchAll {
			allPassed := true
			for _, m := range fs.Matchers {
				if !m.Match(cand) {
					allPassed = false
					break
				}
			}
			if allPassed && len(fs.Matchers) > 0 {
				return true
			}
		} else {
			for _, m := range fs.Matchers {
				if m.Match(cand) {
					return true
				}
			}
		}
	}

	return false
}

// SigmaRule encapsulates a parsed, compiled, and normalized SigmaHQ rule.
type SigmaRule struct {
	ID               string                      `json:"id"`
	Title            string                      `json:"title"`
	Description      string                      `json:"description"`
	Status           string                      `json:"status"`
	Author           string                      `json:"author"`
	Date             string                      `json:"date"`
	Modified         string                      `json:"modified"`
	References       []string                    `json:"references,omitempty"`
	Tags             []string                    `json:"tags,omitempty"`
	MitreTechniqueID string                      `json:"mitre_id"`
	MitreTactic      string                      `json:"mitre_tactic"`
	Level            string                      `json:"level"`
	ThreatScore      int                         `json:"threat_score"` // 0 - 100
	Severity         models.Severity             `json:"severity"`     // INFO, LOW, MEDIUM, HIGH, CRITICAL
	Logsource        map[string]string           `json:"logsource,omitempty"`
	Condition        string                      `json:"condition"`
	Selections       map[string][]FieldSelection `json:"-"`
	Scope            string                      `json:"scope"`  // SCOPE_NETWORK, SCOPE_HOST_LOCAL
	Origin           string                      `json:"origin"` // [BUILTIN], [SIGMAHQ]
	Enabled          bool                        `json:"enabled"`
	RawYAML          string                      `json:"raw_yaml,omitempty"`
	FilePath         string                      `json:"file_path,omitempty"`
}

// RawSigmaYAML maps the generic YAML structure of SigmaHQ rules.
type RawSigmaYAML struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status"`
	Description    string                 `yaml:"description"`
	References     []string               `yaml:"references"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Modified       string                 `yaml:"modified"`
	Tags           []string               `yaml:"tags"`
	Logsource      map[string]string      `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
	Falsepositives []string               `yaml:"falsepositives"`
	Level          string                 `yaml:"level"`
	Scope          string                 `yaml:"scope"`
}

// NormalizeSigmaSeverity maps standard Sigma level strings to CoPSeC threat scores and Severity enums.
// - critical -> Score: 90-100 (SOAR / XDP Drop) -> 95, CRITICAL
// - high     -> Score: 75-89  (High-fidelity Alert) -> 80, HIGH
// - medium   -> Score: 40-74  (Suspicious / Triage) -> 50, MEDIUM
// - low / info -> Score: 0-39 (Telemetry Log)       -> 20 / 0, LOW / INFO
func NormalizeSigmaSeverity(level string) (int, models.Severity) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 95, models.SeverityCritical
	case "high":
		return 80, models.SeverityHigh
	case "medium":
		return 50, models.SeverityMedium
	case "low":
		return 20, models.SeverityLow
	case "informational", "info":
		return 0, models.SeverityInfo
	default:
		return 50, models.SeverityMedium
	}
}

// ExtractMitreMetadata extracts MITRE ATT&CK technique IDs and tactics from Sigma tags.
func ExtractMitreMetadata(tags []string) (techID, tactic string) {
	for _, tag := range tags {
		tLower := strings.ToLower(strings.TrimSpace(tag))
		if strings.HasPrefix(tLower, "attack.t") {
			techID = strings.ToUpper(tLower[7:])
		} else if strings.HasPrefix(tLower, "attack.") && tactic == "" {
			sub := tLower[7:]
			if !strings.HasPrefix(sub, "t1") && !strings.HasPrefix(sub, "t0") {
				tactic = strings.ReplaceAll(sub, "_", " ")
			}
		}
	}
	return techID, tactic
}

// ClassifyScope determines whether a rule represents a host-local execution or a network threat.
func ClassifyScope(ruleID string, logsource map[string]string, tags []string) string {
	idLower := strings.ToLower(ruleID)
	catLower := strings.ToLower(logsource["category"])
	prodLower := strings.ToLower(logsource["product"])
	svcLower := strings.ToLower(logsource["service"])

	for _, tag := range tags {
		t := strings.ToLower(tag)
		if t == "scope.host_local" || t == "scope.local" || t == "scope.host" {
			return "SCOPE_HOST_LOCAL"
		}
		if t == "scope.network" || t == "scope.net" {
			return "SCOPE_NETWORK"
		}
	}

	if idLower == "sudo_execution" || strings.Contains(idLower, "sudo") ||
		strings.Contains(idLower, "cron") || strings.Contains(idLower, "fim") ||
		strings.Contains(idLower, "persistence") || strings.Contains(idLower, "privilege-escalation") ||
		strings.Contains(idLower, "history-clear") || strings.Contains(idLower, "daemon-term") ||
		strings.Contains(idLower, "suid") || strings.Contains(idLower, "rootkit") ||
		catLower == "process_creation" || prodLower == "linux" || svcLower == "auth" || svcLower == "sudo" {
		if strings.Contains(idLower, "revshell") || strings.Contains(idLower, "nc_shell") || strings.Contains(idLower, "web") {
			return "SCOPE_NETWORK"
		}
		return "SCOPE_HOST_LOCAL"
	}

	return "SCOPE_NETWORK"
}

// ParseSigmaRule compiles a raw YAML string into an in-memory SigmaRule.
func ParseSigmaRule(yamlContent string, origin string) (*SigmaRule, error) {
	var raw RawSigmaYAML
	if err := yaml.Unmarshal([]byte(yamlContent), &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sigma yaml: %w", err)
	}

	if raw.Title == "" && raw.ID == "" {
		return nil, fmt.Errorf("invalid sigma rule: missing title and id")
	}

	if raw.ID == "" {
		raw.ID = strings.ToLower(strings.ReplaceAll(raw.Title, " ", "-"))
	}

	techID, tactic := ExtractMitreMetadata(raw.Tags)
	score, severity := NormalizeSigmaSeverity(raw.Level)
	scope := ClassifyScope(raw.ID, raw.Logsource, raw.Tags)
	if raw.Scope != "" {
		scope = raw.Scope
	}

	if origin == "" {
		origin = "[SIGMAHQ]"
	}

	selections := make(map[string][]FieldSelection)
	condition := ""

	if cond, ok := raw.Detection["condition"].(string); ok {
		condition = strings.TrimSpace(cond)
	} else {
		condition = "selection"
	}

	for key, val := range raw.Detection {
		if key == "condition" || key == "timeframe" {
			continue
		}

		selList := parseDetectionBlock(key, val)
		if len(selList) > 0 {
			selections[key] = selList
		}
	}

	return &SigmaRule{
		ID:               raw.ID,
		Title:            raw.Title,
		Description:      raw.Description,
		Status:           raw.Status,
		Author:           raw.Author,
		Date:             raw.Date,
		Modified:         raw.Modified,
		References:       raw.References,
		Tags:             raw.Tags,
		MitreTechniqueID: techID,
		MitreTactic:      tactic,
		Level:            raw.Level,
		ThreatScore:      score,
		Severity:         severity,
		Logsource:        raw.Logsource,
		Condition:        condition,
		Selections:       selections,
		Scope:            scope,
		Origin:           origin,
		Enabled:          true,
		RawYAML:          yamlContent,
	}, nil
}

func parseDetectionBlock(blockName string, blockVal interface{}) []FieldSelection {
	var results []FieldSelection

	switch v := blockVal.(type) {
	case []interface{}:
		// List of strings (keywords)
		var matchers []ValueMatcher
		for _, item := range v {
			if s, ok := item.(string); ok {
				matchers = append(matchers, ValueMatcher{
					RawValue: s,
					Modifier: ModifierContains,
				})
			}
		}
		if len(matchers) > 0 {
			results = append(results, FieldSelection{
				FieldName: "keywords",
				Matchers:  matchers,
				MatchAll:  false,
			})
		}

	case map[string]interface{}:
		// Field to pattern mappings (e.g. CommandLine|contains: "sudo")
		for fieldKey, fieldVal := range v {
			fs := parseFieldPattern(fieldKey, fieldVal)
			if len(fs.Matchers) > 0 {
				results = append(results, fs)
			}
		}
	}

	return results
}

func parseFieldPattern(fieldKey string, fieldVal interface{}) FieldSelection {
	parts := strings.Split(fieldKey, "|")
	fieldName := parts[0]
	modifier := ModifierExact
	matchAll := false

	for _, mod := range parts[1:] {
		modLower := strings.ToLower(mod)
		switch modLower {
		case "contains":
			modifier = ModifierContains
		case "startswith":
			modifier = ModifierStartswith
		case "endswith":
			modifier = ModifierEndswith
		case "re", "regex":
			modifier = ModifierRegex
		case "base64", "base64offset":
			modifier = ModifierBase64
		case "cidr":
			modifier = ModifierCIDR
		case "all":
			matchAll = true
		}
	}

	var matchers []ValueMatcher

	switch val := fieldVal.(type) {
	case string:
		m := buildValueMatcher(val, modifier, matchAll)
		matchers = append(matchers, m)
	case []interface{}:
		for _, elem := range val {
			if s, ok := elem.(string); ok {
				m := buildValueMatcher(s, modifier, matchAll)
				matchers = append(matchers, m)
			} else if num, ok := elem.(int); ok {
				m := buildValueMatcher(strconv.Itoa(num), modifier, matchAll)
				matchers = append(matchers, m)
			}
		}
	case int:
		m := buildValueMatcher(strconv.Itoa(val), modifier, matchAll)
		matchers = append(matchers, m)
	}

	return FieldSelection{
		FieldName: fieldName,
		Matchers:  matchers,
		MatchAll:  matchAll,
	}
}

func buildValueMatcher(raw string, modifier MatchModifier, matchAll bool) ValueMatcher {
	vm := ValueMatcher{
		RawValue: raw,
		Modifier: modifier,
		MatchAll: matchAll,
	}

	if modifier == ModifierRegex {
		if re, err := regexp.Compile("(?i)" + raw); err == nil {
			vm.CompiledRe = re
		}
	} else if modifier == ModifierCIDR {
		if _, ipNet, err := net.ParseCIDR(raw); err == nil {
			vm.ParsedCIDR = ipNet
		}
	}

	return vm
}

// EvaluateEvent evaluates a candidate log event against a single compiled SigmaRule.
func (r *SigmaRule) EvaluateEvent(rawLine string, fields map[string]string) bool {
	if !r.Enabled {
		return false
	}

	blockResults := make(map[string]bool)
	for blockName, selections := range r.Selections {
		matched := true
		for _, sel := range selections {
			if !sel.Match(fields, rawLine) {
				matched = false
				break
			}
		}
		blockResults[blockName] = matched
	}

	return evaluateCondition(r.Condition, blockResults)
}

func evaluateCondition(cond string, blockResults map[string]bool) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		for _, res := range blockResults {
			if res {
				return true
			}
		}
		return false
	}

	// 1. Single selection direct match
	if res, ok := blockResults[cond]; ok {
		return res
	}

	condLower := strings.ToLower(cond)

	// 2. "1 of selection*" or "1 of them"
	if strings.HasPrefix(condLower, "1 of ") || strings.HasPrefix(condLower, "any of ") {
		prefix := strings.TrimSpace(cond[5:])
		prefix = strings.TrimSuffix(prefix, "*")
		for k, res := range blockResults {
			if prefix == "them" || strings.HasPrefix(k, prefix) {
				if res {
					return true
				}
			}
		}
		return false
	}

	// 3. "all of selection*" or "all of them"
	if strings.HasPrefix(condLower, "all of ") {
		prefix := strings.TrimSpace(cond[7:])
		prefix = strings.TrimSuffix(prefix, "*")
		count := 0
		for k, res := range blockResults {
			if prefix == "them" || strings.HasPrefix(k, prefix) {
				count++
				if !res {
					return false
				}
			}
		}
		return count > 0
	}

	// 4. "selection and not filter" / "selection1 and not (filter1 or filter2)"
	if strings.Contains(condLower, " and not ") {
		parts := strings.SplitN(condLower, " and not ", 2)
		pos := strings.Trim(parts[0], "() ")
		neg := strings.Trim(parts[1], "() ")

		posMatch := blockResults[pos]
		if !posMatch && strings.HasPrefix(pos, "1 of ") {
			posMatch = evaluateCondition(pos, blockResults)
		}

		negMatch := blockResults[neg]
		if !negMatch && (strings.Contains(neg, " or ") || strings.Contains(neg, " and ")) {
			// Sub-evaluation
			if strings.Contains(neg, " or ") {
				for _, sub := range strings.Split(neg, " or ") {
					if blockResults[strings.Trim(sub, "() ")] {
						negMatch = true
						break
					}
				}
			}
		}

		return posMatch && !negMatch
	}

	// 5. "selection1 or selection2"
	if strings.Contains(condLower, " or ") {
		parts := strings.Split(condLower, " or ")
		for _, p := range parts {
			clean := strings.Trim(p, "() ")
			if blockResults[clean] {
				return true
			}
		}
		return false
	}

	// 6. "selection1 and selection2"
	if strings.Contains(condLower, " and ") {
		parts := strings.Split(condLower, " and ")
		for _, p := range parts {
			clean := strings.Trim(p, "() ")
			if !blockResults[clean] {
				return false
			}
		}
		return true
	}

	return false
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

// Matcher provides thread-safe in-memory caching and matching of Sigma rules.
type Matcher struct {
	mu    sync.RWMutex
	rules map[string]*SigmaRule
}

var (
	defaultMatcher *Matcher
	matcherOnce    sync.Once
)

// GetDefaultMatcher returns the singleton rule matcher instance.
func GetDefaultMatcher() *Matcher {
	matcherOnce.Do(func() {
		defaultMatcher = NewMatcher()
		defaultMatcher.LoadBuiltinRules()
	})
	return defaultMatcher
}

// NewMatcher creates a new empty Matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		rules: make(map[string]*SigmaRule),
	}
}

// AddRule registers or updates a compiled SigmaRule.
func (m *Matcher) AddRule(rule *SigmaRule) {
	if rule == nil || rule.ID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[rule.ID] = rule
}

// GetRule retrieves a rule by its ID.
func (m *Matcher) GetRule(ruleID string) (*SigmaRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rule, exists := m.rules[ruleID]
	return rule, exists
}

// ListRules returns all in-memory rules.
func (m *Matcher) ListRules() []*SigmaRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*SigmaRule
	for _, r := range m.rules {
		list = append(list, r)
	}
	return list
}

// SetRuleEnabled dynamically toggles a rule state.
func (m *Matcher) SetRuleEnabled(ruleID string, enabled bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule, ok := m.rules[ruleID]; ok {
		rule.Enabled = enabled
		return true
	}
	return false
}

// Evaluate evaluates a log line and extracted fields across all active rules.
func (m *Matcher) Evaluate(rawLine string, fields map[string]string) (*SigmaRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, rule := range m.rules {
		if rule.Enabled && rule.EvaluateEvent(rawLine, fields) {
			return rule, true
		}
	}
	return nil, false
}

// LoadBuiltinRules loads standard built-in rules tagged with [BUILTIN].
func (m *Matcher) LoadBuiltinRules() {
	builtinRules := []string{
		`title: Reverse Shell Command Execution
id: sigma-linux-revshell
status: production
level: critical
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - "bash -i"
      - "/dev/tcp/"
      - "nc -e"
      - "ncat -e"
      - "mkfifo /tmp/"
      - "pty.spawn"
  condition: selection
`,
		`title: Web Application SQL Injection Attack
id: sigma-web-sqli
status: production
level: critical
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
  product: nginx
detection:
  selection:
    RequestURI|contains:
      - "union select"
      - "union%20select"
      - "select from"
      - "select%20from"
      - "or 1=1"
      - "waitfor delay"
      - "sleep("
  condition: selection
`,
		`title: Linux Authentication Brute Force Failure
id: sigma-linux-auth-bruteforce
status: production
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  service: auth
  product: linux
detection:
  selection:
    raw:
      - "Failed password for"
      - "authentication failure"
      - "Invalid user"
  condition: selection
`,
		`title: Port Scan Probe Activity
id: sigma-network-port-scan
status: production
level: medium
tags:
  - attack.reconnaissance
  - attack.t1046
logsource:
  category: network
detection:
  selection:
    raw:
      - "nmap"
      - "masscan"
      - "SYN scan"
      - "port scan"
  condition: selection
`,
	}

	for _, y := range builtinRules {
		if rule, err := ParseSigmaRule(y, "[BUILTIN]"); err == nil {
			m.AddRule(rule)
		}
	}
}
