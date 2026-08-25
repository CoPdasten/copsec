package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/copsec/controller/pkg/sigma"
	"gopkg.in/yaml.v3"
)

// SigmaRuleRaw maps the raw YAML schema of standard SigmaHQ detection rules.
type SigmaRuleRaw struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status"`
	Description    string                 `yaml:"description"`
	References     []string               `yaml:"references"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Modified       string                 `yaml:"modified"`
	Tags           []string               `yaml:"tags"`
	Logsource      SigmaLogsource         `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
	Falsepositives []string               `yaml:"falsepositives"`
	Level          string                 `yaml:"level"`
	Scope          string                 `yaml:"scope"`
}

// SigmaLogsource captures service, category, and product scope.
type SigmaLogsource struct {
	Category   string `yaml:"category"`
	Product    string `yaml:"product"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

// MatchModifier defines the type of value evaluation.
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

// ValueMatcher evaluates a specific field value against log data.
type ValueMatcher struct {
	RawValue   string
	Modifier   MatchModifier
	MatchAll   bool // For '|all' modifier
	CompiledRe *regexp.Regexp
	ParsedCIDR *net.IPNet
}

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
		// Check both raw search and base64 encoded search
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

// FieldEvaluator evaluates a list of matcher values against a specific log field or entire line.
type FieldEvaluator struct {
	FieldName string
	MatchAll  bool
	Matchers  []ValueMatcher
}

func (fe *FieldEvaluator) Evaluate(fields map[string]string, rawLine string) bool {
	var targetVal string
	fieldName := strings.ToLower(fe.FieldName)
	if fieldName == "" || fieldName == "_raw" || fieldName == "raw" || fieldName == "message" || fieldName == "rawlog" {
		targetVal = rawLine
	} else {
		val, ok := sigma.ResolveField(fields, fe.FieldName)
		if !ok {
			// Fallback to checking inside raw line if field not separated
			targetVal = rawLine
		} else {
			targetVal = val
		}
	}

	if len(fe.Matchers) == 0 {
		return false
	}

	if fe.MatchAll {
		for _, m := range fe.Matchers {
			if !m.Match(targetVal) {
				return false
			}
		}
		return true
	}

	// Default: any match (OR within same field values list)
	for _, m := range fe.Matchers {
		if m.Match(targetVal) {
			return true
		}
	}
	return false
}

// SelectionEvaluator evaluates a group of field conditions (e.g. selection_1).
type SelectionEvaluator struct {
	Name       string
	Evaluators []FieldEvaluator
}

func (se *SelectionEvaluator) Evaluate(fields map[string]string, rawLine string) bool {
	// All field evaluators within a selection must match (AND)
	for _, fe := range se.Evaluators {
		if !fe.Evaluate(fields, rawLine) {
			return false
		}
	}
	return true
}

// CompiledSigmaRule is the optimized in-memory compiled representation of a Sigma HQ rule.
type CompiledSigmaRule struct {
	ID                 string                         `json:"id"`
	Title              string                         `json:"title"`
	Description        string                         `json:"description"`
	Level              string                         `json:"level"`
	ThreatScore        int                            `json:"threat_score"`
	MitreTechniqueID   string                         `json:"mitre_technique_id"`
	MitreTechniqueName string                         `json:"mitre_technique_name"`
	MitreTactic        string                         `json:"mitre_tactic"`
	Tags               []string                       `json:"tags"`
	Scope              sigma.RuleScope                `json:"scope"`
	Logsource          SigmaLogsource                 `json:"logsource"`
	Selections         map[string]*SelectionEvaluator `json:"-"`
	ConditionExpr      string                         `json:"condition"`
	ConditionTokens    []string                       `json:"-"`
	RawYAML            string                         `json:"raw_yaml,omitempty"`
}

// SigmaEngine manages pure Go parsing, compilation, and high-throughput log evaluation.
type SigmaEngine struct {
	mu           sync.RWMutex
	rules        []*CompiledSigmaRule
	rulesByID    map[string]*CompiledSigmaRule
	ruleDir      string
	techNameMap  map[string]string
	totalMatches uint64
}

// NewSigmaEngine creates a new in-memory Sigma engine.
func NewSigmaEngine(ruleDir string) *SigmaEngine {
	engine := &SigmaEngine{
		rulesByID:   make(map[string]*CompiledSigmaRule),
		ruleDir:     ruleDir,
		techNameMap: make(map[string]string),
	}

	if ruleDir != "" {
		if err := engine.LoadDirectory(ruleDir); err != nil {
			log.Printf("[WARN] Failed to load Sigma rules from %s: %v (loading built-in detection-as-code rules)", ruleDir, err)
			engine.loadBuiltinSigmaRules()
		}
	} else {
		engine.loadBuiltinSigmaRules()
	}

	return engine
}

// ParseSigmaYAML parses a raw YAML string into a CompiledSigmaRule.
func (se *SigmaEngine) ParseSigmaYAML(content string) (*CompiledSigmaRule, error) {
	var raw SigmaRuleRaw
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("yaml unmarshal error: %w", err)
	}

	if raw.Title == "" && raw.ID == "" {
		return nil, fmt.Errorf("invalid sigma rule: missing title or id")
	}

	ruleID := raw.ID
	if ruleID == "" {
		ruleID = strings.ToLower(strings.ReplaceAll(raw.Title, " ", "_"))
	}

	// Extract MITRE ATT&CK technique and tactic from tags
	mitreID, mitreName, tactic := parseMitreTags(raw.Tags, raw.Title)

	// Determine numeric threat score based on level
	score := mapLevelToScore(raw.Level)

	// Determine rule scope (SCOPE_NETWORK vs SCOPE_HOST_LOCAL)
	var ruleScope sigma.RuleScope
	if strings.EqualFold(raw.Scope, string(sigma.ScopeHostLocal)) || strings.EqualFold(raw.Scope, "host_local") || strings.EqualFold(raw.Scope, "host") || strings.EqualFold(raw.Scope, "local") {
		ruleScope = sigma.ScopeHostLocal
	} else if strings.EqualFold(raw.Scope, string(sigma.ScopeNetwork)) || strings.EqualFold(raw.Scope, "network") {
		ruleScope = sigma.ScopeNetwork
	} else {
		ruleScope = sigma.DetermineRuleScope(ruleID, raw.Logsource.Category, raw.Logsource.Product, raw.Logsource.Service, raw.Tags)
	}

	compiled := &CompiledSigmaRule{
		ID:                 ruleID,
		Title:              raw.Title,
		Description:        raw.Description,
		Level:              strings.ToLower(raw.Level),
		ThreatScore:        score,
		MitreTechniqueID:   mitreID,
		MitreTechniqueName: mitreName,
		MitreTactic:        tactic,
		Tags:               raw.Tags,
		Scope:              ruleScope,
		Logsource:          raw.Logsource,
		Selections:         make(map[string]*SelectionEvaluator),
		RawYAML:            content,
	}

	// Extract condition and selections from detection block
	var conditionStr string
	for key, val := range raw.Detection {
		if key == "condition" {
			if condVal, ok := val.(string); ok {
				conditionStr = strings.TrimSpace(condVal)
			}
			continue
		}

		selEval := parseSelectionBlock(key, val)
		if selEval != nil {
			compiled.Selections[key] = selEval
		}
	}

	if conditionStr == "" {
		if len(compiled.Selections) == 1 {
			for k := range compiled.Selections {
				conditionStr = k
			}
		} else {
			conditionStr = "1 of them"
		}
	}

	compiled.ConditionExpr = conditionStr
	compiled.ConditionTokens = tokenizeCondition(conditionStr)

	return compiled, nil
}

// LoadDirectory recursively scans a directory for .yml/.yaml Sigma rules and compiles them.
func (se *SigmaEngine) LoadDirectory(dirPath string) error {
	info, err := os.Stat(dirPath)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("invalid sigma directory: %s", dirPath)
	}

	var loadedRules []*CompiledSigmaRule
	loadedMap := make(map[string]*CompiledSigmaRule)

	err = filepath.Walk(dirPath, func(path string, fileInfo os.FileInfo, walkErr error) error {
		if walkErr != nil || fileInfo.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		rule, parseErr := se.ParseSigmaYAML(string(data))
		if parseErr != nil {
			log.Printf("[DEBUG] Skipping invalid Sigma rule %s: %v", path, parseErr)
			return nil
		}

		loadedRules = append(loadedRules, rule)
		loadedMap[rule.ID] = rule
		return nil
	})

	if err != nil {
		return err
	}

	if len(loadedRules) == 0 {
		return fmt.Errorf("no valid sigma rules found in %s", dirPath)
	}

	se.mu.Lock()
	se.rules = loadedRules
	se.rulesByID = loadedMap
	se.ruleDir = dirPath
	se.mu.Unlock()

	log.Printf("[INFO] Sigma Detection Engine loaded %d compiled SigmaHQ rules from %s", len(loadedRules), dirPath)
	return nil
}

// AddRule registers a pre-compiled or parsed Sigma rule in-memory.
func (se *SigmaEngine) AddRule(rule *CompiledSigmaRule) {
	se.mu.Lock()
	defer se.mu.Unlock()

	se.rulesByID[rule.ID] = rule
	found := false
	for i, r := range se.rules {
		if r.ID == rule.ID {
			se.rules[i] = rule
			found = true
			break
		}
	}
	if !found {
		se.rules = append(se.rules, rule)
	}
}

// GetRules returns a snapshot of all active compiled rules.
func (se *SigmaEngine) GetRules() []*CompiledSigmaRule {
	se.mu.RLock()
	defer se.mu.RUnlock()

	list := make([]*CompiledSigmaRule, len(se.rules))
	copy(list, se.rules)
	return list
}

// EvaluateEvent inspects normalized fields and raw lines against all compiled Sigma rules in sub-milliseconds.
func (se *SigmaEngine) EvaluateEvent(rawLine string, fields map[string]string) (matchedRule *CompiledSigmaRule, matched bool) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	if IsNoisyLog(rawLine) {
		return nil, false
	}

	normalizedRaw := NormalizePayload(rawLine)

	for _, rule := range se.rules {
		if se.evaluateRule(rule, fields, rawLine, normalizedRaw) {
			return rule, true
		}
	}

	return nil, false
}

// evaluateRule evaluates a single compiled Sigma rule against event data.
func (se *SigmaEngine) evaluateRule(rule *CompiledSigmaRule, fields map[string]string, rawLine, normalizedRaw string) bool {
	selResults := make(map[string]bool, len(rule.Selections))
	for name, sel := range rule.Selections {
		matched := sel.Evaluate(fields, normalizedRaw)
		if !matched && rawLine != normalizedRaw {
			matched = sel.Evaluate(fields, rawLine)
		}
		selResults[name] = matched
	}

	return evalConditionTokens(rule.ConditionTokens, selResults, rule.Selections)
}

// evalConditionTokens processes condition expressions.
func evalConditionTokens(tokens []string, selResults map[string]bool, selections map[string]*SelectionEvaluator) bool {
	if len(tokens) == 0 {
		for _, res := range selResults {
			if res {
				return true
			}
		}
		return false
	}

	if len(tokens) == 3 && (tokens[0] == "1" || tokens[0] == "all") && tokens[1] == "of" {
		pattern := tokens[2]
		return evalQuantifier(tokens[0], pattern, selResults)
	}

	result, _ := parseOrExpr(tokens, 0, selResults)
	return result
}

func evalQuantifier(quantifier, pattern string, selResults map[string]bool) bool {
	matchCount := 0
	totalCount := 0

	for name, res := range selResults {
		if matchesPattern(name, pattern) {
			totalCount++
			if res {
				matchCount++
			}
		}
	}

	if totalCount == 0 {
		return false
	}

	if quantifier == "1" {
		return matchCount >= 1
	}
	if quantifier == "all" {
		return matchCount == totalCount
	}
	return matchCount > 0
}

func matchesPattern(name, pattern string) bool {
	if pattern == "them" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}
	return name == pattern
}

func parseOrExpr(tokens []string, idx int, selResults map[string]bool) (bool, int) {
	left, nextIdx := parseAndExpr(tokens, idx, selResults)
	for nextIdx < len(tokens) && tokens[nextIdx] == "or" {
		right, n := parseAndExpr(tokens, nextIdx+1, selResults)
		left = left || right
		nextIdx = n
	}
	return left, nextIdx
}

func parseAndExpr(tokens []string, idx int, selResults map[string]bool) (bool, int) {
	left, nextIdx := parseNotExpr(tokens, idx, selResults)
	for nextIdx < len(tokens) && tokens[nextIdx] == "and" {
		right, n := parseNotExpr(tokens, nextIdx+1, selResults)
		left = left && right
		nextIdx = n
	}
	return left, nextIdx
}

func parseNotExpr(tokens []string, idx int, selResults map[string]bool) (bool, int) {
	if idx >= len(tokens) {
		return false, idx
	}
	if tokens[idx] == "not" {
		val, nextIdx := parsePrimary(tokens, idx+1, selResults)
		return !val, nextIdx
	}
	return parsePrimary(tokens, idx, selResults)
}

func parsePrimary(tokens []string, idx int, selResults map[string]bool) (bool, int) {
	if idx >= len(tokens) {
		return false, idx
	}

	token := tokens[idx]

	if token == "(" {
		val, nextIdx := parseOrExpr(tokens, idx+1, selResults)
		if nextIdx < len(tokens) && tokens[nextIdx] == ")" {
			nextIdx++
		}
		return val, nextIdx
	}

	if (token == "1" || token == "all") && idx+2 < len(tokens) && tokens[idx+1] == "of" {
		pattern := tokens[idx+2]
		res := evalQuantifier(token, pattern, selResults)
		return res, idx + 3
	}

	res := selResults[token]
	return res, idx + 1
}

func tokenizeCondition(cond string) []string {
	var tokens []string
	clean := strings.ReplaceAll(cond, "(", " ( ")
	clean = strings.ReplaceAll(clean, ")", " ) ")
	clean = strings.ReplaceAll(clean, "|", " or ")

	fields := strings.Fields(clean)
	for _, f := range fields {
		lower := strings.ToLower(f)
		switch lower {
		case "and", "or", "not", "(", ")", "1", "all", "of", "them":
			tokens = append(tokens, lower)
		default:
			tokens = append(tokens, f)
		}
	}
	return tokens
}

func parseSelectionBlock(name string, val interface{}) *SelectionEvaluator {
	sel := &SelectionEvaluator{Name: name}

	switch v := val.(type) {
	case map[string]interface{}:
		for fieldKey, fieldVal := range v {
			fe := parseFieldEvaluator(fieldKey, fieldVal)
			if fe != nil {
				sel.Evaluators = append(sel.Evaluators, *fe)
			}
		}
	case []interface{}:
		var matchers []ValueMatcher
		for _, item := range v {
			if strVal, ok := item.(string); ok {
				matchers = append(matchers, ValueMatcher{
					RawValue: strVal,
					Modifier: ModifierContains,
				})
			}
		}
		if len(matchers) > 0 {
			sel.Evaluators = append(sel.Evaluators, FieldEvaluator{
				FieldName: "_raw",
				MatchAll:  false,
				Matchers:  matchers,
			})
		}
	case string:
		sel.Evaluators = append(sel.Evaluators, FieldEvaluator{
			FieldName: "_raw",
			MatchAll:  false,
			Matchers: []ValueMatcher{{
				RawValue: v,
				Modifier: ModifierContains,
			}},
		})
	}

	return sel
}

func parseFieldEvaluator(fieldKey string, fieldVal interface{}) *FieldEvaluator {
	parts := strings.Split(fieldKey, "|")
	fieldName := parts[0]

	modifier := ModifierExact
	matchAll := false

	for _, mod := range parts[1:] {
		lowerMod := strings.ToLower(mod)
		switch lowerMod {
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

	fe := &FieldEvaluator{
		FieldName: fieldName,
		MatchAll:  matchAll,
	}

	switch v := fieldVal.(type) {
	case string:
		matcher := buildValueMatcher(v, modifier)
		fe.Matchers = append(fe.Matchers, matcher)
	case []interface{}:
		for _, item := range v {
			strItem := fmt.Sprintf("%v", item)
			matcher := buildValueMatcher(strItem, modifier)
			fe.Matchers = append(fe.Matchers, matcher)
		}
	case int:
		matcher := buildValueMatcher(strconv.Itoa(v), modifier)
		fe.Matchers = append(fe.Matchers, matcher)
	case bool:
		matcher := buildValueMatcher(strconv.FormatBool(v), modifier)
		fe.Matchers = append(fe.Matchers, matcher)
	}

	return fe
}

func buildValueMatcher(val string, modifier MatchModifier) ValueMatcher {
	vm := ValueMatcher{
		RawValue: val,
		Modifier: modifier,
	}

	if modifier == ModifierRegex {
		pattern := val
		if strings.HasPrefix(pattern, "(?i)") {
			pattern = pattern[4:]
		}
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			vm.CompiledRe = re
		}
	} else if modifier == ModifierCIDR {
		if _, ipNet, err := net.ParseCIDR(val); err == nil {
			vm.ParsedCIDR = ipNet
		}
	}

	return vm
}

func parseMitreTags(tags []string, title string) (techniqueID, techniqueName, tactic string) {
	techniqueID = "T1190"
	techniqueName = title
	tactic = "Initial Access"

	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			rawID := strings.TrimPrefix(lower, "attack.")
			techniqueID = strings.ToUpper(rawID)
		} else if strings.HasPrefix(lower, "attack.") {
			tact := strings.TrimPrefix(lower, "attack.")
			tact = strings.ReplaceAll(tact, "_", " ")
			tact = strings.Title(tact)
			tactic = tact
		}
	}

	if techniqueName == title {
		switch techniqueID {
		case "T1190":
			techniqueName = "Exploit Public-Facing Application"
		case "T1059", "T1059.004":
			techniqueName = "Command and Scripting Interpreter (Unix Shell)"
		case "T1110", "T1110.001":
			techniqueName = "Brute Force: Password Guessing"
		case "T1078":
			techniqueName = "Valid Accounts (Root / Admin Compromise)"
		case "T1027":
			techniqueName = "Obfuscated Files or Information"
		case "T1595", "T1595.002":
			techniqueName = "Active Scanning: Vulnerability Scanning"
		case "T1505", "T1505.003":
			techniqueName = "Server Software Component: Web Shell"
		case "T1003", "T1003.008":
			techniqueName = "OS Credential Dumping: /etc/shadow"
		case "T1562", "T1562.001":
			techniqueName = "Impair Defenses: Disable Security Tools"
		case "T1499":
			techniqueName = "Endpoint Denial of Service"
		}
	}

	return techniqueID, techniqueName, tactic
}

func mapLevelToScore(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 35
	case "informational":
		return 15
	default:
		return 50
	}
}

func (se *SigmaEngine) loadBuiltinSigmaRules() {
	builtinRules := []string{
		`
title: Web Application SQL Injection Attempt
id: sigma-web-sqli
status: stable
description: Detects classic SQL injection UNION, SELECT, and delay-based payloads in web requests
tags:
  - attack.initial_access
  - attack.t1190
level: critical
logsource:
  category: webserver
detection:
  selection:
    _raw|re: "(?i)(union\\s+select|select\\s+.*from|waitfor\\s+delay|sleep\\(\\d+\\)|'--|%27%20or%20|or\\s+1=1)"
  condition: selection
`,
		`
title: Web Remote Command Execution (RCE) / Shell Injection
id: sigma-web-rce
status: stable
description: Detects command injection tokens and unix shell execution via web requests
tags:
  - attack.execution
  - attack.t1059.004
level: critical
logsource:
  category: webserver
detection:
  selection_cmd:
    _raw|re: "(?i)((;|\\||&&)\\s*/bin/(sh|bash)|curl\\s+https?://.*\\|\\s*(sh|bash)|;\\s*(cat|id|whoami)\\s+|\\|\\s*(cat|id)\\s*|` + "`whoami`" + `|\\$\\(whoami\\))"
  condition: selection_cmd
`,
		`
title: SSH Authentication Brute Force Attack
id: sigma-ssh-bruteforce
status: stable
description: Identifies repeated failed SSH login attempts indicating automated credential brute-forcing
tags:
  - attack.credential_access
  - attack.t1110.001
level: high
logsource:
  service: sshd
detection:
  selection_auth:
    _raw|re: "(?i)(Failed password for (invalid user )?[a-zA-Z0-9_.-]+ from \\d+\\.\\d+\\.\\d+\\.\\d+|Invalid user [a-zA-Z0-9_.-]+ from \\d+\\.\\d+\\.\\d+\\.\\d+)"
  condition: selection_auth
`,
		`
title: Active Web Vulnerability Scanner or Directory Fuzzer
id: sigma-web-scanner
status: stable
description: Detects known automated web vulnerability scanners, fuzzers, and crawler user agents
tags:
  - attack.reconnaissance
  - attack.t1595.002
level: medium
logsource:
  category: webserver
detection:
  selection_scanner:
    _raw|re: "(?i)(sqlmap/|nikto/|nuclei|acunetix|gobuster/|dirsearch|wpscan|masscan/|fuzz/)"
  condition: selection_scanner
`,
		`
title: Web Shell Installation or Access
id: sigma-webshell-access
status: stable
description: Detects access to common web shells, PHP backdoors, or command upload vectors
tags:
  - attack.persistence
  - attack.t1505.003
level: critical
logsource:
  category: webserver
detection:
  selection_webshell:
    _raw|re: "(?i)(/shell\\.php|/c99\\.php|/r57\\.php|/b374k|/wso\\.php|/alfa\\.php|eval\\(base64_decode)"
  condition: selection_webshell
`,
		`
title: OS Credential Dumping (/etc/shadow)
id: sigma-credential-dumping
status: stable
description: Detects unauthorized attempts to read or exfiltrate Linux password hashes
tags:
  - attack.credential_access
  - attack.t1003.008
level: critical
logsource:
  product: linux
detection:
  selection_shadow:
    _raw|re: "(?i)(cat\\s+/etc/shadow|secretsdump|/etc/security/opasswd)"
  condition: selection_shadow
`,
		`
title: Defense Impairment - Firewall and SIEM Evasion
id: sigma-impair-defenses
status: stable
description: Detects commands that disable system firewalls or stop security monitoring services
tags:
  - attack.defense_evasion
  - attack.t1562.001
level: critical
logsource:
  product: linux
detection:
  selection_disable:
    _raw|re: "(?i)(systemctl\\s+(stop|disable)\\s+(ufw|iptables|copsec)|iptables\\s+-F|ufw\\s+disable)"
  condition: selection_disable
`,
	}

	for _, ruleYAML := range builtinRules {
		rule, err := se.ParseSigmaYAML(strings.TrimSpace(ruleYAML))
		if err == nil {
			se.AddRule(rule)
		}
	}

	for _, curatedYAML := range sigma.GetCuratedRulePack() {
		rule, err := se.ParseSigmaYAML(strings.TrimSpace(curatedYAML))
		if err == nil {
			se.AddRule(rule)
		}
	}

	log.Printf("[INFO] Sigma Detection Engine initialized with %d built-in Detection-as-Code rules", len(se.rules))
}
