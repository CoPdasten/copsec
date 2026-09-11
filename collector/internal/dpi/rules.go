package dpi

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	// DefaultRulesPath is the standard enterprise location for custom DPI signatures.
	DefaultRulesPath = "/etc/copsec/rules.yaml"
)

// YAMLRuleFile represents the parsed top-level YAML configuration structure.
type YAMLRuleFile struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

// ParseRulesYAML parses YAML content into a list of Rule structs without external dependencies.
// Handles comments (#), quoted strings, multiline indentation, and custom fields.
func ParseRulesYAML(data []byte) ([]Rule, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var rules []Rule
	var currentRule *Rule
	lineNum := 0

	finalizeCurrent := func() {
		if currentRule != nil {
			if currentRule.Pattern != "" {
				if currentRule.Name == "" {
					currentRule.Name = fmt.Sprintf("CUSTOM_RULE_%d", len(rules)+1)
				}
				if currentRule.Category == "" {
					currentRule.Category = CategoryCustomZeroDay
				}
				if currentRule.ID == "" {
					currentRule.ID = fmt.Sprintf("DPI_CUSTOM_%03d", len(rules)+1)
				}
				if currentRule.Severity == "" {
					currentRule.Severity = "HIGH"
				}
				rules = append(rules, *currentRule)
			}
			currentRule = nil
		}
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Strip comments
		commentIdx := strings.Index(line, "#")
		if commentIdx >= 0 {
			line = line[:commentIdx]
		}

		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		// Skip top-level section headers like "rules:"
		if strings.TrimSuffix(trimmed, ":") == "rules" {
			finalizeCurrent()
			continue
		}

		// New list item
		if strings.HasPrefix(trimmed, "-") {
			finalizeCurrent()
			currentRule = &Rule{}

			remainder := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if len(remainder) > 0 {
				k, v, ok := parseKeyValue(remainder)
				if ok {
					assignRuleField(currentRule, k, v)
				}
			}
			continue
		}

		// Indented property of the current rule
		if currentRule != nil {
			k, v, ok := parseKeyValue(trimmed)
			if ok {
				assignRuleField(currentRule, k, v)
			}
		}
	}

	finalizeCurrent()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error on line %d: %w", lineNum, err)
	}

	return rules, nil
}

// parseKeyValue extracts key and clean scalar value from a YAML line.
func parseKeyValue(line string) (string, string, bool) {
	colonIdx := strings.Index(line, ":")
	if colonIdx <= 0 {
		return "", "", false
	}

	key := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
	rawVal := strings.TrimSpace(line[colonIdx+1:])
	val := unquoteYAMLValue(rawVal)

	return key, val, true
}

// unquoteYAMLValue strips single/double quotes and unescapes basic character escapes.
func unquoteYAMLValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
			s = strings.ReplaceAll(s, `\"`, `"`)
			s = strings.ReplaceAll(s, `\'`, `'`)
			s = strings.ReplaceAll(s, `\n`, "\n")
			s = strings.ReplaceAll(s, `\t`, "\t")
			s = strings.ReplaceAll(s, `\\`, `\`)
		}
	}
	return s
}

// assignRuleField maps parsed YAML key-value pairs into Rule properties.
func assignRuleField(r *Rule, key, val string) {
	switch key {
	case "pattern":
		r.Pattern = val
	case "name":
		r.Name = val
	case "category":
		r.Category = RuleCategory(strings.ToUpper(val))
	case "id":
		r.ID = strings.ToUpper(val)
	case "severity":
		r.Severity = strings.ToUpper(val)
	}
}

// LoadRulesFromFile reads and parses YAML rule specifications from the local filesystem.
func LoadRulesFromFile(filePath string) ([]Rule, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		cleanPath = DefaultRulesPath
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read DPI rules file at %s: %w", cleanPath, err)
	}

	rules, err := ParseRulesYAML(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML rules from %s: %w", cleanPath, err)
	}

	return rules, nil
}

// ReloadFromFile dynamically refreshes the AhoCorasickEngine with baseline + YAML rules from disk.
// Performs atomic swap so active packet inspection routines experience zero lock contention.
func (e *AhoCorasickEngine) ReloadFromFile(filePath string) error {
	rules, err := LoadRulesFromFile(filePath)
	if err != nil {
		return err
	}

	return e.ReloadWithRules(rules)
}

// ReloadFromYAML parses raw YAML bytes and atomically updates the compiled DFA.
func (e *AhoCorasickEngine) ReloadFromYAML(yamlContent []byte) error {
	rules, err := ParseRulesYAML(yamlContent)
	if err != nil {
		return err
	}

	return e.ReloadWithRules(rules)
}

// ReloadWithRules merges embedded baseline signatures with additional rules and performs an atomic swap.
func (e *AhoCorasickEngine) ReloadWithRules(customRules []Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	baseline := GetEmbeddedSignatures()
	merged := make([]Rule, 0, len(baseline)+len(customRules))
	merged = append(merged, baseline...)

	existingPatterns := make(map[string]bool, len(baseline))
	for _, b := range baseline {
		existingPatterns[strings.ToLower(b.Pattern)] = true
	}

	for _, r := range customRules {
		norm := strings.ToLower(strings.TrimSpace(r.Pattern))
		if norm == "" || existingPatterns[norm] {
			continue
		}
		existingPatterns[norm] = true
		merged = append(merged, r)
	}

	compiled := compileTrie(merged)
	e.state.Store(compiled)

	return nil
}

// DynamicRuleManager manages dynamic runtime reloading and synchronization of DPI rules.
type DynamicRuleManager struct {
	mu         sync.RWMutex
	filePath   string
	engine     *AhoCorasickEngine
	lastLoaded int64
}

// NewDynamicRuleManager creates a manager for file-backed dynamic rule reloading.
func NewDynamicRuleManager(filePath string, engine *AhoCorasickEngine) *DynamicRuleManager {
	if filePath == "" {
		filePath = DefaultRulesPath
	}
	if engine == nil {
		engine = GetDefaultEngine()
	}

	return &DynamicRuleManager{
		filePath: filePath,
		engine:   engine,
	}
}

// Reload forces an immediate atomic reload of the rules file.
func (m *DynamicRuleManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.engine.ReloadFromFile(m.filePath)
}
