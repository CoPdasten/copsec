package detection

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// CompiledRule wraps a DetectionRule with its pre-compiled regular expression.
type CompiledRule struct {
	DetectionRule
	Regex *regexp.Regexp
}

// RuleMetric tracks runtime hit metrics for a rule.
type RuleMetric struct {
	TotalHits int64 `json:"total_hits"`
	LastHitMs int64 `json:"last_hit_ms"`
}

// RuleStateDTO represents runtime metadata returned by GET /api/rules.
type RuleStateDTO struct {
	DetectionRule
	TotalHits int64 `json:"total_hits"`
	LastHitMs int64 `json:"last_hit_ms"`
}

// RuleRegistry manages in-memory thread-safe detection rules and hot-reloading.
type RuleRegistry struct {
	mu           sync.RWMutex
	rulesDir     string
	rules        []*CompiledRule
	ruleIndex    map[string]*CompiledRule
	metrics      map[string]*RuleMetric
	slidingStore sync.Map // key: "client_ip:rule_id" -> []int64 (timestamps)
}

var (
	defaultRegistry *RuleRegistry
	once            sync.Once
)

// GetDefaultRegistry returns the singleton detection rule registry.
func GetDefaultRegistry() *RuleRegistry {
	once.Do(func() {
		defaultRegistry = NewRuleRegistry("")
	})
	return defaultRegistry
}

// NewRuleRegistry creates a new rule registry for the given rules directory.
func NewRuleRegistry(rulesDir string) *RuleRegistry {
	if rulesDir == "" {
		if envDir := os.Getenv("COPSEC_CONF_DIR"); envDir != "" {
			rulesDir = filepath.Join(envDir, "rules")
		} else {
			rulesDir = "/etc/copsec/rules"
		}
	}

	reg := &RuleRegistry{
		rulesDir:  rulesDir,
		rules:     make([]*CompiledRule, 0),
		ruleIndex: make(map[string]*CompiledRule),
		metrics:   make(map[string]*RuleMetric),
	}

	// Auto-provision defaults if empty or non-existent
	reg.ProvisionDefaults()

	// Initial load
	_, _, _ = reg.ReloadRules()

	// Register SIGHUP listener for zero-downtime hot-reload
	reg.startSignalListener()

	return reg
}

// SetRulesDir dynamically points the registry to another directory (e.g. testing or local fallback).
func (r *RuleRegistry) SetRulesDir(dir string) {
	r.mu.Lock()
	r.rulesDir = dir
	r.mu.Unlock()

	r.ProvisionDefaults()
	_, _, _ = r.ReloadRules()
}

// startSignalListener catches syscall.SIGHUP and triggers atomic rule reload.
func (r *RuleRegistry) startSignalListener() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			log.Println("[INFO] ⚡ Received SIGHUP signal: Initiating zero-downtime detection rules hot-reload...")
			active, disabled, err := r.ReloadRules()
			if err != nil {
				log.Printf("[ERROR] SIGHUP rule reload encountered error: %v", err)
			} else {
				log.Printf("[INFO] SIGHUP reload complete: %d active, %d disabled", active, disabled)
			}
		}
	}()
}

// ProvisionDefaults creates rule_sqli.json, rule_traversal.json, and rule_high_entropy.json
// if the rules directory is empty or missing.
func (r *RuleRegistry) ProvisionDefaults() {
	r.mu.RLock()
	dir := r.rulesDir
	r.mu.RUnlock()

	if err := os.MkdirAll(dir, 0750); err != nil {
		// Fallback to ./rules if cannot create /etc/copsec/rules
		dir = filepath.Join(".", "rules")
		_ = os.MkdirAll(dir, 0750)
		r.mu.Lock()
		r.rulesDir = dir
		r.mu.Unlock()
	}

	// Check if directory has existing .json files
	files, err := os.ReadDir(dir)
	hasJSON := false
	if err == nil {
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
				hasJSON = true
				break
			}
		}
	}

	if !hasJSON {
		// 1. rule_sqli.json
		sqliRule := DetectionRule{
			ID:               "RULE-SQLI-001",
			Name:             "SQL Injection Attack Pattern",
			Description:      "Detects SQL injection operators, UNION SELECT queries, and tautology bypasses",
			Severity:         "CRITICAL",
			ThreatScore:      85,
			MitreTechniqueID: "T1190",
			Enabled:          true,
			TargetField:      "raw_payload",
			MatchType:        "regex",
			Pattern:          `(?i)(union\s+select|select\s+.*from|or\s+1=1|--\s*$|waitfor\s+delay|sleep\(\d+\))`,
			WindowSeconds:    60,
			HitThreshold:     1,
			Action:           ActionBan,
			BanDurationSec:   86400,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_sqli.json"), sqliRule)

		// 2. rule_traversal.json
		traversalRule := DetectionRule{
			ID:               "RULE-TRAVERSAL-001",
			Name:             "Path Traversal & Arbitrary File Read",
			Description:      "Detects directory traversal sequences and access to sensitive Linux/Windows files",
			Severity:         "HIGH",
			ThreatScore:      75,
			MitreTechniqueID: "T1083",
			Enabled:          true,
			TargetField:      "uri",
			MatchType:        "contains",
			Pattern:          "../",
			WindowSeconds:    60,
			HitThreshold:     2,
			Action:           ActionBan,
			BanDurationSec:   3600,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_traversal.json"), traversalRule)

		// 3. rule_high_entropy.json
		entropyRule := DetectionRule{
			ID:               "RULE-ENTROPY-001",
			Name:             "High Shannon Entropy Payload Obfuscation",
			Description:      "Detects encrypted or packed shellcode, Base64 stagers, and XOR payloads with entropy > 5.2",
			Severity:         "HIGH",
			ThreatScore:      70,
			MitreTechniqueID: "T1027",
			Enabled:          true,
			TargetField:      "raw_payload",
			MatchType:        "shannon_entropy_gt",
			EntropyThreshold: 5.2,
			WindowSeconds:    120,
			HitThreshold:     1,
			Action:           ActionAlertOnly,
			BanDurationSec:   0,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_high_entropy.json"), entropyRule)

		// 4. rule_recon_nmap.json
		nmapRule := DetectionRule{
			ID:               "RULE-RECON-NMAP-001",
			Name:             "Nmap Scripting Engine & Port Sweep Probe",
			Description:      "Detects Nmap NSE scanning, reconnaissance probes, and banner sweeps",
			Severity:         "HIGH",
			ThreatScore:      85,
			MitreTechniqueID: "T1046",
			Enabled:          true,
			TargetField:      "headers",
			MatchType:        "regex",
			Pattern:          `(?i)(nmap\s+nse|nmap\s+scripting\s+engine|nmap\s+probe|nmap\s+vulnscan)`,
			WindowSeconds:    10,
			HitThreshold:     3,
			Action:           ActionBan,
			BanDurationSec:   86400,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_recon_nmap.json"), nmapRule)

		// 5. rule_recon_amass_subdomain.json
		amassRule := DetectionRule{
			ID:               "RULE-RECON-AMASS-001",
			Name:             "OWASP Amass Subdomain Scraping & DNS Fuzzing",
			Description:      "Detects automated reconnaissance headers and high-frequency non-existent vhost sweeps from OWASP Amass",
			Severity:         "MEDIUM",
			ThreatScore:      75,
			MitreTechniqueID: "T1595.002",
			Enabled:          true,
			TargetField:      "headers",
			MatchType:        "regex",
			Pattern:          `(?i)(owasp\s+amass|x-amass-sweep|amass-enum|amass/v\d+)`,
			WindowSeconds:    60,
			HitThreshold:     30,
			Action:           ActionBan,
			BanDurationSec:   86400,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_recon_amass_subdomain.json"), amassRule)

		// 6. rule_fuzzing_gobuster_ffuf.json
		fuzzerRule := DetectionRule{
			ID:               "RULE-FUZZ-GOBUSTER-001",
			Name:             "Endpoint & Directory Brute-Forcers (Gobuster / FFUF / Nikto / SQLmap)",
			Description:      "Detects high-frequency aggressive directory brute-forcing, SQLmap scans, and fuzzer user agents",
			Severity:         "CRITICAL",
			ThreatScore:      90,
			MitreTechniqueID: "T1595.002",
			Enabled:          true,
			TargetField:      "user_agent",
			MatchType:        "regex",
			Pattern:          `(?i)(gobuster|dirbuster|ffuf|wfuzz|nikto|sqlmap)`,
			WindowSeconds:    15,
			HitThreshold:     5,
			Action:           ActionBan,
			BanDurationSec:   86400,
		}
		r.writeRuleJSON(filepath.Join(dir, "rule_fuzzing_gobuster_ffuf.json"), fuzzerRule)

		log.Printf("[INFO] Auto-provisioned default detection rules in %s", dir)
	}
}

func (r *RuleRegistry) writeRuleJSON(path string, rule DetectionRule) {
	data, err := json.MarshalIndent(rule, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0640)
	}
}

// ReloadRules scans the rules directory, validates JSON schemas, pre-compiles regexes,
// and swaps the in-memory pointer atomically.
func (r *RuleRegistry) ReloadRules() (int, int, error) {
	r.mu.RLock()
	dir := r.rulesDir
	r.mu.RUnlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read rules directory %s: %w", dir, err)
	}

	var newRules []*CompiledRule
	newIndex := make(map[string]*CompiledRule)
	activeCount := 0
	disabledCount := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("[WARN] Failed to read rule file %s: %v", filePath, err)
			continue
		}

		var rule DetectionRule
		if err := json.Unmarshal(data, &rule); err != nil {
			log.Printf("[ERROR] Skipping malformed detection rule %s: JSON parse error: %v", filePath, err)
			continue
		}

		if rule.ID == "" {
			rule.ID = strings.TrimSuffix(entry.Name(), ".json")
		}

		compiled := &CompiledRule{DetectionRule: rule}

		// Pre-compile regex if match_type == "regex"
		if rule.MatchType == "regex" && rule.Pattern != "" {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Printf("[ERROR] Skipping rule %s (%s): invalid regex pattern %q: %v", rule.ID, filePath, rule.Pattern, err)
				continue
			}
			compiled.Regex = re
		}

		newRules = append(newRules, compiled)
		newIndex[rule.ID] = compiled

		if rule.Enabled {
			activeCount++
		} else {
			disabledCount++
		}
	}

	// Swap pointers atomically
	r.mu.Lock()
	r.rules = newRules
	r.ruleIndex = newIndex
	// Retain existing metrics
	for _, cr := range newRules {
		if _, ok := r.metrics[cr.ID]; !ok {
			r.metrics[cr.ID] = &RuleMetric{}
		}
	}
	r.mu.Unlock()

	log.Printf("[INFO] Loaded %d active detection rules (%d disabled) from rules directory.", activeCount, disabledCount)
	return activeCount, disabledCount, nil
}

// ToggleRule enables or disables a rule by ID dynamically in-memory without touching disk.
func (r *RuleRegistry) ToggleRule(ruleID string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	rule, ok := r.ruleIndex[ruleID]
	if !ok {
		return false
	}
	rule.Enabled = enabled
	return true
}

// ListRules returns all loaded rules with their runtime metrics.
func (r *RuleRegistry) ListRules() []RuleStateDTO {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]RuleStateDTO, 0, len(r.rules))
	for _, cr := range r.rules {
		m := r.metrics[cr.ID]
		hits := int64(0)
		lastHit := int64(0)
		if m != nil {
			hits = m.TotalHits
			lastHit = m.LastHitMs
		}
		res = append(res, RuleStateDTO{
			DetectionRule: cr.DetectionRule,
			TotalHits:     hits,
			LastHitMs:     lastHit,
		})
	}
	return res
}

// CalculateShannonEntropy measures data randomness in byte/character sequences.
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

// EvaluationResult represents a match and threshold decision from the evaluation pipeline.
type EvaluationResult struct {
	Rule           *DetectionRule
	Triggered      bool
	HitsInWindow   int
	ThresholdMet   bool
	MatchedContent string
}

// EvaluateEvent tests incoming event fields against all enabled detection rules.
// EvaluateEvent tests incoming event fields against all enabled detection rules.
// Supports sliding-window hit threshold aggregation keyed by client_ip + rule_id.
func (r *RuleRegistry) EvaluateEvent(fields map[string]string) []*EvaluationResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clientIP := fields["client_ip"]
	if clientIP == "" {
		clientIP = fields["source_ip"]
	}
	nowMs := time.Now().UnixMilli()

	var results []*EvaluationResult

	for _, cr := range r.rules {
		if !cr.Enabled {
			continue
		}

		// Extract target field
		targetVal := ""
		switch cr.TargetField {
		case "uri", "url", "path":
			targetVal = fields["uri"]
			if targetVal == "" {
				targetVal = fields["url"]
			}
			if targetVal == "" {
				targetVal = fields["raw_payload"]
			}
		case "user_agent", "user-agent", "agent":
			targetVal = fields["user_agent"]
			if targetVal == "" {
				targetVal = fields["headers"]
			}
			if targetVal == "" {
				targetVal = fields["raw_line"]
			}
		case "headers", "header":
			targetVal = fields["headers"]
			if targetVal == "" {
				targetVal = fields["user_agent"]
			}
			if targetVal == "" {
				targetVal = fields["raw_line"]
			}
		case "source_ip", "client_ip", "ip":
			targetVal = clientIP
		default:
			// "raw_payload" or fallback
			targetVal = fields["raw_payload"]
			if targetVal == "" {
				targetVal = fields["raw"]
			}
			if targetVal == "" {
				targetVal = fields["raw_line"]
			}
		}

		matched := false
		matchedContent := ""

		// Provide both raw and unescaped representation for robust detection
		unescapedVal, err := url.QueryUnescape(targetVal)
		if err != nil {
			unescapedVal = targetVal
		}

		switch cr.MatchType {
		case "contains":
			patLower := strings.ToLower(cr.Pattern)
			if cr.Pattern != "" && (strings.Contains(strings.ToLower(targetVal), patLower) || strings.Contains(strings.ToLower(unescapedVal), patLower)) {
				matched = true
				matchedContent = cr.Pattern
			}
		case "regex":
			if cr.Regex != nil {
				if cr.Regex.MatchString(targetVal) {
					matched = true
					matchedContent = cr.Regex.FindString(targetVal)
				} else if cr.Regex.MatchString(unescapedVal) {
					matched = true
					matchedContent = cr.Regex.FindString(unescapedVal)
				}
			}
		case "shannon_entropy_gt":
			entropy := CalculateShannonEntropy(targetVal)
			if len(targetVal) >= 16 && entropy >= cr.EntropyThreshold {
				matched = true
				matchedContent = fmt.Sprintf("entropy: %.2f", entropy)
			}
		}

		if !matched {
			continue
		}

		// Update metrics (using atomic or localized lookup)
		if m, ok := r.metrics[cr.ID]; ok {
			atomic.AddInt64(&m.TotalHits, 1)
			atomic.StoreInt64(&m.LastHitMs, nowMs)
		}

		// Sliding window threshold correlation
		windowSec := cr.WindowSeconds
		if windowSec <= 0 {
			windowSec = 60
		}
		hitThreshold := cr.HitThreshold
		if hitThreshold <= 0 {
			hitThreshold = 1
		}

		thresholdMet := false
		hitsInWindow := 1

		if hitThreshold > 1 && clientIP != "" {
			corrKey := fmt.Sprintf("%s:%s", clientIP, cr.ID)
			cutoff := nowMs - int64(windowSec*1000)

			var recent []int64
			if val, ok := r.slidingStore.Load(corrKey); ok {
				if oldList, ok2 := val.([]int64); ok2 {
					for _, ts := range oldList {
						if ts >= cutoff {
							recent = append(recent, ts)
						}
					}
				}
			}
			recent = append(recent, nowMs)
			r.slidingStore.Store(corrKey, recent)

			hitsInWindow = len(recent)
			if hitsInWindow >= hitThreshold {
				thresholdMet = true
			}
		} else {
			thresholdMet = true
		}

		ruleCopy := cr.DetectionRule
		results = append(results, &EvaluationResult{
			Rule:           &ruleCopy,
			Triggered:      true,
			HitsInWindow:   hitsInWindow,
			ThresholdMet:   thresholdMet,
			MatchedContent: matchedContent,
		})
	}

	return results
}
