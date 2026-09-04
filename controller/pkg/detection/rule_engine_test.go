package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRuleEngineRegexAndSubstringMatching(t *testing.T) {
	tempDir := t.TempDir()
	reg := NewRuleRegistry(tempDir)

	// Verify defaults auto-provisioned
	rules := reg.ListRules()
	if len(rules) < 3 {
		t.Fatalf("Expected at least 3 auto-provisioned rules, got %d", len(rules))
	}

	// 1. Test SQLi Regex Rule
	sqliPayload := "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1"
	fieldsSQLi := map[string]string{
		"client_ip":   "198.51.100.12",
		"raw_payload": sqliPayload,
	}
	results := reg.EvaluateEvent(fieldsSQLi)
	foundSQLi := false
	for _, res := range results {
		if res.Rule.ID == "RULE-SQLI-001" {
			foundSQLi = true
			if !res.ThresholdMet {
				t.Errorf("Expected threshold to be met immediately for SQLi hit")
			}
			if res.Rule.Action != ActionBan {
				t.Errorf("Expected ActionBan, got %s", res.Rule.Action)
			}
		}
	}
	if !foundSQLi {
		t.Errorf("RULE-SQLI-001 failed to detect UNION SELECT payload")
	}

	// 2. Test Path Traversal Substring & HitThreshold=2
	fieldsTrav1 := map[string]string{
		"client_ip": "198.51.100.15",
		"uri":       "/download?file=../../etc/passwd",
	}
	resTrav1 := reg.EvaluateEvent(fieldsTrav1)
	for _, res := range resTrav1 {
		if res.Rule.ID == "RULE-TRAVERSAL-001" {
			// Hit 1: ThresholdMet should be false because hit_threshold is 2
			if res.ThresholdMet {
				t.Errorf("Expected threshold NOT to be met on 1st traversal hit (hit_threshold=2)")
			}
		}
	}

	// Hit 2: ThresholdMet should now be true
	resTrav2 := reg.EvaluateEvent(fieldsTrav1)
	hit2Met := false
	for _, res := range resTrav2 {
		if res.Rule.ID == "RULE-TRAVERSAL-001" {
			if res.ThresholdMet {
				hit2Met = true
			}
		}
	}
	if !hit2Met {
		t.Errorf("Expected threshold to be met on 2nd traversal hit for same IP")
	}

	// 3. Test High Entropy Detection (> 5.2)
	highEntropyPayload := "k7V!9#mQ$1zP@8wL^3xR&0tY*5uI(2oK)4pE_6sD+8fG=0hJ"
	fieldsEntropy := map[string]string{
		"client_ip":   "198.51.100.99",
		"raw_payload": highEntropyPayload,
	}
	resEntropy := reg.EvaluateEvent(fieldsEntropy)
	foundEntropy := false
	for _, res := range resEntropy {
		if res.Rule.ID == "RULE-ENTROPY-001" {
			foundEntropy = true
		}
	}
	if !foundEntropy {
		t.Errorf("RULE-ENTROPY-001 failed to detect high entropy payload")
	}
}

func TestInvalidRuleSyntaxIsolation(t *testing.T) {
	tempDir := t.TempDir()
	reg := NewRuleRegistry(tempDir)

	// Write an invalid regex rule
	badJSON := `{
		"id": "RULE-BAD-REGEX",
		"name": "Invalid Regex Rule",
		"match_type": "regex",
		"pattern": "[a-z(+?invalid(",
		"enabled": true
	}`
	_ = os.WriteFile(filepath.Join(tempDir, "bad_rule.json"), []byte(badJSON), 0640)

	// Write a malformed JSON file
	_ = os.WriteFile(filepath.Join(tempDir, "malformed.json"), []byte("{not-valid-json"), 0640)

	// Reload rules: Server must not crash and valid rules must continue functioning
	active, _, err := reg.ReloadRules()
	if err != nil {
		t.Fatalf("ReloadRules returned unexpected fatal error: %v", err)
	}

	if active < 3 {
		t.Errorf("Expected at least 3 valid rules to remain active despite bad files, got %d", active)
	}

	// Verify valid rules still evaluate cleanly
	fields := map[string]string{
		"client_ip":   "198.51.100.1",
		"raw_payload": "UNION SELECT 1,2",
	}
	res := reg.EvaluateEvent(fields)
	if len(res) == 0 {
		t.Errorf("Valid rules should still trigger after skipping bad rules")
	}
}

func TestConcurrentEvaluationAndHotReloadRace(t *testing.T) {
	tempDir := t.TempDir()
	reg := NewRuleRegistry(tempDir)

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Traffic evaluation goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					fields := map[string]string{
						"client_ip":   fmt.Sprintf("198.51.100.%d", workerID),
						"raw_payload": "SELECT * FROM users WHERE id = 1 OR 1=1",
					}
					_ = reg.EvaluateEvent(fields)
				}
			}
		}(i)
	}

	// Rule reload goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			_, _, _ = reg.ReloadRules()
			reg.ToggleRule("RULE-SQLI-001", j%2 == 0)
		}
		close(stopChan)
	}()

	wg.Wait()
}
