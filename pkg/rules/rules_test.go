package rules

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		input       string
		expectedLen uint32
		expectedIP  [4]byte
		expectErr   bool
	}{
		{"192.0.2.0/24", 24, [4]byte{192, 0, 2, 0}, false},
		{"198.51.100.14/32", 32, [4]byte{198, 51, 100, 14}, false},
		{"10.0.0.1", 32, [4]byte{10, 0, 0, 1}, false}, // Auto /32
		{"172.16.0.0/12", 12, [4]byte{172, 16, 0, 0}, false},
		{"invalid-ip", 0, [4]byte{}, true},
		{"2001:db8::/32", 0, [4]byte{}, true}, // IPv6 not supported in v4 trie
	}

	for _, tt := range tests {
		k, canon, err := ParseCIDR(tt.input)
		if tt.expectErr {
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("Unexpected error for %s: %v", tt.input, err)
			continue
		}
		if k.PrefixLen != tt.expectedLen {
			t.Errorf("For %s, expected prefix len %d, got %d", tt.input, tt.expectedLen, k.PrefixLen)
		}
		if k.Data != tt.expectedIP {
			t.Errorf("For %s, expected IP %v, got %v", tt.input, tt.expectedIP, k.Data)
		}
		if canon == "" {
			t.Errorf("For %s, canonical representation was empty", tt.input)
		}
	}
}

func TestRuleManager_BlockAndUnblock(t *testing.T) {
	rm, err := NewRuleManager("", "")
	if err != nil {
		t.Fatalf("NewRuleManager failed: %v", err)
	}
	defer rm.Close()

	cidr := "192.0.2.0/24"
	if err := rm.BlockCIDR(cidr, "TEST-NET-1 malicious scanner"); err != nil {
		t.Fatalf("BlockCIDR failed: %v", err)
	}

	blocks := rm.ListBlocks()
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(blocks))
	}
	if blocks[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s, got %s", cidr, blocks[0].CIDR)
	}

	// Unblock
	if err := rm.UnblockCIDR(cidr); err != nil {
		t.Fatalf("UnblockCIDR failed: %v", err)
	}

	blocksAfter := rm.ListBlocks()
	if len(blocksAfter) != 0 {
		t.Errorf("Expected 0 blocks after unblock, got %d", len(blocksAfter))
	}
}

func TestRuleManager_LoadRuleFile_YAML(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")

	yamlContent := `
blocklist:
  - cidr: 192.0.2.0/24
    description: Documentation TEST-NET-1
    action: drop
  - cidr: 198.51.100.14/32
    description: Malicious Scanner
    action: drop

firewall_rules:
  - id: drop-telnet
    protocol: tcp
    port: 23
    action: drop
    description: Drop unencrypted Telnet
  - id: drop-rdp
    protocol: tcp
    port: 3389
    action: drop
`
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test rules.yaml: %v", err)
	}

	rm, err := NewRuleManager("", rulesPath)
	if err != nil {
		t.Fatalf("NewRuleManager failed: %v", err)
	}
	defer rm.Close()

	blocks := rm.ListBlocks()
	if len(blocks) != 2 {
		t.Errorf("Expected 2 blocks loaded from YAML, got %d", len(blocks))
	}

	rules := rm.ListRules()
	if len(rules) != 2 {
		t.Errorf("Expected 2 firewall rules loaded from YAML, got %d", len(rules))
	}
}

func TestRuleManager_LoadRuleFile_JSON(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")

	jsonContent := `{
  "blocklist": [
    {"cidr": "203.0.113.0/24", "description": "TEST-NET-3", "action": "drop"}
  ],
  "firewall_rules": [
    {"id": "drop-ssh", "protocol": "tcp", "port": 2222, "action": "drop"}
  ]
}`
	if err := os.WriteFile(rulesPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("Failed to write test rules.json: %v", err)
	}

	rm, err := NewRuleManager("", rulesPath)
	if err != nil {
		t.Fatalf("NewRuleManager failed: %v", err)
	}
	defer rm.Close()

	blocks := rm.ListBlocks()
	if len(blocks) != 1 {
		t.Errorf("Expected 1 block loaded from JSON, got %d", len(blocks))
	}
}

func TestRuleManager_SaveRuleFile(t *testing.T) {
	dir := t.TempDir()
	savePath := filepath.Join(dir, "exported_rules.yaml")

	rm, err := NewRuleManager("", "")
	if err != nil {
		t.Fatalf("NewRuleManager failed: %v", err)
	}
	defer rm.Close()

	_ = rm.BlockCIDR("10.50.0.0/16", "Internal quarantine subnet")
	_ = rm.BlockCIDR("192.168.100.5/32", "Rogue host")

	if err := rm.SaveRuleFile(savePath); err != nil {
		t.Fatalf("SaveRuleFile failed: %v", err)
	}

	// Verify file exists and can be reloaded
	reloaded, err := rm.LoadRuleFile(savePath)
	if err != nil {
		t.Fatalf("Failed to reload exported rules: %v", err)
	}

	if len(reloaded.Blocklist) != 2 {
		t.Errorf("Expected 2 exported blocklist entries, got %d", len(reloaded.Blocklist))
	}
}

func TestRuleManager_Concurrent_Race(t *testing.T) {
	rm, err := NewRuleManager("", "")
	if err != nil {
		t.Fatalf("NewRuleManager failed: %v", err)
	}
	defer rm.Close()

	var wg sync.WaitGroup
	workers := 10
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cidr := "10.0.0.0/24"
				if j%2 == 0 {
					_ = rm.BlockCIDR(cidr, "dynamic")
				} else {
					_ = rm.UnblockCIDR(cidr)
				}
				_ = rm.ListBlocks()
				_ = rm.ListRules()
			}
		}(i)
	}

	wg.Wait()
}
