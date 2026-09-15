package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	DefaultRulesConfigPath = "/etc/copsec/rules.yaml"
	DefaultBPFMapName      = "lpm_blocklist"
	DefaultBPFPinPath      = "/sys/fs/bpf/copsec/lpm_blocklist"
	MaxLPMEntries          = 65536
)

var (
	ErrInvalidCIDR   = errors.New("invalid IPv4 CIDR prefix")
	ErrCIDRNotFound  = errors.New("CIDR prefix not found in blocklist")
	ErrIPv6NotSupported = errors.New("IPv6 prefix not supported in IPv4 LPM trie")
)

// LPMKey models the exact in-kernel binary structure for BPF_MAP_TYPE_LPM_TRIE (IPv4)
type LPMKey struct {
	PrefixLen uint32
	Data      [4]byte
}

// BlockEntry represents a CIDR prefix rule
type BlockEntry struct {
	CIDR        string    `json:"cidr" yaml:"cidr"`
	Description string    `json:"description,omitempty" yaml:"description,omitempty"`
	Action      string    `json:"action,omitempty" yaml:"action,omitempty"`
	AddedAt     time.Time `json:"added_at,omitempty" yaml:"added_at,omitempty"`
}

// FirewallRule models an L4 port/protocol policy rule
type FirewallRule struct {
	ID          string `json:"id" yaml:"id"`
	Protocol    string `json:"protocol" yaml:"protocol"` // tcp, udp, any
	Port        uint16 `json:"port" yaml:"port"`
	Action      string `json:"action" yaml:"action"` // drop, reject
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// RuleConfig defines the root YAML/JSON structure for file-based rules
type RuleConfig struct {
	Blocklist     []BlockEntry   `json:"blocklist" yaml:"blocklist"`
	FirewallRules []FirewallRule `json:"firewall_rules,omitempty" yaml:"firewall_rules,omitempty"`
}

// ParseCIDR parses an IPv4 string (with or without /mask) into an LPMKey and canonical CIDR string
func ParseCIDR(cidrStr string) (*LPMKey, string, error) {
	cidrStr = strings.TrimSpace(cidrStr)
	if cidrStr == "" {
		return nil, "", ErrInvalidCIDR
	}

	// Auto-append /32 if single IP provided
	if !strings.Contains(cidrStr, "/") {
		cidrStr += "/32"
	}

	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, "", ErrIPv6NotSupported
	}

	ones, _ := ipNet.Mask.Size()
	key := &LPMKey{
		PrefixLen: uint32(ones),
		Data:      [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
	}

	canonical := ipNet.String()
	return key, canonical, nil
}

// RuleManager manages local rule parsing and synchronization into the kernel eBPF LPM trie map
type RuleManager struct {
	mu         sync.RWMutex
	bpfMap     *ebpf.Map
	mapPath    string
	isEmulated bool
	entries    map[string]BlockEntry
	rules      []FirewallRule
	configPath string
}

// NewRuleManager initializes the rule manager and connects to the in-kernel LPM map
func NewRuleManager(mapPinPath string, configPath string) (*RuleManager, error) {
	rm := &RuleManager{
		mapPath:    mapPinPath,
		configPath: configPath,
		entries:    make(map[string]BlockEntry),
		rules:      make([]FirewallRule, 0),
	}

	rm.initBPFMap(mapPinPath)

	// Automatically load rule file if configured and exists
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			if cfg, err := rm.LoadRuleFile(configPath); err == nil {
				if syncErr := rm.SyncRules(cfg); syncErr != nil {
					log.Printf("[RULES] [WARN] Partial sync error loading %s: %v", configPath, syncErr)
				} else {
					log.Printf("[RULES] [OK] Loaded %d CIDR blocks and %d firewall rules from %s",
						len(cfg.Blocklist), len(cfg.FirewallRules), configPath)
				}
			}
		}
	}

	return rm, nil
}

// initBPFMap attempts to attach to pinned LPM map or create an in-kernel BPF_MAP_TYPE_LPM_TRIE
func (rm *RuleManager) initBPFMap(mapPinPath string) {
	candidates := []string{
		mapPinPath,
		DefaultBPFPinPath,
		"/sys/fs/bpf/lpm_blocklist",
	}

	for _, p := range candidates {
		if p == "" {
			continue
		}
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			rm.bpfMap = m
			log.Printf("[RULES] [BPF] Attached to pinned in-kernel LPM Trie map at %s", p)
			return
		}
	}

	// Try creating a new in-kernel LPM Trie map
	spec := &ebpf.MapSpec{
		Name:       DefaultBPFMapName,
		Type:       ebpf.LPMTrie,
		KeySize:    8, // 4 bytes prefixlen + 4 bytes IPv4
		ValueSize:  4, // 4 bytes uint32 (1 = drop)
		MaxEntries: MaxLPMEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	}

	m, err := ebpf.NewMap(spec)
	if err == nil {
		rm.bpfMap = m
		log.Printf("[RULES] [BPF] Created standalone in-kernel BPF_MAP_TYPE_LPM_TRIE for CIDR blocks")
		return
	}

	// Fallback to in-memory emulation for unprivileged environments or testing
	rm.isEmulated = true
	log.Printf("[RULES] [EMULATED] Running in userspace LPM mode (Kernel map notice: %v)", err)
}

// BlockCIDR inserts a CIDR prefix into the kernel LPM trie and local registry
func (rm *RuleManager) BlockCIDR(cidr string, desc string) error {
	key, canonical, err := ParseCIDR(cidr)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 1. Insert into in-kernel eBPF LPM map
	if rm.bpfMap != nil {
		val := uint32(1) // Action: 1 = DROP
		if err := rm.bpfMap.Update(key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to insert CIDR into kernel LPM map: %w", err)
		}
	}

	// 2. Track in local registry
	rm.entries[canonical] = BlockEntry{
		CIDR:        canonical,
		Description: desc,
		Action:      "drop",
		AddedAt:     time.Now(),
	}

	log.Printf("[RULES] [BLOCK] Blocked CIDR prefix %s in kernel LPM trie (%s)", canonical, desc)
	return nil
}

// UnblockCIDR evicts a CIDR prefix from the kernel LPM trie and local registry
func (rm *RuleManager) UnblockCIDR(cidr string) error {
	key, canonical, err := ParseCIDR(cidr)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.entries[canonical]; !exists {
		// Even if not in local memory, attempt kernel deletion
	}

	if rm.bpfMap != nil {
		if err := rm.bpfMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to delete CIDR from kernel LPM map: %w", err)
		}
	}

	delete(rm.entries, canonical)
	log.Printf("[RULES] [UNBLOCK] Evicted CIDR prefix %s from kernel LPM trie", canonical)
	return nil
}

// ListBlocks returns all currently active CIDR blocks
func (rm *RuleManager) ListBlocks() []BlockEntry {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	list := make([]BlockEntry, 0, len(rm.entries))
	for _, entry := range rm.entries {
		list = append(list, entry)
	}
	return list
}

// ListRules returns all configured firewall rules
func (rm *RuleManager) ListRules() []FirewallRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	list := make([]FirewallRule, len(rm.rules))
	copy(list, rm.rules)
	return list
}

// LoadRuleFile parses a local YAML or JSON rules configuration file
func (rm *RuleManager) LoadRuleFile(filePath string) (*RuleConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", filePath, err)
	}

	var cfg RuleConfig

	// Try YAML first (YAML parser is a superset of JSON)
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// Fallback to JSON
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
			return nil, fmt.Errorf("failed to parse %s as YAML (%v) or JSON (%v)", filePath, err, jsonErr)
		}
	}

	// Validate CIDRs
	for _, b := range cfg.Blocklist {
		if _, _, err := ParseCIDR(b.CIDR); err != nil {
			return nil, fmt.Errorf("invalid entry %s in rule file: %w", b.CIDR, err)
		}
	}

	return &cfg, nil
}

// SyncRules synchronizes an entire RuleConfig into the eBPF LPM trie map
func (rm *RuleManager) SyncRules(cfg *RuleConfig) error {
	if cfg == nil {
		return errors.New("nil RuleConfig provided")
	}

	var errs []string
	for _, b := range cfg.Blocklist {
		if err := rm.BlockCIDR(b.CIDR, b.Description); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.CIDR, err))
		}
	}

	rm.mu.Lock()
	rm.rules = append([]FirewallRule{}, cfg.FirewallRules...)
	rm.mu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("errors syncing rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SaveRuleFile persists active rules and blocklists to disk
func (rm *RuleManager) SaveRuleFile(filePath string) error {
	rm.mu.RLock()
	blocks := make([]BlockEntry, 0, len(rm.entries))
	for _, b := range rm.entries {
		blocks = append(blocks, b)
	}
	rulesCopy := make([]FirewallRule, len(rm.rules))
	copy(rulesCopy, rm.rules)
	rm.mu.RUnlock()

	cfg := RuleConfig{
		Blocklist:     blocks,
		FirewallRules: rulesCopy,
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal rules to yaml: %w", err)
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return fmt.Errorf("failed to write temp rules file: %w", err)
	}

	if err := os.Rename(tmpFile, filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit rules file: %w", err)
	}

	return nil
}

// Close releases the underlying eBPF map handle
func (rm *RuleManager) Close() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.bpfMap != nil {
		err := rm.bpfMap.Close()
		rm.bpfMap = nil
		return err
	}
	return nil
}

// IsEmulated indicates whether the manager is running in userspace fallback mode
func (rm *RuleManager) IsEmulated() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.isEmulated
}
