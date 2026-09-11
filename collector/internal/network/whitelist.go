package network

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/copsec/collector/pkg/ebpf"
)

const (
	// DefaultWhitelistYAMLPath is the standard enterprise location for trusted subnets.
	DefaultWhitelistYAMLPath = "/etc/copsec/whitelist.yaml"
	// DefaultWhitelistJSONPath is the fallback legacy location.
	DefaultWhitelistJSONPath = "/etc/copsec/whitelist.json"
)

// IPv4Subnet represents a precomputed bitwise IPv4 subnet mask for zero-allocation checks.
type IPv4Subnet struct {
	Network uint32 `json:"network"`
	Mask    uint32 `json:"mask"`
	CIDR    string `json:"cidr"`
	Name    string `json:"name,omitempty"`
}

// CIDRWhitelist implements high-performance, zero-allocation CIDR matching for trusted enterprise zones.
type CIDRWhitelist struct {
	mu         sync.RWMutex
	ipv4Blocks []IPv4Subnet
	exactIPv4s map[uint32]string
	ipv6Nets   []*net.IPNet
	xdpEngine  *ebpf.XDPMitigationEngine
}

var (
	defaultWhitelist *CIDRWhitelist
	whitelistOnce    sync.Once
)

// GetDefaultWhitelist returns the singleton instance of the enterprise CIDR whitelist.
func GetDefaultWhitelist() *CIDRWhitelist {
	whitelistOnce.Do(func() {
		defaultWhitelist = NewCIDRWhitelist()
		// Try loading from standard configuration paths if present
		if err := defaultWhitelist.LoadFromFile(DefaultWhitelistYAMLPath); err != nil {
			_ = defaultWhitelist.LoadFromFile(DefaultWhitelistJSONPath)
		}
	})
	return defaultWhitelist
}

// NewCIDRWhitelist initializes a whitelist engine pre-populated with RFC 1918 & loopback ranges.
func NewCIDRWhitelist() *CIDRWhitelist {
	w := &CIDRWhitelist{
		ipv4Blocks: make([]IPv4Subnet, 0, 32),
		exactIPv4s: make(map[uint32]string),
		ipv6Nets:   make([]*net.IPNet, 0, 8),
		xdpEngine:  ebpf.GetXDPEngine(),
	}

	// Pre-populate enterprise RFC 1918 and loopback defaults:
	// - 127.0.0.1/32 (Localhost single address)
	// - 127.0.0.0/8 (Localhost entire block)
	// - 10.0.0.0/8 (RFC 1918 Class A)
	// - 172.16.0.0/12 (RFC 1918 Class B)
	// - 192.168.0.0/16 (RFC 1918 Class C)
	// - ::1/128 (IPv6 Localhost)
	_ = w.AddCIDR("127.0.0.1/32", "Loopback Host")
	_ = w.AddCIDR("127.0.0.0/8", "Loopback Subnet")
	_ = w.AddCIDR("10.0.0.0/8", "RFC1918 Private Class A")
	_ = w.AddCIDR("172.16.0.0/12", "RFC1918 Private Class B")
	_ = w.AddCIDR("192.168.0.0/16", "RFC1918 Private Class C")
	_ = w.AddCIDR("::1/128", "IPv6 Loopback")

	return w
}

// IsWhitelisted evaluates an IPv4/IPv6 address against the CIDR whitelist.
// For IPv4, execution uses purely bitwise operations and requires zero heap allocations.
func (w *CIDRWhitelist) IsWhitelisted(ipStr string) bool {
	clean := strings.TrimSpace(ipStr)
	if clean == "" || clean == "-" || clean == "localhost" {
		return true
	}

	// 1. Zero-allocation bitwise IPv4 evaluation
	if ipVal, ok := parseIPv4ToUint32(clean); ok {
		w.mu.RLock()
		defer w.mu.RUnlock()

		// Direct /32 hit
		if _, exists := w.exactIPv4s[ipVal]; exists {
			return true
		}

		// Fast bitwise subnet mask evaluation
		for _, sub := range w.ipv4Blocks {
			if (ipVal & sub.Mask) == sub.Network {
				return true
			}
		}

		return false
	}

	// 2. IPv6 evaluation
	parsed := net.ParseIP(clean)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() {
		return true
	}

	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, ipNet := range w.ipv6Nets {
		if ipNet.Contains(parsed) {
			return true
		}
	}

	return false
}

// AddCIDR parses and registers an IPv4 or IPv6 CIDR block into the whitelist.
func (w *CIDRWhitelist) AddCIDR(cidrStr string, name ...string) error {
	clean := strings.TrimSpace(cidrStr)
	if clean == "" {
		return fmt.Errorf("empty CIDR entry")
	}

	// If single IP without slash, treat as /32 (or /128)
	if !strings.Contains(clean, "/") {
		if strings.Contains(clean, ":") {
			clean += "/128"
		} else {
			clean += "/32"
		}
	}

	ip, ipNet, err := net.ParseCIDR(clean)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation %s: %w", cidrStr, err)
	}

	entryName := ""
	if len(name) > 0 {
		entryName = name[0]
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// IPv4 Subnet registration
	if ip4 := ip.To4(); ip4 != nil {
		ipVal := (uint32(ip4[0]) << 24) | (uint32(ip4[1]) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
		maskVal := (uint32(ipNet.Mask[0]) << 24) | (uint32(ipNet.Mask[1]) << 16) | (uint32(ipNet.Mask[2]) << 8) | uint32(ipNet.Mask[3])
		netVal := ipVal & maskVal

		if maskVal == 0xFFFFFFFF {
			w.exactIPv4s[netVal] = entryName
		}

		// Avoid duplicate CIDRs
		for _, existing := range w.ipv4Blocks {
			if existing.Network == netVal && existing.Mask == maskVal {
				return nil
			}
		}

		w.ipv4Blocks = append(w.ipv4Blocks, IPv4Subnet{
			Network: netVal,
			Mask:    maskVal,
			CIDR:    clean,
			Name:    entryName,
		})

		// Optionally inject into in-kernel eBPF whitelisted_ips map
		if w.xdpEngine != nil && maskVal == 0xFFFFFFFF {
			_ = w.xdpEngine.AddWhitelistIP(ip4.String())
		}

		return nil
	}

	// IPv6 Subnet registration
	for _, existing := range w.ipv6Nets {
		if existing.String() == ipNet.String() {
			return nil
		}
	}
	w.ipv6Nets = append(w.ipv6Nets, ipNet)
	return nil
}

// RemoveCIDR removes a previously registered block from the whitelist.
func (w *CIDRWhitelist) RemoveCIDR(cidrStr string) error {
	clean := strings.TrimSpace(cidrStr)
	if !strings.Contains(clean, "/") {
		if strings.Contains(clean, ":") {
			clean += "/128"
		} else {
			clean += "/32"
		}
	}

	ip, ipNet, err := net.ParseCIDR(clean)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		ipVal := (uint32(ip4[0]) << 24) | (uint32(ip4[1]) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
		maskVal := (uint32(ipNet.Mask[0]) << 24) | (uint32(ipNet.Mask[1]) << 16) | (uint32(ipNet.Mask[2]) << 8) | uint32(ipNet.Mask[3])
		netVal := ipVal & maskVal

		delete(w.exactIPv4s, netVal)

		filtered := make([]IPv4Subnet, 0, len(w.ipv4Blocks))
		for _, sub := range w.ipv4Blocks {
			if !(sub.Network == netVal && sub.Mask == maskVal) {
				filtered = append(filtered, sub)
			}
		}
		w.ipv4Blocks = filtered

		if w.xdpEngine != nil && maskVal == 0xFFFFFFFF {
			_ = w.xdpEngine.RemoveWhitelistIP(ip4.String())
		}
		return nil
	}

	filteredV6 := make([]*net.IPNet, 0, len(w.ipv6Nets))
	for _, sub := range w.ipv6Nets {
		if sub.String() != ipNet.String() {
			filteredV6 = append(filteredV6, sub)
		}
	}
	w.ipv6Nets = filteredV6
	return nil
}

// LoadFromFile reads and parses whitelist definitions from YAML or JSON.
func (w *CIDRWhitelist) LoadFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if strings.HasSuffix(filePath, ".json") {
		return w.LoadFromJSON(data)
	}
	return w.LoadFromYAML(data)
}

// LoadFromYAML parses zero-dependency YAML whitelist documents.
// Supports both "trusted_cidrs: [...]" and list format "- <cidr>".
func (w *CIDRWhitelist) LoadFromYAML(yamlData []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(yamlData))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "trusted_cidrs:") || strings.HasPrefix(trimmed, "whitelist:") {
			continue
		}

		cleanItem := strings.TrimPrefix(trimmed, "-")
		cleanItem = strings.Trim(cleanItem, " \t\"'")
		if colonIdx := strings.Index(cleanItem, ":"); colonIdx > 0 && !strings.Contains(cleanItem, "/") {
			// Key-value pair like "cidr: 10.0.0.0/8"
			cleanItem = strings.Trim(cleanItem[colonIdx+1:], " \t\"'")
		}

		if len(cleanItem) > 0 {
			_ = w.AddCIDR(cleanItem)
		}
	}

	log.Printf("[WHITELIST] 🛡️ Loaded enterprise CIDR whitelist from YAML (%d active IPv4 blocks)", len(w.ipv4Blocks))
	return nil
}

// LoadFromJSON parses legacy JSON whitelist files.
func (w *CIDRWhitelist) LoadFromJSON(jsonData []byte) error {
	var cfg struct {
		TrustedCIDRs []string `json:"trusted_cidrs"`
	}
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return err
	}

	for _, c := range cfg.TrustedCIDRs {
		_ = w.AddCIDR(c)
	}
	log.Printf("[WHITELIST] 🛡️ Loaded enterprise CIDR whitelist from JSON (%d active IPv4 blocks)", len(w.ipv4Blocks))
	return nil
}

// ListCIDRs returns all active whitelisted CIDR strings.
func (w *CIDRWhitelist) ListCIDRs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	res := make([]string, 0, len(w.ipv4Blocks)+len(w.ipv6Nets))
	for _, sub := range w.ipv4Blocks {
		res = append(res, sub.CIDR)
	}
	for _, sub := range w.ipv6Nets {
		res = append(res, sub.String())
	}
	return res
}

// parseIPv4ToUint32 converts a dotted IPv4 decimal string into a 32-bit unsigned integer without heap allocations.
func parseIPv4ToUint32(s string) (uint32, bool) {
	var val uint32
	var octet uint32
	var dots int
	var emptyOctet = true

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			octet = octet*10 + uint32(c-'0')
			if octet > 255 {
				return 0, false
			}
			emptyOctet = false
		} else if c == '.' {
			if emptyOctet || dots >= 3 {
				return 0, false
			}
			val = (val << 8) | octet
			octet = 0
			dots++
			emptyOctet = true
		} else {
			return 0, false
		}
	}

	if dots != 3 || emptyOctet {
		return 0, false
	}
	val = (val << 8) | octet
	return val, true
}
