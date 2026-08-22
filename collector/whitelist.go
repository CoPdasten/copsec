package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	// Fast regex for IP extraction in log lines
	ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|::1|::ffff:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}`)

	// Fast regex for HTTP status code extraction in access logs
	// Format: "GET /path HTTP/1.1" 200 1234
	httpStatusRegex = regexp.MustCompile(`\"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+[^\s\"]+(?:\s+HTTP\/[0-9.]+)?\"\s+([1-5]\d{2})\b`)

	// Static builtin fast-path networks
	_, loopbackIPv4Net, _  = net.ParseCIDR("127.0.0.0/8")
	_, loopbackIPv6Net, _  = net.ParseCIDR("::1/128")
	_, tailscaleNet, _     = net.ParseCIDR("100.64.0.0/10")
)

// PreRoutingFilter evaluates fast-path whitelists and HTTP status codes.
type PreRoutingFilter struct {
	mu           sync.RWMutex
	trustedNets  []*net.IPNet
	allowedCodes map[int]bool
}

// WhitelistConfigFile matches the config/whitelist.json structure.
type WhitelistConfigFile struct {
	TrustedCIDRs []string `json:"trusted_cidrs"`
}

// NewPreRoutingFilter initializes the filter with builtin and file-based CIDRs.
func NewPreRoutingFilter(configPath string) *PreRoutingFilter {
	filter := &PreRoutingFilter{
		allowedCodes: map[int]bool{
			400: true,
			403: true,
			404: true,
			500: true,
		},
	}
	filter.loadConfig(configPath)
	return filter
}

func (f *PreRoutingFilter) loadConfig(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[INFO] Whitelist config %s not found or unreadable, using default builtin CIDRs", path)
		return
	}

	var cfg WhitelistConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[WARN] Failed to parse whitelist config %s: %v", path, err)
		return
	}

	f.trustedNets = nil
	for _, cidr := range cfg.TrustedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Invalid CIDR in whitelist: %s (%v)", cidr, err)
			continue
		}
		f.trustedNets = append(f.trustedNets, ipNet)
	}
	log.Printf("[INFO] Loaded %d trusted CIDRs into Pre-Routing Filter", len(f.trustedNets))
}

// ExtractIP extracts the first matching valid IPv4 or IPv6 from the line.
func ExtractIP(line string) net.IP {
	matches := ipRegex.FindAllString(line, -1)
	for _, match := range matches {
		if ip := net.ParseIP(match); ip != nil {
			return ip
		}
	}
	return nil
}

// ExtractHTTPStatus extracts the HTTP status code integer (e.g. 200, 404).
func ExtractHTTPStatus(line string) int {
	matches := httpStatusRegex.FindStringSubmatch(line)
	if len(matches) > 1 {
		code, err := strconv.Atoi(matches[1])
		if err == nil {
			return code
		}
	}
	return 0
}

// IsFastPathWhitelisted checks if an IP is in the loopback, Tailscale, or trusted_cidrs.
func (f *PreRoutingFilter) IsFastPathWhitelisted(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// 1. Built-in Loopback IPv4 (127.0.0.0/8)
	if loopbackIPv4Net.Contains(ip) || ip.IsLoopback() {
		return true
	}

	// 2. Built-in Loopback IPv6 (::1/128)
	if loopbackIPv6Net.Contains(ip) {
		return true
	}

	// 3. Tailscale CGNAT Range (100.64.0.0/10)
	if tailscaleNet.Contains(ip) {
		return true
	}

	// 4. Configured Trusted CIDRs
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, netBlock := range f.trustedNets {
		if netBlock.Contains(ip) {
			return true
		}
	}

	return false
}

// ShouldDrop evaluates whether a LogEntry must be dropped immediately.
// Returns (drop=true, reason) if it should be discarded without regex evaluation.
func (f *PreRoutingFilter) ShouldDrop(entry LogEntry) (bool, string) {
	// 1. Extract IP & Pre-Routing Whitelist check
	ip := ExtractIP(entry.Line)
	if ip != nil && f.IsFastPathWhitelisted(ip) {
		return true, "whitelisted_ip"
	}

	// 2. Nginx/Web HTTP Status Code filter (Phase 1 rule: skip 200 OK / non-suspicious status)
	if entry.Source == "nginx" || strings.Contains(entry.Line, "HTTP/") {
		status := ExtractHTTPStatus(entry.Line)
		if status > 0 {
			// If status is 200 OK or not in [400, 403, 404, 500], drop to prevent False Positive bans
			if !f.allowedCodes[status] {
				return true, "benign_http_status_" + strconv.Itoa(status)
			}
		}
	}

	return false, ""
}

// AddDynamicWhitelist adds an IP to the in-memory filter and persists to whitelist.json.
func (f *PreRoutingFilter) AddDynamicWhitelist(ipStr string, configPath string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return &net.ParseError{Type: "IP address", Text: ipStr}
	}

	cidr := ipStr
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	f.mu.Lock()
	// Check duplicate
	exists := false
	for _, n := range f.trustedNets {
		if n.String() == ipNet.String() {
			exists = true
			break
		}
	}
	if !exists {
		f.trustedNets = append(f.trustedNets, ipNet)
	}

	// Prepare persist list
	var cidrList []string
	for _, n := range f.trustedNets {
		cidrList = append(cidrList, n.String())
	}
	f.mu.Unlock()

	if configPath != "" {
		cfg := WhitelistConfigFile{TrustedCIDRs: cidrList}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err == nil {
			_ = os.WriteFile(configPath, data, 0640)
		}
	}

	log.Printf("[WHITELIST] Dynamically whitelisted %s (%s)", ipStr, ipNet.String())
	return nil
}
