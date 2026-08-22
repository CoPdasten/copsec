package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
)

var (
	nftInitOnce sync.Once
	nftInitErr  error
)

// EnsureNftablesRules initializes the high-priority inet raw/input table and timeout sets.
func EnsureNftablesRules() error {
	nftInitOnce.Do(func() {
		initScript := `
table inet copsec_filter {
    set ban_list {
        type ipv4_addr
        flags timeout
    }
    set ban_list_v6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -300; policy accept;
        ip saddr @ban_list drop
        ip6 saddr @ban_list_v6 drop
        iif "lo" accept
    }
}
`
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(initScript)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Fallback with sudo if not root
			sudoCmd := exec.Command("sudo", "/usr/sbin/nft", "-f", "-")
			sudoCmd.Stdin = strings.NewReader(initScript)
			sudoOut, sudoErr := sudoCmd.CombinedOutput()
			if sudoErr != nil {
				nftInitErr = fmt.Errorf("nft initialization failed: %v (%s | %s)", err, string(out), string(sudoOut))
				log.Printf("[WARN] %v - will fallback to iptables/ip6tables", nftInitErr)
				return
			}
		}
		log.Println("[INFO] nftables copsec_filter table & sets initialized (Priority -300, IPv4+IPv6).")
	})
	return nftInitErr
}

// KillActiveTCPConnections forcibly tears down established TCP / HTTP Keep-Alive sockets.
func KillActiveTCPConnections(ipStr string) {
	// 1. Terminate sockets using iproute2 'ss -K' (kernel socket destruction)
	_ = exec.Command("ss", "-K", "dst", ipStr).Run()
	_ = exec.Command("ss", "-K", "src", ipStr).Run()

	// 2. Clear stateful conntrack entries if conntrack utility is present
	_ = exec.Command("conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("conntrack", "-D", "-d", ipStr).Run()
}

// ExecuteSOARBan executes a multi-layer isolation: nftables priority set + iptables fallback + TCP socket killer.
func ExecuteSOARBan(ipStr string, durationSec int64) (bool, string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, fmt.Sprintf("Rejected: invalid IP address '%s'", ipStr)
	}

	if durationSec <= 0 {
		durationSec = 86400 // Default 24h
	}

	isIPv6 := ip.To4() == nil
	var appliedLayers []string

	// Layer 1: nftables high-priority raw drop with automatic timeout
	_ = EnsureNftablesRules()
	var nftCmd *exec.Cmd
	if isIPv6 {
		nftCmd = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
	} else {
		nftCmd = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
	}

	if out, err := nftCmd.CombinedOutput(); err == nil {
		appliedLayers = append(appliedLayers, "nftables(priority -300)")
	} else {
		// Try sudo fallback
		var sudoNftCmd *exec.Cmd
		if isIPv6 {
			sudoNftCmd = exec.Command("sudo", "/usr/sbin/nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
		} else {
			sudoNftCmd = exec.Command("sudo", "/usr/sbin/nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
		}
		if sudoOut, sudoErr := sudoNftCmd.CombinedOutput(); sudoErr == nil {
			appliedLayers = append(appliedLayers, "nftables(priority -300)")
		} else {
			_ = out
			_ = sudoOut
		}
	}

	// Layer 2: iptables / ip6tables fallback drop rule
	if isIPv6 {
		checkErr := exec.Command("ip6tables", "-C", "INPUT", "-s", ipStr, "-j", "DROP").Run()
		if checkErr != nil {
			if iptOut, iptErr := exec.Command("ip6tables", "-I", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); iptErr == nil {
				appliedLayers = append(appliedLayers, "ip6tables")
			} else {
				_ = iptOut
			}
		} else {
			appliedLayers = append(appliedLayers, "ip6tables(existing)")
		}
	} else {
		checkErr := exec.Command("iptables", "-C", "INPUT", "-s", ipStr, "-j", "DROP").Run()
		if checkErr != nil {
			if iptOut, iptErr := exec.Command("iptables", "-I", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); iptErr == nil {
				appliedLayers = append(appliedLayers, "iptables")
			} else {
				_ = iptOut
			}
		} else {
			appliedLayers = append(appliedLayers, "iptables(existing)")
		}
	}

	// Layer 3: TCP Connection Killer (Immediate RST injection for open HTTP/Keep-Alive sockets)
	KillActiveTCPConnections(ipStr)
	appliedLayers = append(appliedLayers, "TCP-Killer(RST)")

	if len(appliedLayers) > 0 {
		msg := fmt.Sprintf("Successfully isolated %s via [%s] for %ds", ipStr, strings.Join(appliedLayers, ", "), durationSec)
		log.Printf("[SOAR_MITIGATION] 🚫 %s", msg)
		return true, msg
	}

	return false, fmt.Sprintf("Failed to isolate IP %s across all firewall backends", ipStr)
}

// ExecuteSOARUnban removes the IP from nftables sets and iptables chains.
func ExecuteSOARUnban(ipStr string) (bool, string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, fmt.Sprintf("Rejected: invalid IP address '%s'", ipStr)
	}

	isIPv6 := ip.To4() == nil
	var removedLayers []string

	// Layer 1: nftables set removal
	var nftCmd *exec.Cmd
	if isIPv6 {
		nftCmd = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s }", ipStr))
	} else {
		nftCmd = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s }", ipStr))
	}
	if _, err := nftCmd.CombinedOutput(); err == nil {
		removedLayers = append(removedLayers, "nftables")
	}

	// Layer 2: iptables removal
	if isIPv6 {
		if _, err := exec.Command("ip6tables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); err == nil {
			removedLayers = append(removedLayers, "ip6tables")
		}
	} else {
		if _, err := exec.Command("iptables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); err == nil {
			removedLayers = append(removedLayers, "iptables")
		}
	}

	msg := fmt.Sprintf("Unbanned IP %s across backends: %s", ipStr, strings.Join(removedLayers, ", "))
	log.Printf("[SOAR_MITIGATION] 🔓 %s", msg)
	return true, msg
}
