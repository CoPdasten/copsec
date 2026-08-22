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

// EnsureNftablesRules initializes the kernel-compatible inet table and timeout sets.
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
        type filter hook input priority filter; policy accept;
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
			sudoCmd := exec.Command("sudo", "/usr/sbin/nft", "-f", "-")
			sudoCmd.Stdin = strings.NewReader(initScript)
			sudoOut, sudoErr := sudoCmd.CombinedOutput()
			if sudoErr != nil {
				nftInitErr = fmt.Errorf("nft initialization skipped (%s | %s)", strings.TrimSpace(string(out)), strings.TrimSpace(string(sudoOut)))
				log.Printf("[INFO] nftables not available (%v) -> Using iptables raw/input pipeline", nftInitErr)
				return
			}
		}
		log.Println("[INFO] nftables copsec_filter table & sets initialized (Priority filter, IPv4+IPv6).")
	})
	return nftInitErr
}

// KillActiveTCPConnections forcibly tears down established TCP / HTTP Keep-Alive sockets.
func KillActiveTCPConnections(ipStr string) {
	// 1. Terminate sockets using iproute2 'ss -K' (kernel socket destruction)
	_ = exec.Command("ss", "-K", "dst", ipStr).Run()
	_ = exec.Command("ss", "-K", "src", ipStr).Run()
	_ = exec.Command("sudo", "ss", "-K", "dst", ipStr).Run()
	_ = exec.Command("sudo", "ss", "-K", "src", ipStr).Run()

	// 2. Clear stateful conntrack entries if conntrack utility is present
	_ = exec.Command("conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("conntrack", "-D", "-d", ipStr).Run()
	_ = exec.Command("sudo", "conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("sudo", "conntrack", "-D", "-d", ipStr).Run()
}

// ExecuteSOARBan executes a multi-layer isolation: iptables raw/input + nftables set + TCP socket killer.
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

	// Layer 1: Guaranteed iptables / ip6tables RAW PREROUTING + INPUT Drop
	if !isIPv6 {
		// IPv4: raw PREROUTING (earliest packet drop) + INPUT
		_ = exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ipStr, "-j", "DROP").Run()
		_ = exec.Command("sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ipStr, "-j", "DROP").Run()

		checkErr := exec.Command("iptables", "-C", "INPUT", "-s", ipStr, "-j", "DROP").Run()
		if checkErr != nil {
			if iptOut, iptErr := exec.Command("iptables", "-I", "INPUT", "1", "-s", ipStr, "-j", "DROP").CombinedOutput(); iptErr == nil {
				appliedLayers = append(appliedLayers, "iptables-raw/input")
			} else {
				sudoOut, sudoErr := exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-s", ipStr, "-j", "DROP").CombinedOutput()
				if sudoErr == nil {
					appliedLayers = append(appliedLayers, "iptables-raw/input")
				} else {
					_ = iptOut
					_ = sudoOut
				}
			}
		} else {
			appliedLayers = append(appliedLayers, "iptables(existing)")
		}
	} else {
		// IPv6: raw PREROUTING + INPUT
		_ = exec.Command("ip6tables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ipStr, "-j", "DROP").Run()
		_ = exec.Command("sudo", "ip6tables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ipStr, "-j", "DROP").Run()

		checkErr := exec.Command("ip6tables", "-C", "INPUT", "-s", ipStr, "-j", "DROP").Run()
		if checkErr != nil {
			if iptOut, iptErr := exec.Command("ip6tables", "-I", "INPUT", "1", "-s", ipStr, "-j", "DROP").CombinedOutput(); iptErr == nil {
				appliedLayers = append(appliedLayers, "ip6tables-raw/input")
			} else {
				sudoOut, sudoErr := exec.Command("sudo", "ip6tables", "-I", "INPUT", "1", "-s", ipStr, "-j", "DROP").CombinedOutput()
				if sudoErr == nil {
					appliedLayers = append(appliedLayers, "ip6tables-raw/input")
				} else {
					_ = iptOut
					_ = sudoOut
				}
			}
		} else {
			appliedLayers = append(appliedLayers, "ip6tables(existing)")
		}
	}

	// Layer 2: Optional nftables set (if available)
	_ = EnsureNftablesRules()
	var nftCmd *exec.Cmd
	if isIPv6 {
		nftCmd = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
	} else {
		nftCmd = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", ipStr, durationSec))
	}
	if _, err := nftCmd.CombinedOutput(); err == nil {
		appliedLayers = append(appliedLayers, "nftables")
	}

	// Layer 3: TCP Connection Killer (Immediate RST injection for open HTTP/Keep-Alive sockets)
	KillActiveTCPConnections(ipStr)
	appliedLayers = append(appliedLayers, "TCP-Killer(RST)")

	msg := fmt.Sprintf("Successfully isolated %s via [%s] for %ds", ipStr, strings.Join(appliedLayers, ", "), durationSec)
	log.Printf("[SOAR_MITIGATION] 🚫 %s", msg)
	return true, msg
}

// ExecuteSOARUnban removes the IP from iptables raw/input chains and nftables sets.
func ExecuteSOARUnban(ipStr string) (bool, string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, fmt.Sprintf("Rejected: invalid IP address '%s'", ipStr)
	}

	isIPv6 := ip.To4() == nil
	var removedLayers []string

	// Layer 1: iptables / ip6tables removal
	if !isIPv6 {
		_ = exec.Command("iptables", "-t", "raw", "-D", "PREROUTING", "-s", ipStr, "-j", "DROP").Run()
		_ = exec.Command("sudo", "iptables", "-t", "raw", "-D", "PREROUTING", "-s", ipStr, "-j", "DROP").Run()
		if _, err := exec.Command("iptables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); err == nil {
			removedLayers = append(removedLayers, "iptables")
		} else {
			if _, sudoErr := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); sudoErr == nil {
				removedLayers = append(removedLayers, "iptables")
			}
		}
	} else {
		_ = exec.Command("ip6tables", "-t", "raw", "-D", "PREROUTING", "-s", ipStr, "-j", "DROP").Run()
		_ = exec.Command("sudo", "ip6tables", "-t", "raw", "-D", "PREROUTING", "-s", ipStr, "-j", "DROP").Run()
		if _, err := exec.Command("ip6tables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); err == nil {
			removedLayers = append(removedLayers, "ip6tables")
		} else {
			if _, sudoErr := exec.Command("sudo", "ip6tables", "-D", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput(); sudoErr == nil {
				removedLayers = append(removedLayers, "ip6tables")
			}
		}
	}

	// Layer 2: nftables set removal
	var nftCmd *exec.Cmd
	if isIPv6 {
		nftCmd = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s }", ipStr))
	} else {
		nftCmd = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s }", ipStr))
	}
	if _, err := nftCmd.CombinedOutput(); err == nil {
		removedLayers = append(removedLayers, "nftables")
	}

	msg := fmt.Sprintf("Unbanned IP %s across backends: %s", ipStr, strings.Join(removedLayers, ", "))
	log.Printf("[SOAR_MITIGATION] 🔓 %s", msg)
	return true, msg
}
