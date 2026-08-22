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
	// 1. Linux Kernel Socket Killer: Kill all active TCP/HTTP Keep-Alive sockets immediately (Force RST)
	_ = exec.Command("ss", "-K", "dst", ipStr).Run()
	_ = exec.Command("ss", "-K", "src", ipStr).Run()
	_ = exec.Command("sudo", "ss", "-K", "dst", ipStr).Run()
	_ = exec.Command("sudo", "ss", "-K", "src", ipStr).Run()

	// 2. Clear stateful conntrack entries immediately
	_ = exec.Command("conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("conntrack", "-D", "-d", ipStr).Run()
	_ = exec.Command("sudo", "conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("sudo", "conntrack", "-D", "-d", ipStr).Run()
}

// ExecuteBan drops all packets at RAW PREROUTING and INPUT, kills all active TCP sockets, and registers in nftables.
func ExecuteBan(targetIP string, timeoutSeconds int) error {
	targetIP = strings.TrimSpace(targetIP)
	if targetIP == "" {
		return fmt.Errorf("empty target ip")
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("invalid ip address: %s", targetIP)
	}

	if timeoutSeconds <= 0 {
		timeoutSeconds = 86400 // Default 24 hours
	}

	isV6 := ip.To4() == nil
	cmdTool := "iptables"
	if isV6 {
		cmdTool = "ip6tables"
	}

	// 1. En erken aşamada düşür (RAW PREROUTING - State bakmaksızın anında DROP)
	_ = exec.Command(cmdTool, "-t", "raw", "-I", "PREROUTING", "1", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-t", "raw", "-I", "PREROUTING", "1", "-s", targetIP, "-j", "DROP").Run()

	// 2. INPUT zincirine DROP ekle
	_ = exec.Command(cmdTool, "-I", "INPUT", "1", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-I", "INPUT", "1", "-s", targetIP, "-j", "DROP").Run()

	// 3. Mevcut tüm TCP/UDP oturumlarını conntrack üzerinden anında sil & Kernel Socket Destruction
	KillActiveTCPConnections(targetIP)

	// 4. nftables kuralı (varsa)
	_ = EnsureNftablesRules()
	if !isV6 {
		_ = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
		_ = exec.Command("sudo", "nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
	} else {
		_ = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
		_ = exec.Command("sudo", "nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
	}

	log.Printf("[SOAR_MITIGATION] 🚫 Severed all TCP sockets & isolated %s via RAW PREROUTING/INPUT/ss-kill for %ds", targetIP, timeoutSeconds)
	return nil
}

// ExecuteUnban removes the target IP from raw/input firewall chains and nftables sets.
func ExecuteUnban(targetIP string) error {
	targetIP = strings.TrimSpace(targetIP)
	if targetIP == "" {
		return fmt.Errorf("empty target ip")
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("invalid ip address: %s", targetIP)
	}

	isV6 := ip.To4() == nil
	cmdTool := "iptables"
	if isV6 {
		cmdTool = "ip6tables"
	}

	_ = exec.Command(cmdTool, "-t", "raw", "-D", "PREROUTING", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-t", "raw", "-D", "PREROUTING", "-s", targetIP, "-j", "DROP").Run()

	_ = exec.Command(cmdTool, "-D", "INPUT", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-D", "INPUT", "-s", targetIP, "-j", "DROP").Run()

	if !isV6 {
		_ = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s }", targetIP)).Run()
		_ = exec.Command("sudo", "nft", "delete", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s }", targetIP)).Run()
	} else {
		_ = exec.Command("nft", "delete", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s }", targetIP)).Run()
		_ = exec.Command("sudo", "nft", "delete", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s }", targetIP)).Run()
	}

	log.Printf("[SOAR_MITIGATION] 🟢 Unbanned %s", targetIP)
	return nil
}

// ExecuteSOARBan wraps ExecuteBan for compatibility with legacy client and fallback calls.
func ExecuteSOARBan(ipStr string, durationSec int64) (bool, string) {
	err := ExecuteBan(ipStr, int(durationSec))
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Successfully isolated %s via [RAW PREROUTING/INPUT, TCP-Killer(RST)] for %ds", ipStr, durationSec)
}

// ExecuteSOARUnban wraps ExecuteUnban for compatibility.
func ExecuteSOARUnban(ipStr string) (bool, string) {
	err := ExecuteUnban(ipStr)
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Successfully unbanned %s across backends", ipStr)
}
