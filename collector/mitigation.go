package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const NginxBlocklistPath = "/etc/nginx/conf.d/copsec_blocklist.conf"

var (
	nftInitOnce sync.Once
	nftInitErr  error
	blocklistMu sync.Mutex
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

func addNginxDenyRule(ip string) error {
	dir := filepath.Dir(NginxBlocklistPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // Nginx configuration directory does not exist, skip safely
	}

	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	targetEntry := fmt.Sprintf("deny %s;", ip)
	content, err := os.ReadFile(NginxBlocklistPath)
	if err == nil && strings.Contains(string(content), targetEntry) {
		return nil
	}

	f, err := os.OpenFile(NginxBlocklistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, err = f.WriteString(targetEntry + "\n")
		return err
	}

	// Sudo fallback for non-root collector processes
	echoCmd := fmt.Sprintf("echo '%s' >> %s", targetEntry, NginxBlocklistPath)
	return exec.Command("sudo", "sh", "-c", echoCmd).Run()
}

func removeNginxDenyRule(ip string) error {
	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	data, err := os.ReadFile(NginxBlocklistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Try reading with sudo
		out, sudoErr := exec.Command("sudo", "cat", NginxBlocklistPath).CombinedOutput()
		if sudoErr != nil {
			return err
		}
		data = out
	}

	var newLines []string
	targetEntry := fmt.Sprintf("deny %s;", ip)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != targetEntry {
			newLines = append(newLines, trimmed)
		}
	}

	outData := ""
	if len(newLines) > 0 {
		outData = strings.Join(newLines, "\n") + "\n"
	}

	writeErr := os.WriteFile(NginxBlocklistPath, []byte(outData), 0644)
	if writeErr != nil {
		sedCmd := fmt.Sprintf("sed -i '/deny %s;/d' %s", ip, NginxBlocklistPath)
		return exec.Command("sudo", "sh", "-c", sedCmd).Run()
	}
	return nil
}

// isProtectedIP checks if an IP belongs to the local machine, cluster interconnect, or protected CIDRs.
func isProtectedIP(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "localhost" {
		return true
	}
	// Cluster nodes, Controller public IP & Tailscale interconnect (100.64.0.0/10)
	if ipStr == "37.59.108.186" || strings.HasPrefix(ipStr, "100.") {
		return true
	}
	parsed := net.ParseIP(ipStr)
	if parsed != nil {
		return parsed.IsLoopback() || parsed.IsUnspecified()
	}
	return false
}

// ExecuteBan executes Hybrid L3/L4 iptables + Kernel Socket Killer + L7 Nginx WAF isolation.
func ExecuteBan(targetIP string, timeoutSeconds int) error {
	targetIP = strings.TrimSpace(targetIP)
	if targetIP == "" {
		return fmt.Errorf("empty target ip")
	}

	if isProtectedIP(targetIP) {
		log.Printf("[SOAR_SAFEGUARD] 🛡️ Refusing to ban protected/self IP: %s", targetIP)
		return nil
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

	// 1. L3 / L4 Katmanı: Doğrudan gelen TCP paketleri için RAW PREROUTING / INPUT & ss-kill
	_ = exec.Command(cmdTool, "-t", "raw", "-I", "PREROUTING", "1", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-t", "raw", "-I", "PREROUTING", "1", "-s", targetIP, "-j", "DROP").Run()

	_ = exec.Command(cmdTool, "-I", "INPUT", "1", "-s", targetIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", cmdTool, "-I", "INPUT", "1", "-s", targetIP, "-j", "DROP").Run()

	KillActiveTCPConnections(targetIP)

	// 2. nftables desteği
	_ = EnsureNftablesRules()
	if !isV6 {
		_ = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
		_ = exec.Command("sudo", "nft", "add", "element", "inet", "copsec_filter", "ban_list", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
	} else {
		_ = exec.Command("nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
		_ = exec.Command("sudo", "nft", "add", "element", "inet", "copsec_filter", "ban_list_v6", fmt.Sprintf("{ %s timeout %ds }", targetIP, timeoutSeconds)).Run()
	}

	// 3. L7 Katmanı: Nginx Dynamic Blocklist (Cloudflare / Reverse Proxy için)
	if err := addNginxDenyRule(targetIP); err != nil {
		log.Printf("[SOAR_MITIGATION] ⚠️ Failed to update nginx blocklist: %v", err)
	} else {
		_ = exec.Command("nginx", "-s", "reload").Run()
		_ = exec.Command("sudo", "nginx", "-s", "reload").Run()
	}

	log.Printf("[SOAR_MITIGATION] 🚫 [HYBRID BAN] %s blocked via iptables RAW/INPUT + Nginx WAF for %ds", targetIP, timeoutSeconds)
	return nil
}

// ExecuteUnban removes target IP from L3/L4 firewall and L7 Nginx WAF blocklists.
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

	if err := removeNginxDenyRule(targetIP); err == nil {
		_ = exec.Command("nginx", "-s", "reload").Run()
		_ = exec.Command("sudo", "nginx", "-s", "reload").Run()
	}

	log.Printf("[SOAR_MITIGATION] 🟢 [HYBRID UNBAN] %s removed across L3 iptables & L7 Nginx WAF", targetIP)
	return nil
}

// ExecuteSOARBan wraps ExecuteBan for compatibility.
func ExecuteSOARBan(ipStr string, durationSec int64) (bool, string) {
	err := ExecuteBan(ipStr, int(durationSec))
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Successfully isolated %s via [HYBRID L3/L4 iptables + L7 Nginx WAF] for %ds", ipStr, durationSec)
}

// ExecuteSOARUnban wraps ExecuteUnban for compatibility.
func ExecuteSOARUnban(ipStr string) (bool, string) {
	err := ExecuteUnban(ipStr)
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Successfully unbanned %s across backends", ipStr)
}
