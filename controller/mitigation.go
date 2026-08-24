package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	banLock     sync.Mutex
	bannedIPMap sync.Map
)

// isProtectedIP checks if an IP belongs to local machine, private networks, or protected ranges.
func isProtectedIP(ipStr string) bool {
	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP == "" || cleanIP == "127.0.0.1" || cleanIP == "::1" || cleanIP == "localhost" {
		return true
	}
	if cleanIP == "37.59.108.186" || strings.HasPrefix(cleanIP, "100.") {
		return true
	}
	parsed := net.ParseIP(cleanIP)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return true
	}
	return false
}

// ExecuteInstantBan: Zero-Latency Hybrid Mitigation (L3/L4 immediate, L7 async in background)
func ExecuteInstantBan(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	if isProtectedIP(cleanIP) {
		log.Printf("[SOAR_MITIGATION] ⚠️ Skip ban for protected/invalid IP: %s", cleanIP)
		return fmt.Errorf("protected/invalid ip: %s", cleanIP)
	}

	banLock.Lock()
	if _, exists := bannedIPMap.Load(cleanIP); exists {
		banLock.Unlock()
		return nil
	}
	bannedIPMap.Store(cleanIP, true)
	banLock.Unlock()

	// 1. ANLIK L3 İMHA (Kernel PREROUTING & INPUT)
	_ = exec.Command("sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", cleanIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-s", cleanIP, "-j", "DROP").Run()

	// 2. ANLIK L4 SOKET VE KERNEL STATE TEMİZLİĞİ (0 Gecikme)
	_ = exec.Command("sudo", "conntrack", "-D", "-s", cleanIP).Run()
	_ = exec.Command("sudo", "conntrack", "-D", "-d", cleanIP).Run()
	_ = exec.Command("sudo", "ss", "-K", "dst", cleanIP).Run()
	_ = exec.Command("sudo", "ss", "-K", "src", cleanIP).Run()

	// 3. ASENKRON L7 NGINX WAF (Arka planda reload etsin, ana akışı bekletmesin)
	go func(targetIP string) {
		blocklistPath := "/etc/nginx/conf.d/copsec_blocklist.conf"
		data, _ := os.ReadFile(blocklistPath)
		if !strings.Contains(string(data), fmt.Sprintf("deny %s;", targetIP)) {
			f, err := os.OpenFile(blocklistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				_, _ = f.WriteString(fmt.Sprintf("deny %s;\n", targetIP))
				_ = f.Close()
				if err := exec.Command("sudo", "nginx", "-t").Run(); err == nil {
					_ = exec.Command("sudo", "nginx", "-s", "reload").Run()
				}
			}
		}
	}(cleanIP)

	log.Printf("[SOAR_MITIGATION] ⚡ ZERO-LATENCY BAN EXECUTED: %s", cleanIP)
	return nil
}

// ExecuteAbsoluteBan: L3 (RAW/INPUT), L4 (Socket/Conntrack Kill) ve L7 (Nginx WAF) Hibrit İnfaz
func ExecuteAbsoluteBan(ip string) error {
	return ExecuteInstantBan(ip)
}

// ExecuteAbsoluteUnban: İnfazı tüm katmanlardan eksiksiz temizleme
func ExecuteAbsoluteUnban(ip string) error {
	banLock.Lock()
	defer banLock.Unlock()

	ip = strings.TrimSpace(ip)

	// 1. iptables Kurallarını Kaldır
	_ = exec.Command("sudo", "iptables", "-t", "raw", "-D", "PREROUTING", "-s", ip, "-j", "DROP").Run()
	_ = exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()

	// 2. Nginx Blocklist Dosyasından Çıkar
	blocklistPath := "/etc/nginx/conf.d/copsec_blocklist.conf"
	data, err := os.ReadFile(blocklistPath)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var cleanLines []string
		target := fmt.Sprintf("deny %s;", ip)
		for _, l := range lines {
			if strings.TrimSpace(l) != target && strings.TrimSpace(l) != "" {
				cleanLines = append(cleanLines, l)
			}
		}
		newContent := strings.Join(cleanLines, "\n")
		if len(cleanLines) > 0 {
			newContent += "\n"
		}
		_ = os.WriteFile(blocklistPath, []byte(newContent), 0644)
		if err := exec.Command("sudo", "nginx", "-t").Run(); err == nil {
			_ = exec.Command("sudo", "nginx", "-s", "reload").Run()
		}
	}

	bannedIPMap.Delete(ip)
	log.Printf("[SOAR_MITIGATION] 🟢 IP UNBANNED ACROSS ALL LAYERS: %s", ip)
	return nil
}
