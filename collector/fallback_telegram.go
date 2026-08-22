package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	criticalAttackPatterns = map[string]*regexp.Regexp{
		"SQL_INJECTION":    regexp.MustCompile(`(?i)(union[\s\+]+select|select.+from|information_schema|waitfor[\s\+]+delay|benchmark\(|order[\s\+]+by[\s\+]+[0-9]+|1=1|1=2|'\s*or\s*'|--\s*)`),
		"PATH_TRAVERSAL":   regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self)`),
		"REMOTE_CODE_EXEC": regexp.MustCompile(`(?i)(/bin/bash|/bin/sh|cmd\.exe|powershell|wget[\s\+]|curl[\s\+]|\$\(.*\)|;\s*cat\s+)`),
		"SENSITIVE_LEAK":   regexp.MustCompile(`(?i)(\.env|\.git/|wp-config\.php|id_rsa|\.aws/)`),
		"SSH_BRUTE_FORCE":  regexp.MustCompile(`(?i)(Failed password for (invalid user )?\w+ from)`),
	}
)

type AutonomousEdgeEngine struct {
	Token       string
	ChatID      string
	IsConnected bool
	bannedCache sync.Map
	httpClient  *http.Client
}

var edgeEngine = &AutonomousEdgeEngine{
	Token:       "8275343323:AAHnc6qdWOSJW5ozJ5xsTyaQkE7BSCW7lFE",
	ChatID:      "6352241918",
	IsConnected: false,
	httpClient:  &http.Client{Timeout: 5 * time.Second},
}

func (e *AutonomousEdgeEngine) SetControllerConnection(connected bool) {
	e.IsConnected = connected
}

func (e *AutonomousEdgeEngine) ProcessAutonomousInspection(rawLog string, source string, attackerIP string) {
	if e.IsConnected || attackerIP == "" || isProtectedIP(attackerIP) {
		return
	}

	// 1. Tüm satırı (URI + Referer + User-Agent) URL-Decode et
	decodedLog, err := url.QueryUnescape(rawLog)
	if err != nil {
		decodedLog = rawLog
	}
	if d2, err2 := url.PathUnescape(decodedLog); err2 == nil {
		decodedLog = d2
	}

	// 2. Hem ham hem decode edilmiş tam metin üzerinde ara
	var detectedVulnerability string
	for vulnType, pattern := range criticalAttackPatterns {
		if pattern.MatchString(decodedLog) || pattern.MatchString(rawLog) {
			detectedVulnerability = vulnType
			break
		}
	}

	if detectedVulnerability == "" {
		return
	}

	if _, banned := e.bannedCache.Load(attackerIP); banned {
		return
	}
	e.bannedCache.Store(attackerIP, time.Now())

	log.Printf("[FALLBACK_SOAR] 🚨 FULL-SPECTRUM THREAT MATCHED [%s] from IP: %s", detectedVulnerability, attackerIP)
	go e.executeAutonomousHybridBan(attackerIP, detectedVulnerability, decodedLog, source)
}

func (e *AutonomousEdgeEngine) executeAutonomousHybridBan(ip string, vuln string, logSample string, source string) {
	// L3/L4 & L7 Mitigation
	if err := ExecuteBan(ip, 86400); err != nil {
		_ = exec.Command("sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ip, "-j", "DROP").Run()
		_ = exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP").Run()
		_ = exec.Command("sudo", "ss", "-K", "dst", ip).Run()

		blockLine := fmt.Sprintf("deny %s;\n", ip)
		f, pipeErr := exec.Command("sudo", "tee", "-a", "/etc/nginx/conf.d/copsec_blocklist.conf").StdinPipe()
		if pipeErr == nil {
			_, _ = f.Write([]byte(blockLine))
			_ = f.Close()
			_ = exec.Command("sudo", "nginx", "-s", "reload").Run()
		}
	}

	// Telegram Bildirimi
	msg := fmt.Sprintf("🛡️ *[COPSEC AUTONOMOUS EDGE SOAR]*\n\n"+
		"🚨 *CRITICAL THREAT AUTO-MITIGATED*\n"+
		"⚠️ *Status:* `CONTROLLER OFFLINE (Edge Defense)`\n"+
		"🎯 *Attacker IP:* `%s`\n"+
		"☣️ *Attack:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🔒 *Action:* `PERMANENT BAN (iptables + Nginx WAF)`\n"+
		"⏰ *Time:* `%s`\n\n"+
		"📝 *Payload:*\n`%s`",
		ip, vuln, source, time.Now().Format("15:04:05"), sanitizePayload(logSample, 160))

	e.sendTelegram(msg)
}

func (e *AutonomousEdgeEngine) sendTelegram(text string) {
	if e.Token == "" || e.ChatID == "" {
		return
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", e.Token)
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    e.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	})

	resp, err := e.httpClient.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[FALLBACK_SOAR] Telegram send error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[FALLBACK_SOAR] ✅ Telegram alert sent successfully!")
}

func sanitizePayload(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "`", "")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
