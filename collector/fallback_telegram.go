package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// URL decode edilmiş metin üzerinde agresif arama
	criticalAttackPatterns = map[string]*regexp.Regexp{
		"SQL_INJECTION":    regexp.MustCompile(`(?i)(union[\s\+]+select|select.+from|information_schema|waitfor[\s\+]+delay|benchmark\(|order[\s\+]+by[\s\+]+[0-9]+|1=1|1=2|'\s*or\s*'|--\s*$)`),
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
	IsConnected: false, // Varsayılan fallback hazır
	httpClient:  &http.Client{Timeout: 5 * time.Second},
}

func (e *AutonomousEdgeEngine) SetControllerConnection(connected bool) {
	e.IsConnected = connected
}

func (e *AutonomousEdgeEngine) ProcessAutonomousInspection(rawLog string, source string, attackerIP string) {
	if e.IsConnected || attackerIP == "" || isProtectedIP(attackerIP) {
		return
	}

	// 1. URL Decoding: %20, %27, %2b vb. çöz
	decodedLog, err := url.QueryUnescape(rawLog)
	if err != nil {
		decodedLog = rawLog
	}
	// İkinci katman decode (çift encode saldırılar için)
	if d2, err2 := url.PathUnescape(decodedLog); err2 == nil {
		decodedLog = d2
	}

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

	// Tekrarlanan banları önle
	if _, banned := e.bannedCache.Load(attackerIP); banned {
		return
	}
	e.bannedCache.Store(attackerIP, time.Now())

	log.Printf("[FALLBACK_SOAR] 🚨 THREAT MATCHED [%s] from IP: %s", detectedVulnerability, attackerIP)
	go e.executeAutonomousHybridBan(attackerIP, detectedVulnerability, decodedLog, source)
}

func (e *AutonomousEdgeEngine) executeAutonomousHybridBan(ip string, vuln string, logSample string, source string) {
	// 1. L3/L4 & L7 Hibrit Ban
	if err := ExecuteBan(ip, 86400); err != nil {
		log.Printf("[FALLBACK_SOAR] ⚠️ Ban execution warning for %s: %v", ip, err)
	}

	// 2. Telegram Bildirimi
	msg := fmt.Sprintf("🛡️ *[COPSEC AUTONOMOUS EDGE SOAR]*\n\n"+
		"🚨 *CRITICAL THREAT AUTO-MITIGATED*\n"+
		"⚠️ *Status:* `CONTROLLER OFFLINE (Edge Defense)`\n"+
		"🎯 *Attacker IP:* `%s`\n"+
		"☣️ *Attack:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🔒 *Action:* `PERMANENT BAN (iptables + Nginx WAF)`\n"+
		"⏰ *Time:* `%s`\n\n"+
		"📝 *Decoded Payload:*\n`%s`",
		ip, vuln, source, time.Now().Format("15:04:05"), sanitizePayload(logSample, 150))

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
