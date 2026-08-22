package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// Yüksek kritiklikteki saldırı vektörleri
	criticalAttackPatterns = map[string]*regexp.Regexp{
		"SQL_INJECTION":    regexp.MustCompile(`(?i)(union\s+select|select.*from|information_schema|waitfor\s+delay|benchmark\(|order\s+by\s+\d+)`),
		"PATH_TRAVERSAL":   regexp.MustCompile(`(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ)`),
		"REMOTE_CODE_EXEC": regexp.MustCompile(`(?i)(/bin/bash|/bin/sh|cmd\.exe|powershell|wget\s+|curl\s+.*\|\s*sh|\$\(.*\)|;\s*cat\s+)`),
		"SENSITIVE_LEAK":   regexp.MustCompile(`(?i)(\.env|\.git/config|wp-config\.php|id_rsa|id_ed25519|\.aws/credentials)`),
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
	IsConnected: true,
	httpClient:  &http.Client{Timeout: 5 * time.Second},
}

func (e *AutonomousEdgeEngine) SetControllerConnection(connected bool) {
	e.IsConnected = connected
}

// ProcessAutonomousInspection inspects raw lines and autonomously mitigates threats when controller is offline.
func (e *AutonomousEdgeEngine) ProcessAutonomousInspection(rawLog string, source string, attackerIP string) {
	// Controller bağlıysa merkezi SOAR yönetsin (çift işlem olmasın)
	if e.IsConnected || attackerIP == "" || isProtectedIP(attackerIP) {
		return
	}

	// IP zaten bu oturumda banlandıysa tekrar tetikleme
	if _, banned := e.bannedCache.Load(attackerIP); banned {
		return
	}

	var detectedVulnerability string
	for vulnType, pattern := range criticalAttackPatterns {
		if pattern.MatchString(rawLog) {
			detectedVulnerability = vulnType
			break
		}
	}

	if detectedVulnerability == "" {
		return // Zararsız istek, geç
	}

	// 1. IP'yi hafızaya al
	e.bannedCache.Store(attackerIP, time.Now())

	// 2. Otonom Hibrit Ban Uygula (iptables + Nginx WAF)
	go e.executeAutonomousHybridBan(attackerIP, detectedVulnerability, rawLog, source)
}

func (e *AutonomousEdgeEngine) executeAutonomousHybridBan(ip string, vuln string, rawLog string, source string) {
	log.Printf("[EDGE_AUTONOMOUS_SOAR] ⚡ Zero-Touch Ban Triggered for IP: %s (Reason: %s)", ip, vuln)

	// ExecuteBan: L3/L4 iptables RAW PREROUTING/INPUT + Kernel Socket Killer + L7 Nginx WAF
	if err := ExecuteBan(ip, 86400); err != nil {
		log.Printf("[EDGE_AUTONOMOUS_SOAR] ⚠️ Failed to execute ban on %s: %v", ip, err)
	}

	// 3. Telegram Acil Durum & İnfaz Raporu Gönder
	msg := fmt.Sprintf("🛡️ *[COPSEC AUTONOMOUS EDGE SOAR]*\n\n"+
		"🚨 *CRITICAL THREAT MITIGATED*\n"+
		"⚠️ *Status:* `CONTROLLER OFFLINE (Edge Self-Defense)`\n"+
		"🎯 *Attacker IP:* `%s`\n"+
		"☣️ *Attack Type:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🔒 *Action:* `PERMANENT HYBRID BAN (iptables + Nginx WAF)`\n"+
		"⏰ *Timestamp:* `%s`\n\n"+
		"📝 *Intercepted Payload:*\n`%s`",
		ip, vuln, source, time.Now().Format("15:04:05"), sanitizePayload(rawLog, 160))

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
		log.Printf("[EDGE_AUTONOMOUS_SOAR] Telegram error: %v", err)
		return
	}
	defer resp.Body.Close()
}

func sanitizePayload(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "`", "")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
