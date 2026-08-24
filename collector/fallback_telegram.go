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
	// URL decode edilmiş veya ham metinde aranacak saldırı kalıpları
	criticalPatterns = map[string]*regexp.Regexp{
		"SQL_INJECTION":    regexp.MustCompile(`(?i)(union[\s\+]+select|select.+from|information_schema|waitfor[\s\+]+delay|benchmark\(|order[\s\+]+by[\s\+]+[0-9]+|'\s*or\s*'|--\s*)`),
		"PATH_TRAVERSAL":   regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self)`),
		"REMOTE_CODE_EXEC": regexp.MustCompile(`(?i)(/bin/bash|/bin/sh|cmd\.exe|powershell|wget[\s\+]|curl[\s\+]|\$\(.*\)|;\s*cat\s+)`),
		"SENSITIVE_LEAK":   regexp.MustCompile(`(?i)(\.env|\.git/|wp-config\.php|id_rsa|\.aws/)`),
		"SSH_BRUTE_FORCE":  regexp.MustCompile(`(?i)(Failed password for (invalid user )?\w+ from)`),
	}

	edgeIPRegex = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

type AutonomousEdgeEngine struct {
	Token       string
	ChatID      string
	IsConnected bool
	bannedCache sync.Map
}

var edgeEngine = &AutonomousEdgeEngine{
	Token:       "8275343323:AAHnc6qdWOSJW5ozJ5xsTyaQkE7BSCW7lFE",
	ChatID:      "6352241918",
	IsConnected: false, // Controller bağlı değilken true'ya döner
}

func (e *AutonomousEdgeEngine) SetControllerConnection(connected bool) {
	e.IsConnected = connected
}

func (e *AutonomousEdgeEngine) InspectRawLine(rawLog string, source string) {
	// Controller bağlıysa müdahale etme
	if e.IsConnected {
		return
	}

	// URL Decode
	decodedLog, _ := url.QueryUnescape(rawLog)
	if d2, err := url.PathUnescape(decodedLog); err == nil {
		decodedLog = d2
	}

	// Tehdit taraması & IP Ayıklama
	var matchedThreat string
	var attackerIP string

	if source == "suricata" {
		if sEv, ok := parseSuricataLine(rawLog); ok && sEv.ThreatScore >= 80 {
			matchedThreat = "SURICATA_ALERT"
			attackerIP = sEv.ClientIp
		}
	}

	if matchedThreat == "" {
		for threatType, pattern := range criticalPatterns {
			if pattern.MatchString(decodedLog) || pattern.MatchString(rawLog) {
				matchedThreat = threatType
				break
			}
		}
	}

	if matchedThreat == "" {
		return
	}

	if attackerIP == "" {
		if source == "auth" || source == "ssh" {
			attackerIP = extractIPFromLine(rawLog, source)
		}
		if attackerIP == "" {
			if ipMatch := edgeIPRegex.FindStringSubmatch(rawLog); len(ipMatch) > 1 {
				attackerIP = ipMatch[1]
			}
		}
		if attackerIP == "" {
			attackerIP = extractIPFromLine(rawLog, source)
		}
	}

	if attackerIP == "127.0.0.1" || attackerIP == "" {
		return
	}

	if _, banned := e.bannedCache.Load(attackerIP); banned {
		return
	}
	e.bannedCache.Store(attackerIP, time.Now())

	log.Printf("[EDGE_SOAR_DEBUG] 🚨 THREAT DETECTED: %s from IP: %s (Source: %s)", matchedThreat, attackerIP, source)
	go e.executeBanAndNotify(attackerIP, matchedThreat, decodedLog, source)
}

func (e *AutonomousEdgeEngine) executeBanAndNotify(ip string, threat string, rawLog string, source string) {
	// L3/L4 Anlık İnfaz + L7 Arka Planda
	_ = ExecuteInstantBan(ip)

	// Telegram Bildirimi Gönder
	msg := fmt.Sprintf("🛡️ *[COPSEC AUTONOMOUS EDGE SOAR]*\n\n"+
		"🚨 *CRITICAL THREAT MITIGATED*\n"+
		"⚠️ *Status:* `CONTROLLER OFFLINE (Edge Standalone)`\n"+
		"🎯 *Attacker IP:* `%s`\n"+
		"☣️ *Attack Type:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🔒 *Action:* `PERMANENT HYBRID BAN (L3/L4/L7)`\n"+
		"⏰ *Time:* `%s`\n\n"+
		"📝 *Payload:*\n`%s`",
		ip, threat, source, time.Now().Format("15:04:05"), truncateLog(rawLog, 160))

	e.sendTelegram(msg)
}

func (e *AutonomousEdgeEngine) sendTelegram(text string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", e.Token)
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    e.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	})

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[EDGE_SOAR_DEBUG] Telegram HTTP error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[EDGE_SOAR_DEBUG] 🚀 Telegram alert delivered successfully!")
}

func truncateLog(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "`", "")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
