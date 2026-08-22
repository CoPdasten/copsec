package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FallbackRule holds lightweight signatures for offline mitigation.
type FallbackRule struct {
	Name        string
	Pattern     *regexp.Regexp
	MitreID     string
	ThreatScore int
}

// FallbackEngine protects edge nodes autonomously when Controller is unreachable.
type FallbackEngine struct {
	nodeID          string
	telegramToken   string
	telegramChatID  string
	httpClient      *http.Client
	rules           []FallbackRule
	mu              sync.Mutex
	bannedIPs       map[string]int64
	ipSpikeHistory  map[string][]int64
	isFallbackState bool
	lastUpdateID    int64

	whitelistFilter *PreRoutingFilter
	whitelistPath   string
}

// NewFallbackEngine initializes the emergency autonomous threat engine.
func NewFallbackEngine(nodeID, tgToken, tgChatID string) *FallbackEngine {
	rules := []FallbackRule{
		{
			Name:        "offline_rce_command_injection",
			Pattern:     regexp.MustCompile(`(?i)(/bin/sh|/bin/bash|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|;\s*id\b|;\s*whoami\b|;\s*cat\s+/etc/|jndi:ldap|\$\{jndi:|{{.*}}|php://input)`),
			MitreID:     "T1059.004",
			ThreatScore: 90,
		},
		{
			Name:        "offline_sqli_exploit",
			Pattern:     regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|information_schema|1=1|--\s*$|\bxp_cmdshell|\bwaitfor\s+delay)`),
			MitreID:     "T1190",
			ThreatScore: 85,
		},
		{
			Name:        "offline_path_traversal",
			Pattern:     regexp.MustCompile(`(?i)(\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self/environ|/boot\.ini|win\.ini)`),
			MitreID:     "T1190",
			ThreatScore: 85,
		},
		{
			Name:        "offline_ssh_brute_force",
			Pattern:     regexp.MustCompile(`(?i)(Failed password for|Invalid user|authentication failure|pam_unix\(sshd:auth\): authentication failure)`),
			MitreID:     "T1110.001",
			ThreatScore: 55,
		},
	}

	return &FallbackEngine{
		nodeID:         nodeID,
		telegramToken:  tgToken,
		telegramChatID: tgChatID,
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		rules:          rules,
		bannedIPs:      make(map[string]int64),
		ipSpikeHistory: make(map[string][]int64),
	}
}

// SetWhitelistFilter links the dynamic whitelist manager.
func (f *FallbackEngine) SetWhitelistFilter(filter *PreRoutingFilter, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.whitelistFilter = filter
	f.whitelistPath = path
}

// SetFallbackActive enables or disables the offline autonomous inspection & Telegram bot listener.
func (f *FallbackEngine) SetFallbackActive(active bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isFallbackState != active {
		f.isFallbackState = active
		if active {
			log.Println("[FALLBACK_SOAR] Controller unreachable -> Autonomous Edge Fallback Mode ACTIVATED.")
		} else {
			log.Println("[FALLBACK_SOAR] Controller reconnected -> Autonomous Edge Fallback Mode STANDBY.")
		}
	}
}

// IsActive returns the current fallback mode.
func (f *FallbackEngine) IsActive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isFallbackState
}

// StartTelegramPolling runs long-polling for emergency commands when Controller is offline.
func (f *FallbackEngine) StartTelegramPolling(ctx context.Context, wg *sync.WaitGroup) {
	if f.telegramToken == "" || f.telegramChatID == "" {
		return
	}

	defer wg.Done()
	log.Printf("[FALLBACK_TELEGRAM] Edge Emergency Telegram Bot listener initialized (ChatID: %s)", f.telegramChatID)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Only poll when Controller is disconnected to avoid 409 Conflict with Controller bot
			if f.IsActive() {
				f.fetchOfflineUpdates()
			}
		}
	}
}

func (f *FallbackEngine) fetchOfflineUpdates() {
	payload := map[string]interface{}{
		"offset":  f.lastUpdateID + 1,
		"timeout": 2,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", f.telegramToken)
	resp, err := f.httpClient.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var res struct {
		Ok     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				MessageID int64 `json:"message_id"`
				Chat      struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || !res.Ok {
		return
	}

	for _, update := range res.Result {
		if update.UpdateID > f.lastUpdateID {
			f.lastUpdateID = update.UpdateID
		}

		if update.Message != nil && update.Message.Text != "" {
			chatID := strconv.FormatInt(update.Message.Chat.ID, 10)
			if chatID != f.telegramChatID {
				log.Printf("[FALLBACK_WARN] Unauthorized message attempt from chat ID %s", chatID)
				continue
			}

			f.handleEmergencyCommand(strings.TrimSpace(update.Message.Text))
		}
	}
}

func (f *FallbackEngine) handleEmergencyCommand(text string) {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "/ban":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			f.replyMessage("⚠️ *Geçersiz IP adresi.*\nKullanım: `/ban 185.220.101.5`")
			return
		}
		ip := parts[1]
		_ = exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run()
		f.mu.Lock()
		f.bannedIPs[ip] = time.Now().Unix()
		f.mu.Unlock()
		f.replyMessage(fmt.Sprintf("🚫 *[EDGE DIRECT BAN]* `%s` adresi VDS üzerinde başarıyla engellendi.", ip))

	case "/unban":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			f.replyMessage("⚠️ *Geçersiz IP adresi.*\nKullanım: `/unban 185.220.101.5`")
			return
		}
		ip := parts[1]
		_ = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
		f.mu.Lock()
		delete(f.bannedIPs, ip)
		f.mu.Unlock()
		f.replyMessage(fmt.Sprintf("🔓 *[EDGE DIRECT UNBAN]* `%s` engel kuralı VDS üzerinden kaldırıldı.", ip))

	case "/whitelist", "/wl":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			f.replyMessage("⚠️ *Geçersiz IP adresi.*\nKullanım: `/whitelist 176.88.125.20`")
			return
		}
		ip := parts[1]
		_ = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
		f.mu.Lock()
		delete(f.bannedIPs, ip)
		if f.whitelistFilter != nil {
			_ = f.whitelistFilter.AddDynamicWhitelist(ip, f.whitelistPath)
		}
		f.mu.Unlock()
		f.replyMessage(fmt.Sprintf("🛡 *[EDGE WHITELIST]* `%s` beyaz listeye eklendi ve korumaya alındı.", ip))

	case "/status":
		f.mu.Lock()
		banCount := len(f.bannedIPs)
		isOffline := f.isFallbackState
		f.mu.Unlock()

		modeStr := "🟢 Normal (Controller'a Bağlı)"
		if isOffline {
			modeStr = "🟡 Otonom Acil Durum Modu (Controller Çevrimdışı!)"
		}

		statusText := fmt.Sprintf("📊 *CoPSeC VDS Uç Durum Raporu*\n\n"+
			"🖥 *Düğüm:* `%s`\n"+
			"🔗 *Bağlantı Modu:* %s\n"+
			"🛡 *Yerel Cezaevi (Jail):* `%d aktif IP`\n"+
			"⚡ *Motor:* `Yerel Uç Tehdit Kalkanı Devrede`",
			f.nodeID, modeStr, banCount)
		f.replyMessage(statusText)

	case "/help", "/start":
		helpText := "🤖 *CoPSeC VDS Doğrudan Uç Komuta Merkezi*\n\n" +
			"Kullanılabilir Acil Durum Komutları:\n" +
			"• `/ban <IP>` - Belirtilen IP'yi VDS yerelinde derhal engeller.\n" +
			"• `/unban <IP>` - Belirtilen IP'nin engelini kaldırır.\n" +
			"• `/whitelist <IP>` - IP'yi beyaz listeye alır ve engelini açar.\n" +
			"• `/status` - VDS yerel koruma durumunu raporlar.\n" +
			"• `/help` - Bu kılavuzu görüntüler."
		f.replyMessage(helpText)

	default:
		f.replyMessage("❓ *Bilinmeyen komut.* Kullanılabilir komutları görmek için `/help` yazabilirsiniz.")
	}
}

func (f *FallbackEngine) replyMessage(text string) {
	payload := map[string]interface{}{
		"chat_id":    f.telegramChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", f.telegramToken)
	_, _ = f.httpClient.Post(url, "application/json", bytes.NewBuffer(data))
}

// InspectOffline evaluates a log entry and applies local iptables DROP + Telegram streaming pipeline.
func (f *FallbackEngine) InspectOffline(rawLine, source string) {
	if !f.IsActive() {
		return
	}

	ip := ExtractIP(rawLine)
	if ip == nil || ip.IsLoopback() || loopbackIPv4Net.Contains(ip) || tailscaleNet.Contains(ip) {
		return
	}
	ipStr := ip.String()

	var matchedRule FallbackRule
	var isMatched bool

	for _, rule := range f.rules {
		if rule.Pattern.MatchString(rawLine) {
			matchedRule = rule
			isMatched = true
			break
		}
	}

	if !isMatched || matchedRule.ThreatScore < 50 {
		return
	}

	f.mu.Lock()
	now := time.Now().Unix()

	// Check if already banned recently
	if lastBan, ok := f.bannedIPs[ipStr]; ok && now-lastBan < 3600 {
		f.mu.Unlock()
		return
	}

	triggerBan := false
	actionTaken := "Monitored / Logged"

	// Critical Threshold (>= 85)
	if matchedRule.ThreatScore >= 85 {
		triggerBan = true
		actionTaken = "Local IPTABLES DROP Applied"
	} else {
		// Correlational Spike Window (>= 3 attacks in 60s)
		history := f.ipSpikeHistory[ipStr]
		var recent []int64
		for _, ts := range history {
			if now-ts <= 60 {
				recent = append(recent, ts)
			}
		}
		recent = append(recent, now)
		f.ipSpikeHistory[ipStr] = recent

		if len(recent) >= 3 {
			triggerBan = true
			actionTaken = fmt.Sprintf("Correlational Spike (%d attacks in 60s) -> IPTABLES DROP Applied", len(recent))
		}
	}

	if triggerBan {
		f.bannedIPs[ipStr] = now
	}
	f.mu.Unlock()

	// 1. Execute local containment if ban triggered
	if triggerBan {
		f.executeLocalBan(ipStr)
	}

	// 2. Stream WARN (50-84) and CRIT (>=85 or Spike) directly to Telegram
	if f.telegramToken != "" && f.telegramChatID != "" {
		go f.sendDirectTelegramAlert(ipStr, matchedRule.Name, matchedRule.MitreID, matchedRule.ThreatScore, actionTaken, rawLine, triggerBan)
	}
}

func (f *FallbackEngine) executeLocalBan(ipStr string) {
	checkErr := exec.Command("iptables", "-C", "INPUT", "-s", ipStr, "-j", "DROP").Run()
	if checkErr == nil {
		log.Printf("[FALLBACK_SOAR] IP %s is already isolated in local iptables", ipStr)
		return
	}

	out, err := exec.Command("iptables", "-I", "INPUT", "-s", ipStr, "-j", "DROP").CombinedOutput()
	if err == nil {
		log.Printf("[FALLBACK_SOAR] 🚫 Autonomous local iptables DROP executed for %s", ipStr)
	} else {
		log.Printf("[FALLBACK_SOAR] Failed to ban IP %s: %v (%s)", ipStr, err, string(out))
	}
}

func (f *FallbackEngine) sendDirectTelegramAlert(ip, ruleName, mitreID string, threatScore int, actionTaken, rawLine string, isBanned bool) {
	severityTag := "⚠️ *[EDGE OFFLINE INCIDENT - WARN]*"
	scoreBadge := fmt.Sprintf("[WARN %d/100]", threatScore)
	if isBanned || threatScore >= 85 {
		severityTag = "🔥 *[EDGE OFFLINE INCIDENT - CRITICAL]*"
		scoreBadge = fmt.Sprintf("[CRIT %d/100]", threatScore)
	}

	text := fmt.Sprintf("%s\n\n"+
		"🖥 *Node:* `%s` _(Controller Offline!)_\n"+
		"🎯 *Target/IP:* `%s`\n"+
		"⚡ *Threat Level:* `%s`\n"+
		"🏷 *MITRE:* `%s`\n"+
		"🛡 *Rule:* `%s`\n"+
		"📋 *Action Taken:* `%s`\n\n"+
		"📜 *Payload:*\n`%s`",
		severityTag,
		f.nodeID,
		ip,
		scoreBadge,
		mitreID,
		ruleName,
		actionTaken,
		truncateString(rawLine, 140))

	f.replyMessage(text)
	log.Printf("[FALLBACK_TELEGRAM] Direct incident alert dispatched to Telegram for %s (%s)", ip, scoreBadge)
}

func truncateString(str string, length int) string {
	if length <= 0 {
		return ""
	}
	if len(str) <= length {
		return str
	}
	if length <= 3 {
		return str[:length]
	}
	return str[:length-3] + "..."
}
