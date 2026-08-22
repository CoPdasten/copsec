package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
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

// SetFallbackActive enables or disables the offline autonomous inspection.
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

// InspectOffline evaluates a log entry and applies local iptables DROP + Telegram alert if severe.
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

	if !isMatched {
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
	reason := ""

	// Static critical condition (>= 80)
	if matchedRule.ThreatScore >= 80 {
		triggerBan = true
		reason = fmt.Sprintf("Critical Threat Score (%d >= 80)", matchedRule.ThreatScore)
	} else if matchedRule.ThreatScore >= 50 {
		// Correlational spike condition (>= 3 attacks in 60s)
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
			reason = fmt.Sprintf("Correlational Spike (%d attacks in 60s)", len(recent))
		}
	}

	if !triggerBan {
		f.mu.Unlock()
		return
	}

	f.bannedIPs[ipStr] = now
	f.mu.Unlock()

	// 1. Execute local iptables containment
	f.executeLocalBan(ipStr)

	// 2. Dispatch direct Telegram alert if configured
	if f.telegramToken != "" && f.telegramChatID != "" {
		go f.sendDirectTelegramAlert(ipStr, matchedRule.Name, matchedRule.MitreID, matchedRule.ThreatScore, reason, rawLine)
	}
}

func (f *FallbackEngine) executeLocalBan(ipStr string) {
	// Check duplicate rule
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

func (f *FallbackEngine) sendDirectTelegramAlert(ip, ruleName, mitreID string, threatScore int, reason, rawLine string) {
	text := fmt.Sprintf("🚨 *[EDGE OFFLINE AUTONOMOUS ACTION]*\n\n"+
		"🖥 *Node:* `%s` _(Controller Offline!)_\n"+
		"🎯 *Target IP:* `%s`\n"+
		"⚡ *Threat Score:* `%d/100 (CRITICAL)`\n"+
		"🏷 *MITRE:* `%s`\n"+
		"🛡 *Rule:* `%s`\n"+
		"📋 *Reason:* `%s`\n"+
		"🚫 *Action:* `Local IPTABLES DROP Applied`\n\n"+
		"📜 *Payload:*\n`%s`",
		f.nodeID,
		ip,
		threatScore,
		mitreID,
		ruleName,
		reason,
		truncateString(rawLine, 140))

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
	resp, err := f.httpClient.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[FALLBACK_TELEGRAM] Failed to send offline alert: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[FALLBACK_TELEGRAM] Direct emergency alert dispatched to Telegram for %s", ip)
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
