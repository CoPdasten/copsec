package main

import (
	"log"
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
	rules           []FallbackRule
	mu              sync.Mutex
	bannedIPs       map[string]int64
	ipSpikeHistory  map[string][]int64
	isFallbackState bool

	whitelistFilter *PreRoutingFilter
	whitelistPath   string
}

// NewFallbackEngine initializes the emergency autonomous threat engine.
func NewFallbackEngine(nodeID string) *FallbackEngine {
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
			MitreID:     "T1083",
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

// InspectOffline evaluates a log entry and applies local iptables DROP.
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

	// Critical Threshold (>= 85)
	if matchedRule.ThreatScore >= 85 {
		triggerBan = true
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
		}
	}

	if triggerBan {
		f.bannedIPs[ipStr] = now
	}
	f.mu.Unlock()

	// Execute local containment if ban triggered
	if triggerBan {
		f.executeLocalBan(ipStr)
	}
}

func (f *FallbackEngine) executeLocalBan(ipStr string) {
	success, msg := ExecuteSOARBan(ipStr, 86400)
	if success {
		log.Printf("[FALLBACK_SOAR] 🚫 Autonomous local ban executed for %s (%s)", ipStr, msg)
	} else {
		log.Printf("[FALLBACK_SOAR] Failed to ban IP %s: %s", ipStr, msg)
	}
}
