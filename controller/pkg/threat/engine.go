package threat

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/copsec/controller/pkg/ipinfo"
)

// ThreatAction defines the recommended mitigation action from the engine.
type ThreatAction string

const (
	ActionAllow      ThreatAction = "ALLOW"
	ActionLog        ThreatAction = "LOG"
	ActionTarpit     ThreatAction = "TARPIT"
	ActionInstantBan ThreatAction = "INSTANT_BAN"
)

// MicroEvent records an atomic security signal from a specific source IP.
type MicroEvent struct {
	TimestampMs int64   `json:"timestamp_ms"`
	EventType   string  `json:"event_type"` // SSH_AUTH_FAIL, WEB_4XX_BURST, DNS_ANOMALY, TIER1_CRITICAL, HONEYPOT_TRAP, GENERIC_RULE
	RuleID      string  `json:"rule_id"`
	MitreID     string  `json:"mitre_id"`
	BaseScore   float64 `json:"base_score"`
}

// EntityState tracks the dynamic behavioral and scoring history of an IP.
type EntityState struct {
	IP                     string       `json:"ip"`
	FirstSeenMs            int64        `json:"first_seen_ms"`
	LastSeenMs             int64        `json:"last_seen_ms"`
	CurrentScore           float64      `json:"current_score"`
	RecentEvents           []MicroEvent `json:"recent_events"`
	ConsecutiveAuthFails   int          `json:"consecutive_auth_fails"`
	RecentWeb4xxCount      int          `json:"recent_web_4xx_count"`
	RecentDNSAnomalyCount  int          `json:"recent_dns_anomaly_count"`
	TotalIncidents         int          `json:"total_incidents"`
	IsDatacenterASN        bool         `json:"is_datacenter_asn"`
	LastASNInfo            string       `json:"last_asn_info"`
	Quarantined            bool         `json:"quarantined"`
}

// ThreatAssessment encapsulates the real-time scoring breakdown and recommendation.
type ThreatAssessment struct {
	IP                  string       `json:"ip"`
	FinalScore          int          `json:"final_score"`
	BaseScore           int          `json:"base_score"`
	DecayedScore        float64      `json:"decayed_score"`
	CumulativeIncrement float64      `json:"cumulative_increment"`
	RiskMultiplier      float64      `json:"risk_multiplier"`
	IsWhitelisted       bool         `json:"is_whitelisted"`
	Action              ThreatAction `json:"action"`
	Tier                string       `json:"tier"`
	Breakdown           string       `json:"breakdown"`
	TimestampMs         int64        `json:"timestamp_ms"`
}

// ShardedThreatStore holds state across 64 lock-striped shards to maximize multi-core throughput.
type ShardedThreatStore struct {
	shards    [64]*threatShard
	whitelist []*net.IPNet
	whiteMu   sync.RWMutex
}

type threatShard struct {
	mu       sync.RWMutex
	entities map[string]*EntityState
}

// ScoringEngine coordinates dynamic sliding-window scoring, exponential decay, and multi-tier correlation.
type ScoringEngine struct {
	store             *ShardedThreatStore
	banThreshold      int
	tarpitThreshold   int
	halfLifeSeconds   float64 // default: 180s (3 minutes)
	slidingWindowMs   int64   // default: 60,000ms (60s)
}

var (
	defaultEngine *ScoringEngine
	engineOnce    sync.Once
)

// GetDefaultEngine returns the singleton scoring engine.
func GetDefaultEngine() *ScoringEngine {
	engineOnce.Do(func() {
		defaultEngine = NewScoringEngine(80, 60)
	})
	return defaultEngine
}

// NewScoringEngine initializes the threat scoring engine.
func NewScoringEngine(banThreshold, tarpitThreshold int) *ScoringEngine {
	if banThreshold <= 0 {
		banThreshold = 80
	}
	if tarpitThreshold <= 0 {
		tarpitThreshold = 60
	}

	store := &ShardedThreatStore{
		whitelist: make([]*net.IPNet, 0),
	}
	for i := 0; i < 64; i++ {
		store.shards[i] = &threatShard{
			entities: make(map[string]*EntityState),
		}
	}

	// Initialize default private/local/DNS CIDRs to whitelist
	defaultCIDRs := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",   // Tailscale / CGNAT
		"169.254.0.0/16",  // Link-local
		"8.8.8.8/32",      // Google Primary DNS
		"8.8.4.4/32",      // Google Secondary DNS
		"1.1.1.1/32",      // Cloudflare Primary DNS
		"1.0.0.1/32",      // Cloudflare Secondary DNS
		"1.1.1.2/32",      // Cloudflare Security DNS
		"1.0.0.2/32",
		"1.1.1.3/32",      // Cloudflare Family DNS
		"1.0.0.3/32",
		"9.9.9.9/32",      // Quad9 DNS
		"149.112.112.112/32",
		"208.67.222.222/32", // OpenDNS
		"208.67.220.220/32",
		"2001:4860:4860::8888/128",
		"2001:4860:4860::8844/128",
		"2606:4700:4700::1111/128",
		"2606:4700:4700::1001/128",
		"2620:fe::fe/128",
		"2620:fe::9/128",
		"2620:119:35::35/128",
		"2620:119:53::53/128",
	}
	for _, cidr := range defaultCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			store.whitelist = append(store.whitelist, ipNet)
		}
	}

	return &ScoringEngine{
		store:           store,
		banThreshold:    banThreshold,
		tarpitThreshold: tarpitThreshold,
		halfLifeSeconds: 180.0,
		slidingWindowMs: 60 * 1000,
	}
}

// AddWhitelistCIDR adds a trusted network range that will never be scored or banned.
func (se *ScoringEngine) AddWhitelistCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid CIDR/IP: %s", cidr)
		}
		if ip.To4() != nil {
			_, ipNet, _ = net.ParseCIDR(cidr + "/32")
		} else {
			_, ipNet, _ = net.ParseCIDR(cidr + "/128")
		}
	}

	se.store.whiteMu.Lock()
	defer se.store.whiteMu.Unlock()
	se.store.whitelist = append(se.store.whitelist, ipNet)
	return nil
}

// IsWhitelisted checks if an IP is in the whitelist.
func (se *ScoringEngine) IsWhitelisted(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}

	se.store.whiteMu.RLock()
	defer se.store.whiteMu.RUnlock()

	for _, cidr := range se.store.whitelist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (se *ScoringEngine) getShard(ipStr string) *threatShard {
	var hash uint32 = 2166136261
	for i := 0; i < len(ipStr); i++ {
		hash ^= uint32(ipStr[i])
		hash *= 16777619
	}
	return se.store.shards[hash%64]
}

// IsDatacenterASN detects cloud hosting, VPS providers, and Tor exit nodes from ASN strings.
func IsDatacenterASN(asn string) bool {
	lower := strings.ToLower(asn)
	keywords := []string{
		"digitalocean", "ovh", "hetzner", "amazon", "aws", "google", "linode",
		"vultr", "choopa", "leaseweb", "contabo", "m247", "tor", "vpn",
		"fastly", "cloudflare", "akamai", "alibaba", "tencent", "datacenter",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// Evaluate calculates the dynamic, decayed, and cumulative threat score for an incoming event.
func (se *ScoringEngine) Evaluate(
	ipStr string,
	rawScore int,
	ruleID, mitreID string,
	statusCode int,
	asnInfo string,
) ThreatAssessment {
	ipStr = strings.TrimSpace(ipStr)
	now := time.Now().UnixMilli()

	// 1. Whitelist check: instant zero-score bypass
	if ipStr == "" || se.IsWhitelisted(ipStr) {
		return ThreatAssessment{
			IP:            ipStr,
			FinalScore:    0,
			BaseScore:     rawScore,
			IsWhitelisted: true,
			Action:        ActionAllow,
			Tier:          "WHITELISTED",
			Breakdown:     "IP belongs to trusted whitelist/private subnet (Protected)",
			TimestampMs:   now,
		}
	}

	shard := se.getShard(ipStr)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.entities[ipStr]
	if !exists {
		state = &EntityState{
			IP:           ipStr,
			FirstSeenMs:  now,
			LastSeenMs:   now,
			CurrentScore: 0,
			RecentEvents: make([]MicroEvent, 0, 20),
		}
		shard.entities[ipStr] = state
	}

	if asnInfo != "" {
		state.LastASNInfo = asnInfo
		state.IsDatacenterASN = IsDatacenterASN(asnInfo)
	}

	// Check Live IPinfo Intelligence (Hosting / VPN / Tor exit node indicators)
	if ipinfoResp, ok := ipinfo.GetDefaultClient().GetCached(ipStr); ok && ipinfoResp != nil {
		if ipinfoResp.IsHosting || ipinfoResp.IsVPN || ipinfoResp.IsProxy || ipinfoResp.IsTor {
			state.IsDatacenterASN = true
		}
		if ipinfoResp.Org != "" {
			state.LastASNInfo = ipinfoResp.Org
		}
	}

	// 2. Exponential Half-Life Score Decay (Auto-Forgiveness)
	// S_t = S_0 * 0.5^(deltaT / 180s)
	deltaSeconds := float64(now-state.LastSeenMs) / 1000.0
	if deltaSeconds > 0 && state.CurrentScore > 0 {
		decayFactor := math.Pow(0.5, deltaSeconds/se.halfLifeSeconds)
		state.CurrentScore = state.CurrentScore * decayFactor
		if state.CurrentScore < 1.0 {
			state.CurrentScore = 0
		}
	}
	decayedScore := state.CurrentScore

	// 3. Prune events outside sliding 60s window
	cutoff := now - se.slidingWindowMs
	activeEvents := make([]MicroEvent, 0, len(state.RecentEvents))
	for _, ev := range state.RecentEvents {
		if ev.TimestampMs >= cutoff {
			activeEvents = append(activeEvents, ev)
		}
	}
	state.RecentEvents = activeEvents

	// 4. Categorize Event & Determine Base Increment
	var eventType string
	var baseIncrement float64
	var tier string
	var breakdownDetails []string

	// Apply +15 base threat intelligence risk when entity is identified as Hosting / VPN / Tor / Proxy
	if state.IsDatacenterASN {
		baseIncrement += 15.0
		breakdownDetails = append(breakdownDetails, "IPinfo Threat Intel: Hosting/VPN/Tor Entity (+15 Base Risk)")
	}

	// Multiplier for datacenter/cloud hosting / Tor / VPN
	riskMultiplier := 1.0
	if state.IsDatacenterASN {
		riskMultiplier = 1.3
	}

	// --- Tier 1: Instant Critical (Score: 95 - 100) ---
	if rawScore >= 95 || isTier1Rule(ruleID, mitreID) {
		tier = "TIER_1_CRITICAL"
		eventType = "TIER1_CRITICAL"
		baseIncrement = float64(rawScore)
		if baseIncrement < 95 {
			baseIncrement = 95
		}
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("Critical Threat Pattern (%s / %s)", ruleID, mitreID))

	// --- Tier 2: High Confidence Deception (Score: 85 - 90) ---
	} else if isDeceptionEvent(ruleID, rawScore) {
		tier = "TIER_2_DECEPTION"
		eventType = "HONEYPOT_TRAP"
		baseIncrement = 88.0
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("Direct Deception Trap Interaction (%s)", ruleID))

	// --- Tier 3: Rapid Cumulative Vectors ---
	} else if isAuthFailure(ruleID, rawScore) {
		tier = "TIER_3_CUMULATIVE"
		eventType = "SSH_AUTH_FAIL"
		state.ConsecutiveAuthFails++
		// Exponential multiplier for repeat failed authentications: 25 * 1.5^(n-1)
		expMult := math.Pow(1.5, float64(state.ConsecutiveAuthFails-1))
		baseIncrement = 25.0 * expMult
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("%dx SSH Auth Failures (Burst Increment: +%.1f)", state.ConsecutiveAuthFails, baseIncrement))

	} else if statusCode == 404 || statusCode == 403 || isWebBurst(ruleID) {
		tier = "TIER_3_CUMULATIVE"
		eventType = "WEB_4XX_BURST"
		state.RecentWeb4xxCount++
		baseIncrement = 10.0
		if state.RecentWeb4xxCount >= 6 {
			baseIncrement = 35.0 // Burst escalation
			breakdownDetails = append(breakdownDetails, fmt.Sprintf("Web Fuzzing Burst (%d invalid requests in window)", state.RecentWeb4xxCount))
		} else {
			breakdownDetails = append(breakdownDetails, fmt.Sprintf("HTTP %d Probe (+10)", statusCode))
		}

	} else if isDNSAnomaly(ruleID, mitreID) {
		tier = "TIER_3_CUMULATIVE"
		eventType = "DNS_ANOMALY"
		state.RecentDNSAnomalyCount++
		baseIncrement = 60.0
		breakdownDetails = append(breakdownDetails, "DNS Tunneling / High-Entropy DGA Resolution (+60)")

	} else if mitreID != "" && strings.HasPrefix(strings.ToUpper(mitreID), "T") {
		tier = "TIER_3_CUMULATIVE"
		eventType = "MITRE_TECHNIQUE"
		baseIncrement = float64(rawScore)
		if baseIncrement <= 0 || (isHighImpactMitre(mitreID) && baseIncrement < 60.0) {
			baseIncrement = 60.0
		}
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("MITRE Technique %s (%s, +%.0f Base)", mitreID, ruleID, baseIncrement))

	} else if strings.Contains(strings.ToLower(ruleID), "flow") || strings.Contains(strings.ToLower(ruleID), "probe") || strings.Contains(strings.ToLower(ruleID), "scan") {
		tier = "TIER_3_CUMULATIVE"
		eventType = "NETWORK_PROBE_BURST"
		baseIncrement = 15.0
		if float64(rawScore) > baseIncrement {
			baseIncrement = float64(rawScore)
		}
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("Network Flow/Probe Burst: %s (+%.0f)", ruleID, baseIncrement))

	} else {
		tier = "NORMAL"
		eventType = "GENERIC_RULE"
		baseIncrement = float64(rawScore)
		if baseIncrement > 0 {
			breakdownDetails = append(breakdownDetails, fmt.Sprintf("Rule Hit: %s (+%.0f)", ruleID, baseIncrement))
		}
	}

	// Apply Contextual Risk Multiplier to the increment
	adjustedIncrement := baseIncrement * riskMultiplier
	if riskMultiplier > 1.0 {
		breakdownDetails = append(breakdownDetails, fmt.Sprintf("Datacenter/Hosting ASN (x%.1f)", riskMultiplier))
	}

	// Update State
	state.LastSeenMs = now
	state.TotalIncidents++
	state.CurrentScore = math.Min(100.0, state.CurrentScore+adjustedIncrement)

	// Record MicroEvent in Sliding Window
	state.RecentEvents = append(state.RecentEvents, MicroEvent{
		TimestampMs: now,
		EventType:   eventType,
		RuleID:      ruleID,
		MitreID:     mitreID,
		BaseScore:   adjustedIncrement,
	})

	finalScoreInt := int(math.Round(state.CurrentScore))
	if finalScoreInt > 100 {
		finalScoreInt = 100
	}

	// Determine SOAR Action
	var action ThreatAction
	if finalScoreInt >= se.banThreshold || tier == "TIER_1_CRITICAL" || (tier == "TIER_2_DECEPTION" && finalScoreInt >= 80) {
		action = ActionInstantBan
		state.Quarantined = true
	} else if finalScoreInt >= se.tarpitThreshold {
		action = ActionTarpit
	} else if finalScoreInt >= 30 {
		action = ActionLog
	} else {
		action = ActionAllow
	}

	explanation := strings.Join(breakdownDetails, " + ")
	if explanation == "" {
		explanation = "Baseline telemetry observation"
	}
	formattedBreakdown := fmt.Sprintf("Threat Score: %d (Decayed Base: %.1f + %s)", finalScoreInt, decayedScore, explanation)

	return ThreatAssessment{
		IP:                  ipStr,
		FinalScore:          finalScoreInt,
		BaseScore:           rawScore,
		DecayedScore:        decayedScore,
		CumulativeIncrement: adjustedIncrement,
		RiskMultiplier:      riskMultiplier,
		IsWhitelisted:       false,
		Action:              action,
		Tier:                tier,
		Breakdown:           formattedBreakdown,
		TimestampMs:         now,
	}
}

// GetEntityState returns the live behavioral state for an IP.
func (se *ScoringEngine) GetEntityState(ipStr string) (*EntityState, bool) {
	shard := se.getShard(strings.TrimSpace(ipStr))
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	state, exists := shard.entities[strings.TrimSpace(ipStr)]
	if !exists {
		return nil, false
	}

	// Return clone
	clone := *state
	clone.RecentEvents = make([]MicroEvent, len(state.RecentEvents))
	copy(clone.RecentEvents, state.RecentEvents)
	return &clone, true
}

// ResetEntity clears scoring history for an IP (e.g. on manual unban).
func (se *ScoringEngine) ResetEntity(ipStr string) {
	shard := se.getShard(strings.TrimSpace(ipStr))
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.entities, strings.TrimSpace(ipStr))
}

// Helper detection classifiers
func isTier1Rule(ruleID, mitreID string) bool {
	r := strings.ToLower(ruleID)
	m := strings.ToUpper(mitreID)
	return strings.Contains(r, "revshell") ||
		strings.Contains(r, "rootkit") ||
		strings.Contains(r, "injection") ||
		strings.Contains(r, "sudoers") ||
		strings.Contains(r, "rce") ||
		m == "T1059.004" || m == "T1014" || m == "T1055" || m == "T1548.003"
}

func isDeceptionEvent(ruleID string, rawScore int) bool {
	r := strings.ToLower(ruleID)
	return strings.Contains(r, "honey") || strings.Contains(r, "deception") || strings.Contains(r, "canary")
}

func isAuthFailure(ruleID string, rawScore int) bool {
	r := strings.ToLower(ruleID)
	return strings.Contains(r, "auth") || strings.Contains(r, "bruteforce") || strings.Contains(r, "ssh") || strings.Contains(r, "login")
}

func isWebBurst(ruleID string) bool {
	r := strings.ToLower(ruleID)
	return strings.Contains(r, "scanner") || strings.Contains(r, "fuzz") || strings.Contains(r, "dirsearch") || strings.Contains(r, "nikto")
}

func isDNSAnomaly(ruleID, mitreID string) bool {
	r := strings.ToLower(ruleID)
	m := strings.ToUpper(mitreID)
	return strings.Contains(r, "dns") || strings.Contains(r, "dga") || strings.Contains(r, "tunnel") || m == "T1048.003" || m == "T1568.002"
}

func isHighImpactMitre(mitreID string) bool {
	m := strings.ToUpper(mitreID)
	return strings.HasPrefix(m, "T1078") || // Valid Accounts / Credential Abuse
		strings.HasPrefix(m, "T1190") || // Exploit Public-Facing Application
		strings.HasPrefix(m, "T1059") || // Command & Scripting Interpreter / Execution
		strings.HasPrefix(m, "T1068") || // Exploitation for Privilege Escalation
		strings.HasPrefix(m, "T1071") || // Application Layer Protocol C2
		strings.HasPrefix(m, "T1021")    // Remote Services
}
