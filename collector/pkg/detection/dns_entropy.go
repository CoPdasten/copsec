package detection

import (
	"encoding/json"
	"log"
	"math"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNSEntropyResult represents the calculation and sliding-window suspicion state for a DNS query.
type DNSEntropyResult struct {
	SrcIP            string  `json:"src_ip"`
	QueryDomain      string  `json:"query_domain"`
	LowestLabel      string  `json:"lowest_label"`
	LabelLength      int     `json:"label_length"`
	Entropy          float64 `json:"entropy"`
	IsHighEntropy    bool    `json:"is_high_entropy"`
	ActiveSpikeCount int     `json:"active_spike_count"`
	Triggered        bool    `json:"triggered"`
	RuleID           string  `json:"rule_id,omitempty"`
	ThreatScore      int     `json:"threat_score,omitempty"`
	MitreID          string  `json:"mitre_id,omitempty"`
	ActionTaken      string  `json:"action_taken,omitempty"`
}

// DNSEntropyEvaluator detects DNS tunneling and C2 exfiltration through Shannon entropy analysis
// and sliding-window spike correlation.
type DNSEntropyEvaluator struct {
	mu              sync.RWMutex
	lengthThreshold int           // Default > 24 chars
	entropyThreshold float64      // Default > 4.5
	spikeThreshold  int           // Default 3 spikes
	windowDuration  time.Duration // Default 30 seconds

	// Sliding window tracking: srcIP -> []int64 (spike timestamps in ms)
	hostSpikes map[string][]int64

	// Threat action callback
	onThreatDetected func(result *DNSEntropyResult)

	totalEvaluated  uint64
	totalSpikes     uint64
	totalDetections uint64
}

var (
	defaultDNSEvaluator *DNSEntropyEvaluator
	dnsEvalOnce         sync.Once
	bindRegex           = regexp.MustCompile(`client\s+(?:@\S+\s+)?(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)#\d+.*:\s+query:\s+(\S+)\s+IN\s+(\S+)`)
)

// GetDefaultDNSEntropyEvaluator returns the singleton DNS entropy detection evaluator.
func GetDefaultDNSEntropyEvaluator() *DNSEntropyEvaluator {
	dnsEvalOnce.Do(func() {
		defaultDNSEvaluator = NewDNSEntropyEvaluator(24, 4.5, 3, 30*time.Second, nil)
	})
	return defaultDNSEvaluator
}

// NewDNSEntropyEvaluator initializes a new DNS entropy evaluator.
func NewDNSEntropyEvaluator(
	minLen int,
	minEntropy float64,
	spikeLimit int,
	windowDur time.Duration,
	onThreat func(*DNSEntropyResult),
) *DNSEntropyEvaluator {
	if minLen <= 0 {
		minLen = 24
	}
	if minEntropy <= 0 {
		minEntropy = 4.5
	}
	if spikeLimit <= 0 {
		spikeLimit = 3
	}
	if windowDur <= 0 {
		windowDur = 30 * time.Second
	}

	return &DNSEntropyEvaluator{
		lengthThreshold:  minLen,
		entropyThreshold: minEntropy,
		spikeThreshold:   spikeLimit,
		windowDuration:   windowDur,
		hostSpikes:       make(map[string][]int64),
		onThreatDetected: onThreat,
	}
}

// SetThreatCallback sets the handler invoked when RULE-DNS-TUNNEL-001 triggers.
func (e *DNSEntropyEvaluator) SetThreatCallback(cb func(*DNSEntropyResult)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onThreatDetected = cb
}

// CalculateShannonEntropy computes H(X) = -\sum P(x_i) \log_2 P(x_i) over an input string.
func CalculateShannonEntropy(s string) float64 {
	length := len(s)
	if length == 0 {
		return 0.0
	}

	freq := make(map[rune]int)
	for _, ch := range s {
		freq[ch]++
	}

	var entropy float64
	flen := float64(length)
	for _, count := range freq {
		p := float64(count) / flen
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// ExtractSubdomainLabels splits a full domain name into lowest-level label, subdomain prefix, and root domain.
func ExtractSubdomainLabels(domain string) (lowestLabel string, fullSubdomain string, rootDomain string) {
	clean := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if clean == "" {
		return "", "", ""
	}

	labels := strings.Split(clean, ".")
	if len(labels) <= 2 {
		return labels[0], "", clean
	}

	lowestLabel = labels[0]
	rootDomain = strings.Join(labels[len(labels)-2:], ".")
	fullSubdomain = strings.Join(labels[:len(labels)-2], ".")
	return lowestLabel, fullSubdomain, rootDomain
}

// EvaluateQuery inspects a DNS query domain and evaluates high-entropy tunneling criteria.
func (e *DNSEntropyEvaluator) EvaluateQuery(srcIP, queryDomain string) (*DNSEntropyResult, bool) {
	atomic.AddUint64(&e.totalEvaluated, 1)

	lowestLabel, _, _ := ExtractSubdomainLabels(queryDomain)
	labelLen := len(lowestLabel)
	entropy := CalculateShannonEntropy(lowestLabel)

	isHighEntropy := labelLen > e.lengthThreshold && entropy > e.entropyThreshold

	result := &DNSEntropyResult{
		SrcIP:         srcIP,
		QueryDomain:   queryDomain,
		LowestLabel:   lowestLabel,
		LabelLength:   labelLen,
		Entropy:       math.Round(entropy*1000) / 1000,
		IsHighEntropy: isHighEntropy,
	}

	if !isHighEntropy {
		return result, false
	}

	atomic.AddUint64(&e.totalSpikes, 1)

	// Sliding-window correlation
	nowMs := time.Now().UnixMilli()
	windowMs := e.windowDuration.Milliseconds()
	cutoffMs := nowMs - windowMs

	e.mu.Lock()
	spikes := e.hostSpikes[srcIP]

	// Prune timestamps older than 30 seconds
	active := make([]int64, 0, len(spikes)+1)
	for _, ts := range spikes {
		if ts >= cutoffMs {
			active = append(active, ts)
		}
	}
	active = append(active, nowMs)
	e.hostSpikes[srcIP] = active
	spikeCount := len(active)
	e.mu.Unlock()

	result.ActiveSpikeCount = spikeCount

	// Check if threshold met (e.g. 3 high-entropy spikes within 30 seconds)
	if spikeCount >= e.spikeThreshold {
		result.Triggered = true
		result.RuleID = "RULE-DNS-TUNNEL-001"
		result.ThreatScore = 85
		result.MitreID = "T1071.004" // Application Layer Protocol: DNS Tunneling
		result.ActionTaken = "XDP_FIREWALL_BLOCK"

		atomic.AddUint64(&e.totalDetections, 1)
		log.Printf("[DNS_TUNNEL_ALERT] 🚨 RULE-DNS-TUNNEL-001 triggered for %s: %d high-entropy DNS spikes in %v (Domain: %s, Entropy: %.2f, Len: %d) [MITRE: T1071.004, Score: 85]",
			srcIP, spikeCount, e.windowDuration, queryDomain, entropy, labelLen)

		e.mu.RLock()
		cb := e.onThreatDetected
		e.mu.RUnlock()

		if cb != nil {
			cb(result)
		}

		return result, true
	}

	return result, false
}

// IngestRawLog parses Suricata EVE JSON, BIND query logs, or raw DNS strings and evaluates entropy.
func (e *DNSEntropyEvaluator) IngestRawLog(rawLine string) (*DNSEntropyResult, bool) {
	srcIP, domain, ok := ParseDNSLog(rawLine)
	if !ok || domain == "" {
		return nil, false
	}

	return e.EvaluateQuery(srcIP, domain)
}

// ParseDNSLog extracts the client IP and query domain from Suricata EVE JSON or BIND query logs.
func ParseDNSLog(line string) (srcIP, domain string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}

	// 1. Try Suricata EVE JSON parser
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"dns"`) {
		var eve struct {
			EventType string `json:"event_type"`
			SrcIP     string `json:"src_ip"`
			DNS       struct {
				RRName string `json:"rrname"`
				Type   string `json:"type"`
			} `json:"dns"`
		}
		if err := json.Unmarshal([]byte(trimmed), &eve); err == nil {
			if eve.EventType == "dns" && eve.DNS.RRName != "" {
				return eve.SrcIP, eve.DNS.RRName, true
			}
		}
	}

	// 2. Try BIND / Named query log parser
	if strings.Contains(trimmed, "query:") {
		matches := bindRegex.FindStringSubmatch(trimmed)
		if len(matches) >= 3 {
			return matches[1], matches[2], true
		}
	}

	// 3. Try standard space-delimited DNS log
	fields := strings.Fields(trimmed)
	for i, f := range fields {
		if net.ParseIP(f) != nil && srcIP == "" {
			srcIP = f
		}
		if (strings.Contains(f, ".com") || strings.Contains(f, ".net") || strings.Contains(f, ".org") || strings.Contains(f, ".io") || strings.Contains(f, ".c2")) && domain == "" {
			if i > 0 && !strings.Contains(f, "@") && !strings.HasPrefix(f, "http") {
				domain = f
			}
		}
	}

	if srcIP != "" && domain != "" {
		return srcIP, domain, true
	}

	return "", "", false
}

// ResetHostSpikes clears sliding-window strike history for an IP.
func (e *DNSEntropyEvaluator) ResetHostSpikes(srcIP string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.hostSpikes, srcIP)
}

// GetStats returns telemetry metrics for the DNS tunneling engine.
func (e *DNSEntropyEvaluator) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"total_evaluated":  atomic.LoadUint64(&e.totalEvaluated),
		"total_spikes":     atomic.LoadUint64(&e.totalSpikes),
		"total_detections": atomic.LoadUint64(&e.totalDetections),
		"tracked_hosts":    len(e.hostSpikes),
	}
}
