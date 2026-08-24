package dns

import (
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNSSinkholeEvent records an intercepted malicious C2 query or data exfiltration attempt.
type DNSSinkholeEvent struct {
	TimestampMs int64   `json:"timestamp_ms"`
	CallerPID   int     `json:"caller_pid"`
	ProcessName string  `json:"process_name"`
	Domain      string  `json:"domain"`
	RecordType  string  `json:"record_type"`
	AnomalyType string  `json:"anomaly_type"` // DGA_DOMAIN, DNS_TUNNELING, C2_IOC_MATCH
	Entropy     float64 `json:"entropy"`
	SinkholedTo string  `json:"sinkholed_to"`
	ThreatScore int     `json:"threat_score"`
	MitreID     string  `json:"mitre_id"`
	Details     string  `json:"details"`
}

// DNSSinkholeEngine evaluates outbound domain resolutions and intercepts C2 channels.
type DNSSinkholeEngine struct {
	mu               sync.RWMutex
	queriesInspected uint64
	sinkholedTotal   uint64
	dgaDetected      uint64
	exfilBlocked     uint64
	recentEvents     []DNSSinkholeEvent
	knownC2Suffixes  []string
	hexBase64Regex   *regexp.Regexp
	onSinkhole       func(ev DNSSinkholeEvent)
}

var (
	defaultSinkhole *DNSSinkholeEngine
	sinkholeOnce    sync.Once
)

// GetDefaultSinkhole returns the singleton DNS sinkhole engine.
func GetDefaultSinkhole() *DNSSinkholeEngine {
	sinkholeOnce.Do(func() {
		defaultSinkhole = NewDNSSinkholeEngine(nil)
	})
	return defaultSinkhole
}

// NewDNSSinkholeEngine initializes the DNS C2 Sinkhole and Exfiltration Guard.
func NewDNSSinkholeEngine(onSinkhole func(ev DNSSinkholeEvent)) *DNSSinkholeEngine {
	return &DNSSinkholeEngine{
		recentEvents:   make([]DNSSinkholeEvent, 0, 50),
		hexBase64Regex: regexp.MustCompile(`(?i)^[a-f0-9]{32,}|^[a-z0-9+/=]{36,}$`),
		knownC2Suffixes: []string{
			"oastify.com",
			"burpcollaborator.net",
			"canarytokens.com",
			"interact.sh",
			"requestbin.net",
			"ngrok-free.app",
			"trycloudflare.com",
			"c2server.org",
			"cobaltstrike.online",
		},
		onSinkhole: onSinkhole,
	}
}

// CalculateShannonEntropy measures randomness to identify algorithmic Domain Generation Algorithms (DGA).
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	total := float64(len(s))
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// InspectDomain analyzes a target domain before resolution. Returns sinkholed event if malicious.
func (e *DNSSinkholeEngine) InspectDomain(domain, recordType string, callerPID int) (*DNSSinkholeEvent, bool) {
	atomic.AddUint64(&e.queriesInspected, 1)

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || domain == "localhost" || strings.HasSuffix(domain, ".local") {
		return nil, false
	}

	procName := e.getProcessName(callerPID)

	// 1. C2 Threat Intel Known Suffix Match
	for _, c2 := range e.knownC2Suffixes {
		if strings.HasSuffix(domain, c2) {
			ev := e.createSinkholeEvent(
				callerPID, procName, domain, recordType,
				"C2_IOC_MATCH", 0.0, 95, "T1071.004",
				fmt.Sprintf("Matched known Out-of-Band / C2 Infrastructure domain suffix %q", c2),
			)
			return ev, true
		}
	}

	// 2. DNS Tunneling / Data Exfiltration (Long subdomains with hex/base64 payloads)
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		subdomain := parts[0]
		if len(subdomain) >= 30 && e.hexBase64Regex.MatchString(subdomain) {
			atomic.AddUint64(&e.exfilBlocked, 1)
			ev := e.createSinkholeEvent(
				callerPID, procName, domain, recordType,
				"DNS_TUNNELING", CalculateShannonEntropy(subdomain), 98, "T1048.003",
				fmt.Sprintf("High-volume DNS Tunneling data exfiltration detected in subdomain payload (len: %d)", len(subdomain)),
			)
			return ev, true
		}
	}

	// 3. Domain Generation Algorithm (DGA) High Entropy Check
	entropy := CalculateShannonEntropy(domain)
	if len(domain) > 18 && entropy > 3.85 && !strings.HasSuffix(domain, ".com") && !strings.HasSuffix(domain, ".org") {
		atomic.AddUint64(&e.dgaDetected, 1)
		ev := e.createSinkholeEvent(
			callerPID, procName, domain, recordType,
			"DGA_DOMAIN", entropy, 85, "T1568.002",
			fmt.Sprintf("High Shannon entropy (%.2f/4.00) indicates algorithmically generated C2 rendezvous domain", entropy),
		)
		return ev, true
	}

	return nil, false
}

func (e *DNSSinkholeEngine) createSinkholeEvent(pid int, procName, domain, recType, anomaly string, entropy float64, score int, mitre, details string) *DNSSinkholeEvent {
	atomic.AddUint64(&e.sinkholedTotal, 1)

	ev := &DNSSinkholeEvent{
		TimestampMs: time.Now().UnixMilli(),
		CallerPID:   pid,
		ProcessName: procName,
		Domain:      domain,
		RecordType:  recType,
		AnomalyType: anomaly,
		Entropy:     entropy,
		SinkholedTo: "0.0.0.0",
		ThreatScore: score,
		MitreID:     mitre,
		Details:     details,
	}

	e.mu.Lock()
	e.recentEvents = append(e.recentEvents, *ev)
	if len(e.recentEvents) > 50 {
		e.recentEvents = e.recentEvents[1:]
	}
	e.mu.Unlock()

	log.Printf("[DNS_SINKHOLE] 🚫 SINKHOLED C2 RESOLUTION: %s (PID: %d [%s], Anomaly: %s, Score: %d)",
		domain, pid, procName, anomaly, score)

	if e.onSinkhole != nil {
		go e.onSinkhole(*ev)
	}

	return ev
}

func (e *DNSSinkholeEngine) getProcessName(pid int) string {
	if pid <= 0 {
		return "unknown"
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	return fmt.Sprintf("proc_%d", pid)
}

// GetStats returns metrics for the DNS Sinkhole.
func (e *DNSSinkholeEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"queries_inspected": atomic.LoadUint64(&e.queriesInspected),
		"sinkholed_total":   atomic.LoadUint64(&e.sinkholedTotal),
		"dga_detected":      atomic.LoadUint64(&e.dgaDetected),
		"exfil_blocked":     atomic.LoadUint64(&e.exfilBlocked),
		"recent_events":     len(e.recentEvents),
	}
}

// GetRecentEvents returns the recent DNS sinkhole logs.
func (e *DNSSinkholeEngine) GetRecentEvents() []DNSSinkholeEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]DNSSinkholeEvent, len(e.recentEvents))
	copy(res, e.recentEvents)
	return res
}
