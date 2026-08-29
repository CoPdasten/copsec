package main

import (
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/copsec/controller/pkg/models"
)

// IPActivityRecord tracks multi-signal activity in a sliding 60-second window.
type IPActivityRecord struct {
	IP               string
	PortProbes       int
	AuthFailures     int
	HttpErrors4xx5xx int
	EntropyAnomalies int
	ThreatIntelHit   bool
	LastSeenMs       int64
	Timestamps       []int64
}

// AutonomousSOAREngine coordinates sliding window threat correlation, automated zero-touch mitigation,
// cross-fleet dispatch, and TTL decay expiration.
type AutonomousSOAREngine struct {
	mu           sync.RWMutex
	storage      *StorageEngine
	server       *CentralServer
	ttlManager   *TTLBanManager
	wsHub        *WSHub
	threatIntel  *ThreatIntelEngine

	// Sliding 60-second window activity tracking per IP
	ipWindows    map[string]*IPActivityRecord
	autoBanned   map[string]int64 // IP -> timestamp of auto-ban

	// Engine state
	autoPilotActive int32 // atomic bool (1 = active, 0 = paused)
	banThreshold    int
	windowDuration  time.Duration
	stopChan        chan struct{}
	running         bool
}

var (
	defaultSOAREngine *AutonomousSOAREngine
	soarOnce          sync.Once
)

// GetDefaultSOAREngine returns the singleton instance of AutonomousSOAREngine.
func GetDefaultSOAREngine() *AutonomousSOAREngine {
	soarOnce.Do(func() {
		defaultSOAREngine = NewAutonomousSOAREngine(nil, nil, nil, nil, nil)
	})
	return defaultSOAREngine
}

// NewAutonomousSOAREngine initializes the autonomous SOAR correlation engine.
func NewAutonomousSOAREngine(
	storage *StorageEngine,
	server *CentralServer,
	ttlManager *TTLBanManager,
	wsHub *WSHub,
	threatIntel *ThreatIntelEngine,
) *AutonomousSOAREngine {
	if threatIntel == nil {
		threatIntel = GetDefaultThreatIntel()
	}

	engine := &AutonomousSOAREngine{
		storage:         storage,
		server:          server,
		ttlManager:      ttlManager,
		wsHub:           wsHub,
		threatIntel:     threatIntel,
		ipWindows:       make(map[string]*IPActivityRecord),
		autoBanned:      make(map[string]int64),
		autoPilotActive: 1, // Active by default
		banThreshold:    90,
		windowDuration:  60 * time.Second,
		stopChan:        make(chan struct{}),
	}

	return engine
}

// SetDependencies sets or updates runtime dependencies.
func (ase *AutonomousSOAREngine) SetDependencies(
	storage *StorageEngine,
	server *CentralServer,
	ttlManager *TTLBanManager,
	wsHub *WSHub,
	threatIntel *ThreatIntelEngine,
) {
	ase.mu.Lock()
	defer ase.mu.Unlock()
	if storage != nil {
		ase.storage = storage
	}
	if server != nil {
		ase.server = server
	}
	if ttlManager != nil {
		ase.ttlManager = ttlManager
	}
	if wsHub != nil {
		ase.wsHub = wsHub
	}
	if threatIntel != nil {
		ase.threatIntel = threatIntel
	}
}

// Start launches the TTL decay and sliding-window cleanup background workers.
func (ase *AutonomousSOAREngine) Start() {
	ase.mu.Lock()
	if ase.running {
		ase.mu.Unlock()
		return
	}
	ase.running = true
	ase.mu.Unlock()

	// TTL Decay & Ban Expiration Worker (Runs every 30 seconds)
	go ase.startTTLDecayWorker(30 * time.Second)

	log.Printf("[SOAR_ENGINE] ⚡ Autonomous SOAR & Correlation Engine active (Auto-Pilot: ON, Threshold: %d, Window: 60s)", ase.banThreshold)
}

// Stop cleanly terminates background workers.
func (ase *AutonomousSOAREngine) Stop() {
	ase.mu.Lock()
	defer ase.mu.Unlock()
	if !ase.running {
		return
	}
	ase.running = false
	close(ase.stopChan)
}

// IsAutoPilotActive returns whether zero-touch auto-pilot mitigation is enabled.
func (ase *AutonomousSOAREngine) IsAutoPilotActive() bool {
	return atomic.LoadInt32(&ase.autoPilotActive) == 1
}

// SetAutoPilotActive toggles the auto-pilot status dynamically.
func (ase *AutonomousSOAREngine) SetAutoPilotActive(active bool) {
	var val int32 = 0
	if active {
		val = 1
	}
	atomic.StoreInt32(&ase.autoPilotActive, val)

	ase.mu.RLock()
	hub := ase.wsHub
	ase.mu.RUnlock()

	if hub != nil {
		hub.Broadcast("soar_autopilot_toggle", map[string]interface{}{
			"active":    active,
			"timestamp": time.Now().UnixMilli(),
		})
	}
	log.Printf("[SOAR_ENGINE] Auto-Pilot state toggled: active=%v", active)
}

// CorrelateSignal ingests a telemetry signal, updates the sliding window, calculates composite threat score,
// and executes autonomous mitigation if composite score >= 90.
func (ase *AutonomousSOAREngine) CorrelateSignal(event *StoredEvent) (compositeScore int, correlationFactors string, mitigated bool) {
	if event == nil {
		return 0, "", false
	}

	ip := strings.TrimSpace(event.ClientIP)
	if ip == "" || isProtectedIP(ip) {
		return event.ThreatScore, "", false
	}

	nowMs := time.Now().UnixMilli()
	windowCutoffMs := nowMs - ase.windowDuration.Milliseconds()

	// 1. Evaluate Threat Intelligence feed match first
	var tiEntry *ThreatIntelEntry
	var tiMatched bool
	if ase.threatIntel != nil {
		tiEntry, tiMatched = ase.threatIntel.MatchIP(ip)
		if tiMatched && tiEntry != nil {
			// Boost threat score directly to 95 and tag payload
			if event.ThreatScore < 95 {
				event.ThreatScore = 95
				event.Severity = models.CalculateSeverity(95)
			}
			if !strings.Contains(event.ScoreBreakdown, "[THREAT INTEL HIT]") {
				if event.ScoreBreakdown != "" {
					event.ScoreBreakdown += " | [THREAT INTEL HIT] " + tiEntry.Category
				} else {
					event.ScoreBreakdown = "[THREAT INTEL HIT] " + tiEntry.Category
				}
			}
			if !strings.Contains(event.RawLine, "[THREAT INTEL HIT]") {
				event.RawLine = fmt.Sprintf("[THREAT INTEL HIT: %s (%s)] %s", tiEntry.Category, tiEntry.SourceFeed, event.RawLine)
			}
		}
	}

	ase.mu.Lock()
	rec, exists := ase.ipWindows[ip]
	if !exists {
		rec = &IPActivityRecord{
			IP:         ip,
			Timestamps: make([]int64, 0, 16),
		}
		ase.ipWindows[ip] = rec
	}

	// Evict expired timestamps from sliding window
	var validTimestamps []int64
	for _, ts := range rec.Timestamps {
		if ts >= windowCutoffMs {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	validTimestamps = append(validTimestamps, nowMs)
	rec.Timestamps = validTimestamps
	rec.LastSeenMs = nowMs

	if tiMatched {
		rec.ThreatIntelHit = true
	}

	// Classify incoming signal type into sliding window dimensions
	rawLower := strings.ToLower(event.RawLine)
	ruleLower := strings.ToLower(event.RuleID)

	// Port Probes / SYN Scans / Reconnaissance
	if strings.Contains(ruleLower, "scan") || strings.Contains(ruleLower, "probe") ||
		strings.Contains(rawLower, "port scan") || strings.Contains(rawLower, "syn flood") ||
		strings.Contains(ruleLower, "recon") || strings.Contains(ruleLower, "suricata_flow") && event.ThreatScore >= 40 {
		rec.PortProbes++
	}

	// Auth Failures / SSH Brute-force / Credential Stuffing
	if strings.Contains(ruleLower, "auth") || strings.Contains(ruleLower, "failed_password") ||
		strings.Contains(ruleLower, "bruteforce") || strings.Contains(rawLower, "failed password") ||
		strings.Contains(rawLower, "authentication failure") || strings.Contains(rawLower, "invalid user") {
		rec.AuthFailures++
	}

	// 4xx / 5xx HTTP Error Spikes
	if event.StatusCode >= 400 && event.StatusCode < 600 {
		rec.HttpErrors4xx5xx++
	}

	// Heuristic Entropy Anomalies & Injections (SQLi, RCE, Shellcode, Base64 high-entropy payloads)
	if event.MLAnomaly || strings.Contains(ruleLower, "sqli") || strings.Contains(ruleLower, "rce") ||
		strings.Contains(ruleLower, "revshell") || strings.Contains(ruleLower, "c2") ||
		strings.Contains(ruleLower, "yara") || strings.Contains(ruleLower, "evasion") ||
		strings.Contains(ruleLower, "dns_tunnel") || strings.Contains(ruleLower, "dga") ||
		CalculateShannonEntropy(event.RawLine) > 4.5 {
		rec.EntropyAnomalies++
	}

	// 2. Dynamically calculate composite threat score:
	// Score = min(100, sum(signal_weights))
	var factorList []string
	var scoreSum float64 = float64(event.ThreatScore)

	// Threat Intel Weight (+95 or +50 override)
	if rec.ThreatIntelHit {
		scoreSum = math.Max(scoreSum, 95.0)
		factorList = append(factorList, "Threat Intel Hit")
	}

	// Port Probes: 15 pts each, up to 35 pts
	if rec.PortProbes > 0 {
		probesScore := math.Min(35.0, float64(rec.PortProbes)*15.0)
		scoreSum += probesScore
		factorList = append(factorList, fmt.Sprintf("Port Scan (%d hits)", rec.PortProbes))
	}

	// Auth Failures: 20 pts each, up to 45 pts
	if rec.AuthFailures > 0 {
		authScore := math.Min(45.0, float64(rec.AuthFailures)*20.0)
		scoreSum += authScore
		factorList = append(factorList, fmt.Sprintf("Auth Failure / Credential Stuffing (%d attempts)", rec.AuthFailures))
	}

	// 4xx/5xx HTTP Spikes: 5 pts each, up to 25 pts
	if rec.HttpErrors4xx5xx >= 3 {
		httpScore := math.Min(25.0, float64(rec.HttpErrors4xx5xx)*5.0)
		scoreSum += httpScore
		factorList = append(factorList, fmt.Sprintf("HTTP 4xx/5xx Spike (%d requests)", rec.HttpErrors4xx5xx))
	}

	// Entropy / ML / Injection Anomalies: 25 pts each, up to 50 pts
	if rec.EntropyAnomalies > 0 {
		anomalyScore := math.Min(50.0, float64(rec.EntropyAnomalies)*25.0)
		scoreSum += anomalyScore
		factorList = append(factorList, fmt.Sprintf("Entropy Spike / Exploit Anomaly (%d hits)", rec.EntropyAnomalies))
	}

	finalScore := int(math.Min(100.0, math.Round(scoreSum)))

	factorsStr := strings.Join(factorList, " + ")
	if factorsStr != "" {
		correlationFactors = factorsStr + " -> Multi-Signal Correlation"
	} else {
		correlationFactors = "Single Signal Telemetry"
	}

	// Check if already auto-banned within last 1 hour
	nowSec := time.Now().Unix()
	if lastBan, banned := ase.autoBanned[ip]; banned && nowSec-lastBan < 3600 {
		ase.mu.Unlock()
		return finalScore, correlationFactors, false
	}

	// Auto-Pilot Mitigation Pipeline Trigger Gate
	isAutoPilot := atomic.LoadInt32(&ase.autoPilotActive) == 1
	shouldBan := isAutoPilot && finalScore >= ase.banThreshold

	if shouldBan {
		ase.autoBanned[ip] = nowSec
	}
	ase.mu.Unlock()

	if shouldBan {
		banReason := fmt.Sprintf("SOAR Auto-Pilot: %s (Composite Score: %d)", correlationFactors, finalScore)
		ase.ExecuteAutonomousBan(ip, 86400, banReason, event)
		mitigated = true
	}

	return finalScore, correlationFactors, mitigated
}

// ExecuteAutonomousBan executes zero-touch kernel mitigation, dispatches WebSocket & gRPC fleet bans,
// updates SQLite containment tables, and broadcasts an audit alert event.
func (ase *AutonomousSOAREngine) ExecuteAutonomousBan(sourceIP string, duration int64, reason string, event *StoredEvent) {
	cleanIP := strings.TrimSpace(sourceIP)
	if cleanIP == "" || isProtectedIP(cleanIP) {
		return
	}

	if duration <= 0 {
		duration = 86400 // Default 24h quarantine
	}

	log.Printf("[SOAR_AUTOPILOT] ⚡ EXECUTE AUTONOMOUS BAN: IP=%s, Duration=%ds, Reason=%s", cleanIP, duration, reason)

	ase.mu.RLock()
	storage := ase.storage
	server := ase.server
	ttlMgr := ase.ttlManager
	hub := ase.wsHub
	ase.mu.RUnlock()

	// 1. Enforce locally via TTLBanManager / Kernel XDP & L3/L4/L7 Drop
	if ttlMgr != nil {
		_, _ = ttlMgr.BanIP(cleanIP, reason, duration, TierAutoBanSOAR)
	} else {
		_ = ExecuteAbsoluteBan(cleanIP)
	}

	// 2. Dispatch ACTION_BAN_IP / FLEET_BAN to all connected fleet collectors over WebSocket & gRPC
	dispatchedCount := 0
	if server != nil {
		dispatchedCount = server.BroadcastSOARCommandWithReason("BAN_IP", cleanIP, reason, duration)
	}

	// 3. Insert / Update SQLite with triage_status = 'AUTO_MITIGATED', containment_state = 'XDP_DROP'
	if storage != nil {
		storage.AddMitigatedIP(cleanIP, time.Duration(duration)*time.Second)

		// Record structured ban entry
		_ = storage.RecordDetailedBan(&DetailedBanRecord{
			IP:              cleanIP,
			Reason:          reason,
			BanTimeMs:       time.Now().UnixMilli(),
			DurationSeconds: duration,
			ExpireTimeMs:    time.Now().UnixMilli() + (duration * 1000),
			PenaltyTier:     TierAutoBanSOAR,
			Status:          "ACTIVE",
			L3Active:        true,
			L4Active:        true,
			L7Active:        true,
			OffenseCount:    1,
		})

		// Update database rows for this IP to AUTO_MITIGATED & XDP_DROP
		storage.mu.Lock()
		_, _ = storage.db.Exec(`UPDATE telemetry SET triage_status = 'AUTO_MITIGATED', containment_state = 'XDP_DROP' WHERE client_ip = ?`, cleanIP)
		_, _ = storage.db.Exec(`UPDATE alerts SET triage_status = 'AUTO_MITIGATED', containment_state = 'XDP_DROP' WHERE client_ip = ?`, cleanIP)
		_, _ = storage.db.Exec(`UPDATE events SET triage_status = 'AUTO_MITIGATED', containment_state = 'XDP_DROP' WHERE client_ip = ?`, cleanIP)
		storage.mu.Unlock()

		_ = storage.RecordSOARAction("FLEET_BAN", cleanIP, dispatchedCount)
	}

	// 4. Broadcast an audit alert event over UI WebSocket tagged [SOAR AUTO-PILOT MITIGATION]
	if hub != nil {
		auditEvent := map[string]interface{}{
			"type":              "SOAR_AUTOPILOT_MITIGATION",
			"tag":               "[SOAR AUTO-PILOT MITIGATION]",
			"source_ip":         cleanIP,
			"duration_seconds":  duration,
			"reason":            reason,
			"containment_state": "XDP_DROP",
			"triage_status":     "AUTO_MITIGATED",
			"dispatched_nodes":  dispatchedCount,
			"timestamp_ms":      time.Now().UnixMilli(),
		}

		if event != nil {
			auditEvent["event_id"] = event.ID
			auditEvent["rule_id"] = event.RuleID
			auditEvent["mitre_id"] = event.MitreTechniqueID
			auditEvent["threat_score"] = event.ThreatScore
		}

		hub.Broadcast("ALERT_NEW", auditEvent)
		hub.Broadcast("soar_mitigation_audit", auditEvent)
		hub.Broadcast("FLEET_BAN", map[string]interface{}{
			"type":     "FLEET_BAN",
			"ip":       cleanIP,
			"duration": fmt.Sprintf("%ds", duration),
			"reason":   reason,
		})
	}
}

// startTTLDecayWorker runs a background loop every 30 seconds to evict expired IPs from
// kernel maps, Controller sync maps, and SQLite containment tables.
func (ase *AutonomousSOAREngine) startTTLDecayWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ase.stopChan:
			return
		case <-ticker.C:
			ase.runTTLDecayCycle()
		}
	}
}

func (ase *AutonomousSOAREngine) runTTLDecayCycle() {
	nowMs := time.Now().UnixMilli()
	windowCutoffMs := nowMs - ase.windowDuration.Milliseconds()

	// 1. Evict expired entries from in-memory sliding activity windows
	ase.mu.Lock()
	for ip, rec := range ase.ipWindows {
		if rec.LastSeenMs < windowCutoffMs {
			delete(ase.ipWindows, ip)
			continue
		}
		var valid []int64
		for _, ts := range rec.Timestamps {
			if ts >= windowCutoffMs {
				valid = append(valid, ts)
			}
		}
		if len(valid) == 0 {
			delete(ase.ipWindows, ip)
		} else {
			rec.Timestamps = valid
		}
	}

	// Evict autoBanned map entries older than 2 hours
	nowSec := time.Now().Unix()
	for ip, banTs := range ase.autoBanned {
		if nowSec-banTs > 7200 {
			delete(ase.autoBanned, ip)
		}
	}
	ase.mu.Unlock()

	// 2. Evict expired bans from SQLite and Kernel maps via TTLBanManager / Storage
	ase.mu.RLock()
	storage := ase.storage
	server := ase.server
	ttlMgr := ase.ttlManager
	ase.mu.RUnlock()

	if storage != nil {
		// Prune expired active bans from DB
		storage.mu.Lock()
		rows, err := storage.db.Query(`SELECT ip FROM active_bans WHERE status = 'ACTIVE' AND duration_seconds > 0 AND expire_time_ms > 0 AND expire_time_ms <= ?`, nowMs)
		var expiredIPs []string
		if err == nil {
			for rows.Next() {
				var ip string
				if err := rows.Scan(&ip); err == nil && ip != "" {
					expiredIPs = append(expiredIPs, ip)
				}
			}
			rows.Close()
		}

		for _, ip := range expiredIPs {
			_, _ = storage.db.Exec(`UPDATE active_bans SET status = 'EXPIRED', l3_active = 0, l4_active = 0, l7_active = 0 WHERE ip = ?`, ip)
			storage.RemoveMitigatedIP(ip)
		}
		storage.mu.Unlock()

		for _, ip := range expiredIPs {
			_ = ExecuteAbsoluteUnban(ip)
			if server != nil {
				server.BroadcastSOARCommand("UNBAN_IP", ip, 0)
			}
			log.Printf("[SOAR_TTL] 🟢 Evicted expired ban from kernel and SQLite: IP=%s", ip)
		}
	}

	// Trigger TTLManager evaluation cycle if available
	if ttlMgr != nil {
		ttlMgr.PruneExpiredBans()
	}
}

// PruneExpiredBans explicitly runs an eviction cycle (callable by tests).
func (ase *AutonomousSOAREngine) PruneExpiredBans() {
	ase.runTTLDecayCycle()
}

// GetEngineStats returns metrics regarding active windows and mitigations.
func (ase *AutonomousSOAREngine) GetEngineStats() map[string]interface{} {
	ase.mu.RLock()
	defer ase.mu.RUnlock()

	activeWindowsCount := len(ase.ipWindows)
	autoBannedCount := len(ase.autoBanned)
	autoPilot := atomic.LoadInt32(&ase.autoPilotActive) == 1

	return map[string]interface{}{
		"auto_pilot_active":    autoPilot,
		"active_ip_windows":    activeWindowsCount,
		"auto_banned_count":    autoBannedCount,
		"sliding_window_sec":   int(ase.windowDuration.Seconds()),
		"ban_score_threshold":  ase.banThreshold,
	}
}
