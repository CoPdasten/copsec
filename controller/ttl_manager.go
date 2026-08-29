package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/copsec/controller/pkg/geoip"
)

// PenaltyTier represents the severity tier in the SOAR penalty lifecycle.
type PenaltyTier string

const (
	TierRateLimit          PenaltyTier = "RATE_LIMIT"          // 300 seconds (5 min)
	TierTempIsolation      PenaltyTier = "TEMP_ISOLATION"      // 3600 seconds (1 hour)
	TierAutoBanSOAR        PenaltyTier = "AUTOBAN_SOAR"        // Autonomous SOAR threshold / sigma / suricata trigger
	TierExtendedQuarantine PenaltyTier = "EXTERNAL_QUARANTINE" // 86400 seconds (24 hours)
	TierPermanent          PenaltyTier = "PERMANENT"           // 0 or -1 (Indefinite)
)

// DetailedBanRecord represents an active or historic SOAR quarantine entry.
type DetailedBanRecord struct {
	IP              string      `json:"ip"`
	Reason          string      `json:"reason"`
	BanTimeMs       int64       `json:"ban_time_ms"`
	DurationSeconds int64       `json:"duration_seconds"`
	ExpireTimeMs    int64       `json:"expire_time_ms"`
	PenaltyTier     PenaltyTier `json:"penalty_tier"`
	Status          string      `json:"status"` // ACTIVE, EXPIRED, MANUAL_UNBAN
	L3Active        bool        `json:"l3_active"`
	L4Active        bool        `json:"l4_active"`
	L7Active        bool        `json:"l7_active"`
	OffenseCount    int         `json:"offense_count"`
	RemainingSec    int64       `json:"remaining_sec"`
	CountryCode     string      `json:"country_code,omitempty"`
	CountryName     string      `json:"country_name,omitempty"`
	FlagEmoji       string      `json:"flag_emoji,omitempty"`
	ASN             string      `json:"asn,omitempty"`
}

// TTLBanManager orchestrates the multi-layer kernel/WAF mitigation and tiered TTL lifecycle.
type TTLBanManager struct {
	mu           sync.RWMutex
	storage      *StorageEngine
	server       *CentralServer
	activeBans   map[string]*DetailedBanRecord
	ipOffenses   map[string]int
	stopChan     chan struct{}
	onBanChange  func(ban *DetailedBanRecord, action string)
}

// NewTTLBanManager initializes the SOAR mitigation and TTL lifecycle supervisor.
func NewTTLBanManager(storage *StorageEngine, server *CentralServer) *TTLBanManager {
	mgr := &TTLBanManager{
		storage:    storage,
		server:     server,
		activeBans: make(map[string]*DetailedBanRecord),
		ipOffenses: make(map[string]int),
		stopChan:   make(chan struct{}),
	}

	// Restore active bans from SQLite on startup
	mgr.restoreActiveBans()

	// Start autonomous TTL pruning ticker (evaluates every 1 second)
	go mgr.startTTLPruningLoop()

	return mgr
}

// SetOnBanChangeCallback registers a listener for real-time WebSocket / TUI ban state broadcasts.
func (tm *TTLBanManager) SetOnBanChangeCallback(cb func(ban *DetailedBanRecord, action string)) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.onBanChange = cb
}

func (tm *TTLBanManager) restoreActiveBans() {
	if tm.storage == nil {
		return
	}

	bans, err := tm.storage.GetActiveBansDetailed()
	if err != nil {
		log.Printf("[WARN] Failed to restore active bans from DB: %v", err)
		return
	}

	nowMs := time.Now().UnixMilli()
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, b := range bans {
		if b.Status == "ACTIVE" {
			cleanIP := strings.TrimSpace(b.IP)
			if isProtectedIP(cleanIP) || strings.Contains(strings.ToLower(b.Reason), "sudo") {
				_ = tm.storage.RemoveBan(b.IP)
				_ = ExecuteAbsoluteUnban(b.IP)
				continue
			}
			// Check if already expired while offline
			if b.DurationSeconds > 0 && b.ExpireTimeMs > 0 && b.ExpireTimeMs <= nowMs {
				// Expired during downtime
				_ = tm.storage.UpdateBanStatus(b.IP, "EXPIRED")
				continue
			}
			tm.activeBans[b.IP] = b
			tm.ipOffenses[b.IP] = b.OffenseCount
			// Re-enforce instant L3/L4/L7 kernel rules
			_ = ExecuteAbsoluteBan(b.IP)
		}
	}

	log.Printf("[INFO] SOAR TTL Manager restored %d active quarantined IPs from SQLite", len(tm.activeBans))
}

// BanIP enforces instant hybrid L3/L4/L7 ban with dynamic tiered TTL lifecycle.
func (tm *TTLBanManager) BanIP(ip, reason string, customDurationSec int64, tier PenaltyTier) (*DetailedBanRecord, error) {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || isProtectedIP(cleanIP) {
		return nil, fmt.Errorf("ip %s is protected or invalid", cleanIP)
	}

	tm.mu.Lock()
	offenses := tm.ipOffenses[cleanIP] + 1
	tm.ipOffenses[cleanIP] = offenses

	// Determine duration and tier based on progressive escalation
	duration := customDurationSec
	finalTier := tier

	if duration <= 0 && tier == "" {
		switch offenses {
		case 1:
			duration = 300 // Tier 1: 5 minutes
			finalTier = TierRateLimit
		case 2:
			duration = 3600 // Tier 2: 1 hour
			finalTier = TierTempIsolation
		case 3:
			duration = 86400 // Tier 3: 24 hours
			finalTier = TierExtendedQuarantine
		default:
			duration = -1 // Tier 4: Permanent
			finalTier = TierPermanent
		}
	} else if finalTier == "" {
		if duration == 300 {
			finalTier = TierRateLimit
		} else if duration == 3600 {
			finalTier = TierTempIsolation
		} else if duration >= 86400 {
			finalTier = TierExtendedQuarantine
		} else if duration < 0 {
			finalTier = TierPermanent
		} else {
			finalTier = TierTempIsolation
		}
	}

	now := time.Now()
	nowMs := now.UnixMilli()
	var expireMs int64 = 0
	if duration > 0 {
		expireMs = nowMs + (duration * 1000)
	}

	record := &DetailedBanRecord{
		IP:              cleanIP,
		Reason:          reason,
		BanTimeMs:       nowMs,
		DurationSeconds: duration,
		ExpireTimeMs:    expireMs,
		PenaltyTier:     finalTier,
		Status:          "ACTIVE",
		L3Active:        true,
		L4Active:        true,
		L7Active:        true,
		OffenseCount:    offenses,
		RemainingSec:    duration,
	}

	tm.activeBans[cleanIP] = record
	cb := tm.onBanChange
	tm.mu.Unlock()

	// 1. Zero-Latency L3/L4/L7 Local Mitigation Execution
	err := ExecuteAbsoluteBan(cleanIP)
	if err != nil {
		log.Printf("[WARN] ExecuteAbsoluteBan error for %s: %v", cleanIP, err)
	}

	// 2. Persist in Embedded SQLite Storage
	if tm.storage != nil {
		_ = tm.storage.RecordDetailedBan(record)
		_ = tm.storage.RecordSOARAction("BAN_IP", cleanIP, 1)
	}

	// 3. Broadcast to Distributed Fleet Nodes
	if tm.server != nil {
		tm.server.BroadcastSOARCommand("BAN_IP", cleanIP, duration)
	}

	// 4. Notify WebSocket and TUI subscribers
	if cb != nil {
		cb(record, "BAN")
	}

	log.Printf("[SOAR_TTL] ⚡ Active Quarantine Enforced for %s (Tier: %s, Duration: %ds, Offenses: %d, Reason: %s)",
		cleanIP, finalTier, duration, offenses, reason)

	return record, nil
}

// UnbanIP terminates mitigation across all layers and marks ban as UNBANNED.
func (tm *TTLBanManager) UnbanIP(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return fmt.Errorf("empty ip")
	}

	tm.mu.Lock()
	record, exists := tm.activeBans[cleanIP]
	if exists {
		record.Status = "MANUAL_UNBAN"
		record.L3Active = false
		record.L4Active = false
		record.L7Active = false
		record.RemainingSec = 0
		delete(tm.activeBans, cleanIP)
	}
	cb := tm.onBanChange
	tm.mu.Unlock()

	// 1. Local Full Unban (L3 iptables, L7 nginx blocklist)
	_ = ExecuteAbsoluteUnban(cleanIP)

	// 2. Update DB
	if tm.storage != nil {
		_ = tm.storage.UpdateBanStatus(cleanIP, "MANUAL_UNBAN")
		_ = tm.storage.RecordSOARAction("UNBAN_IP", cleanIP, 1)
	}

	// 3. Broadcast Fleet Unban
	if tm.server != nil {
		tm.server.BroadcastSOARCommand("UNBAN_IP", cleanIP, 0)
	}

	if cb != nil && record != nil {
		cb(record, "UNBAN")
	}

	log.Printf("[SOAR_TTL] 🟢 Quarantine Released (Manual Unban) for %s", cleanIP)
	return nil
}

// GetActiveBans returns current snapshot of quarantined IPs with live calculated remaining seconds.
func (tm *TTLBanManager) GetActiveBans() []DetailedBanRecord {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	nowMs := time.Now().UnixMilli()
	var list []DetailedBanRecord
	geo := geoip.GetDefaultEngine()
	for _, b := range tm.activeBans {
		rec := *b
		if rec.DurationSeconds > 0 && rec.ExpireTimeMs > 0 {
			rem := (rec.ExpireTimeMs - nowMs) / 1000
			if rem < 0 {
				rem = 0
			}
			rec.RemainingSec = rem
		} else {
			rec.RemainingSec = -1 // Permanent
		}
		if rec.IP != "" {
			loc := geo.Lookup(rec.IP)
			rec.CountryCode = loc.CountryCode
			rec.CountryName = loc.CountryName
			rec.FlagEmoji = loc.FlagEmoji
			rec.ASN = loc.ASN
		}
		list = append(list, rec)
	}
	return list
}

// startTTLPruningLoop continuously inspects active bans and cleans up expired ones with zero latency.
func (tm *TTLBanManager) startTTLPruningLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tm.stopChan:
			return
		case now := <-ticker.C:
			tm.pruneExpiredBans(now)
		}
	}
}

func (tm *TTLBanManager) pruneExpiredBans(now time.Time) {
	nowMs := now.UnixMilli()

	var expiredList []*DetailedBanRecord

	tm.mu.Lock()
	for ip, record := range tm.activeBans {
		if record.DurationSeconds > 0 && record.ExpireTimeMs > 0 && record.ExpireTimeMs <= nowMs {
			record.Status = "EXPIRED"
			record.L3Active = false
			record.L4Active = false
			record.L7Active = false
			record.RemainingSec = 0
			expiredList = append(expiredList, record)
			delete(tm.activeBans, ip)
		}
	}
	cb := tm.onBanChange
	tm.mu.Unlock()

	for _, expired := range expiredList {
		log.Printf("[SOAR_TTL] ⏳ Ban Expired for %s (Tier: %s, BanTime: %s). Executing autonomous unban.",
			expired.IP, expired.PenaltyTier, time.UnixMilli(expired.BanTimeMs).Format(time.RFC3339))

		// 1. Clear Kernel L3 / Conntrack & L7 Nginx rules
		_ = ExecuteAbsoluteUnban(expired.IP)

		// 2. Mark EXPIRED in SQLite
		if tm.storage != nil {
			_ = tm.storage.UpdateBanStatus(expired.IP, "EXPIRED")
			_ = tm.storage.RecordSOARAction("AUTO_EXPIRE_UNBAN", expired.IP, 1)
		}

		// 3. Broadcast to fleet
		if tm.server != nil {
			tm.server.BroadcastSOARCommand("UNBAN_IP", expired.IP, 0)
		}

		if cb != nil {
			cb(expired, "EXPIRED")
		}
	}
}

// PruneExpiredBans manually triggers an expiration cycle.
func (tm *TTLBanManager) PruneExpiredBans() {
	tm.pruneExpiredBans(time.Now())
}

// Stop terminates the TTL pruning loop.
func (tm *TTLBanManager) Stop() {
	close(tm.stopChan)
}

