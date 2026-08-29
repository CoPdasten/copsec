package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// TrustEntityState tracks dynamic real-time contextual trust scoring for an entity/IP.
type TrustEntityState struct {
	EntityID           string    `json:"entity_id"`
	IP                 string    `json:"ip"`
	TrustScore         int       `json:"trust_score"` // Baseline 100
	LastSeen           time.Time `json:"last_seen"`
	LastASN            string    `json:"last_asn"`
	LastCountry        string    `json:"last_country"`
	OffHoursViolations int       `json:"off_hours_violations"`
	EntropyViolations  int       `json:"entropy_violations"`
	GeoVelocityDrifts  int       `json:"geo_velocity_drifts"`
	PenaltyLog         []string  `json:"penalty_log"`
	IsIsolated         bool      `json:"is_isolated"`
	StepUpAuthRequired bool      `json:"step_up_auth_required"`
}

// ContextualZeroTrustEngine dynamically evaluates entity trust scores and enforces Zero Trust policies.
type ContextualZeroTrustEngine struct {
	mu            sync.RWMutex
	entities      map[string]*TrustEntityState
	server        *CentralServer
	wsHub         *WSHub
	storage       *StorageEngine
	workHourStart int // e.g. 8 (08:00)
	workHourEnd   int // e.g. 20 (20:00)
}

var (
	defaultTrustEngine *ContextualZeroTrustEngine
	trustOnce          sync.Once
)

// GetDefaultZeroTrustEngine returns the singleton Zero Trust engine.
func GetDefaultZeroTrustEngine() *ContextualZeroTrustEngine {
	trustOnce.Do(func() {
		defaultTrustEngine = NewContextualZeroTrustEngine(nil, nil, nil)
	})
	return defaultTrustEngine
}

// NewContextualZeroTrustEngine creates an instance of ContextualZeroTrustEngine.
func NewContextualZeroTrustEngine(server *CentralServer, wsHub *WSHub, storage *StorageEngine) *ContextualZeroTrustEngine {
	return &ContextualZeroTrustEngine{
		entities:      make(map[string]*TrustEntityState),
		server:        server,
		wsHub:         wsHub,
		storage:       storage,
		workHourStart: 8,
		workHourEnd:   20,
	}
}

// SetDependencies dynamically wires CentralServer, WSHub and StorageEngine.
func (zte *ContextualZeroTrustEngine) SetDependencies(server *CentralServer, wsHub *WSHub, storage *StorageEngine) {
	zte.mu.Lock()
	defer zte.mu.Unlock()
	if server != nil {
		zte.server = server
	}
	if wsHub != nil {
		zte.wsHub = wsHub
	}
	if storage != nil {
		zte.storage = storage
	}
}

// EvaluateEvent evaluates an incoming security event and applies real-time contextual trust penalties.
// Returns updated trust score and whether isolation or step-up auth was triggered.
func (zte *ContextualZeroTrustEngine) EvaluateEvent(event *StoredEvent) (int, bool, bool) {
	if event == nil || event.ClientIP == "" || isProtectedIP(event.ClientIP) {
		return 100, false, false
	}

	entityKey := strings.TrimSpace(event.ClientIP)
	now := time.Now()

	zte.mu.Lock()
	state, exists := zte.entities[entityKey]
	if !exists {
		state = &TrustEntityState{
			EntityID:    entityKey,
			IP:          entityKey,
			TrustScore:  100,
			LastSeen:    now,
			LastASN:     event.ASN,
			LastCountry: event.CountryCode,
			PenaltyLog:  make([]string, 0, 8),
		}
		zte.entities[entityKey] = state
	}

	// 1. Off-Hours Access Penalty (-15)
	localHour := now.Hour()
	if localHour < zte.workHourStart || localHour >= zte.workHourEnd {
		state.TrustScore -= 15
		state.OffHoursViolations++
		state.PenaltyLog = append(state.PenaltyLog, fmt.Sprintf("Off-hours access at %02d:%02d (-15 pts)", localHour, now.Minute()))
	}

	// 2. Rapid Geo-Velocity / ASN Deviation Penalty (-30)
	if state.LastASN != "" && event.ASN != "" && state.LastASN != event.ASN {
		state.TrustScore -= 30
		state.GeoVelocityDrifts++
		state.PenaltyLog = append(state.PenaltyLog, fmt.Sprintf("Rapid ASN deviation (%s -> %s) (-30 pts)", state.LastASN, event.ASN))
	} else if state.LastCountry != "" && event.CountryCode != "" && event.CountryCode != "LOC" && state.LastCountry != event.CountryCode {
		state.TrustScore -= 30
		state.GeoVelocityDrifts++
		state.PenaltyLog = append(state.PenaltyLog, fmt.Sprintf("Geo-velocity drift (%s -> %s) (-30 pts)", state.LastCountry, event.CountryCode))
	}

	// 3. High-Entropy Query / Exploit Payloads Penalty (-40)
	entropy := CalculateShannonEntropy(event.RawLine)
	if entropy > 4.5 || event.MLAnomaly || strings.Contains(strings.ToLower(event.RuleID), "sqli") || strings.Contains(strings.ToLower(event.RuleID), "rce") {
		state.TrustScore -= 40
		state.EntropyViolations++
		state.PenaltyLog = append(state.PenaltyLog, fmt.Sprintf("High-entropy / exploit payload (entropy: %.2f) (-40 pts)", entropy))
	}

	// Cap trust score within [0, 100]
	if state.TrustScore < 0 {
		state.TrustScore = 0
	} else if state.TrustScore > 100 {
		state.TrustScore = 100
	}

	state.LastSeen = now
	if event.ASN != "" {
		state.LastASN = event.ASN
	}
	if event.CountryCode != "" {
		state.LastCountry = event.CountryCode
	}

	currentScore := state.TrustScore
	var triggerIsolation bool
	var triggerStepUp bool

	// Zero Trust Policy Enforcement:
	// If TrustScore < 40: trigger dynamic session isolation command or step-up auth
	if currentScore < 40 && !state.IsIsolated {
		state.IsIsolated = true
		state.StepUpAuthRequired = true
		triggerIsolation = true
		triggerStepUp = true
	} else if currentScore < 60 && !state.StepUpAuthRequired {
		state.StepUpAuthRequired = true
		triggerStepUp = true
	}

	server := zte.server
	hub := zte.wsHub
	storage := zte.storage
	zte.mu.Unlock()

	if triggerIsolation {
		log.Printf("[ZERO_TRUST] 🔒 Zero Trust Threshold Breached (<40)! Enforcing Session Isolation for %s (Score: %d)", entityKey, currentScore)
		if server != nil {
			server.BroadcastSOARCommandWithReason("ISOLATE_SESSION", entityKey, fmt.Sprintf("Zero Trust Engine: Contextual Trust Score collapsed to %d/100", currentScore), 86400)
		}
		if storage != nil {
			storage.mu.Lock()
			_, _ = storage.db.Exec(`UPDATE telemetry SET triage_status = 'AUTO_MITIGATED', containment_state = 'SESSION_ISOLATED' WHERE client_ip = ?`, entityKey)
			storage.mu.Unlock()
		}
		if hub != nil {
			hub.Broadcast("ALERT_NEW", map[string]interface{}{
				"type":              "ZERO_TRUST_ISOLATION",
				"tag":               "[ZERO TRUST ISOLATION]",
				"source_ip":         entityKey,
				"trust_score":       currentScore,
				"containment_state": "SESSION_ISOLATED",
				"reason":            fmt.Sprintf("Trust score degraded to %d", currentScore),
				"timestamp_ms":      now.UnixMilli(),
			})
		}
	}

	return currentScore, triggerIsolation, triggerStepUp
}

// GetEntityState returns trust state for an IP or identifier.
func (zte *ContextualZeroTrustEngine) GetEntityState(entityID string) (*TrustEntityState, bool) {
	zte.mu.RLock()
	defer zte.mu.RUnlock()
	state, exists := zte.entities[entityID]
	if !exists {
		return nil, false
	}
	cp := *state
	return &cp, true
}

// GetAllEntities returns all active entity trust states.
func (zte *ContextualZeroTrustEngine) GetAllEntities() []*TrustEntityState {
	zte.mu.RLock()
	defer zte.mu.RUnlock()
	list := make([]*TrustEntityState, 0, len(zte.entities))
	for _, s := range zte.entities {
		cp := *s
		list = append(list, &cp)
	}
	return list
}

// ResetTrustScore restores trust score back to baseline 100 (e.g. after analyst approval or step-up auth).
func (zte *ContextualZeroTrustEngine) ResetTrustScore(entityID string) {
	zte.mu.Lock()
	defer zte.mu.Unlock()
	if s, exists := zte.entities[entityID]; exists {
		s.TrustScore = 100
		s.IsIsolated = false
		s.StepUpAuthRequired = false
		s.PenaltyLog = append(s.PenaltyLog, fmt.Sprintf("Trust score manually reset to 100 at %s", time.Now().Format(time.RFC3339)))
	}
}
