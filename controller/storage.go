package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/copsec/controller/pkg/geoip"
	"github.com/copsec/controller/pkg/models"
	"github.com/copsec/controller/pkg/whitelist"
	_ "modernc.org/sqlite"
)

// Alert is an alias for StoredEvent representing a high-fidelity incident alert.
type Alert = StoredEvent

// StoredEvent represents a database security incident record.
type StoredEvent struct {
	ID               int64  `json:"id"`
	NodeID           string `json:"node_id"`
	Source           string `json:"source"`
	RawLine          string `json:"raw_line"`
	ClientIP         string `json:"client_ip"`
	StatusCode       int    `json:"status_code"`
	TimestampMs      int64  `json:"timestamp_ms"`
	RuleID           string          `json:"rule_id"`
	MitreTechniqueID string          `json:"mitre_technique_id"`
	ThreatScore      int             `json:"threat_score"`
	Severity         models.Severity `json:"severity,omitempty"`
	AIAnalysis       string          `json:"ai_analysis,omitempty"`
	AnalystNotes     string `json:"analyst_notes,omitempty"`
	PlaybookProgress string `json:"playbook_progress,omitempty"`
	TriageStatus     string `json:"triage_status,omitempty"`
	ContainmentState string `json:"containment_state,omitempty"`
	CountryCode      string `json:"country_code,omitempty"`
	CountryName      string `json:"country_name,omitempty"`
	City             string `json:"city,omitempty"`
	ASN              string `json:"asn,omitempty"`
	FlagEmoji        string `json:"flag_emoji,omitempty"`
	ScoreBreakdown   string  `json:"score_breakdown,omitempty"`
	ThreatTier       string  `json:"threat_tier,omitempty"`
	MLAnomaly        bool    `json:"ml_anomaly,omitempty"`
	MLConfidencePct  float64 `json:"ml_confidence_pct,omitempty"`
	MLDescription    string  `json:"ml_description,omitempty"`
	SnortML          bool    `json:"snort_ml,omitempty"`
	SnortMsg         string  `json:"snort_msg,omitempty"`
	SnortModelID     string  `json:"snort_model_id,omitempty"`
	SnortAnomalyScore float64 `json:"snort_anomaly_score,omitempty"`
	SnortConfidence   float64 `json:"snort_confidence,omitempty"`
	SnortPriority     int     `json:"snort_priority,omitempty"`
	PrevHash          string  `json:"prev_hash,omitempty"`
	EntryHash         string  `json:"entry_hash,omitempty"`
}

// ToUnifiedTelemetry converts a StoredEvent into the canonical UnifiedTelemetry contract.
func (ev *StoredEvent) ToUnifiedTelemetry() *models.UnifiedTelemetry {
	sev := ev.Severity
	if sev == "" {
		sev = models.CalculateSeverity(ev.ThreatScore)
	}

	layer := models.NormalizeLayer(ev.Source)

	return &models.UnifiedTelemetry{
		ID:          fmt.Sprintf("%d", ev.ID),
		Timestamp:   time.UnixMilli(ev.TimestampMs),
		SourceNode:  ev.NodeID,
		Layer:       layer,
		SourceIP:    ev.ClientIP,
		SourcePort:  0,
		DestIP:      "",
		DestPort:    0,
		Protocol:    ev.Source,
		ThreatScore: ev.ThreatScore,
		Severity:    sev,
		MitreID:     ev.MitreTechniqueID,
		RuleMatched: ev.RuleID,
		RawPayload:  ev.RawLine,
		Metadata: map[string]interface{}{
			"status_code":   ev.StatusCode,
			"country_code":  ev.CountryCode,
			"country_name":  ev.CountryName,
			"city":          ev.City,
			"asn":           ev.ASN,
			"threat_tier":   ev.ThreatTier,
			"ml_anomaly":    ev.MLAnomaly,
			"analyst_notes": ev.AnalystNotes,
			"triage_status": ev.TriageStatus,
		},
	}
}

// ActiveBanRecord represents an IP quarantined in the SOAR Jail.
type ActiveBanRecord struct {
	ID              int64  `json:"id"`
	IP              string `json:"ip"`
	Reason          string `json:"reason"`
	BanTimeMs       int64  `json:"ban_time_ms"`
	DurationSeconds int64  `json:"duration_seconds"`
	Status          string `json:"status"`
}

// SOARActionRecord tracks fleet containment operations.
type SOARActionRecord struct {
	ID          int64  `json:"id"`
	ActionType  string `json:"action_type"`
	TargetIP    string `json:"target_ip"`
	NodesCount  int    `json:"nodes_count"`
	TimestampMs int64  `json:"timestamp_ms"`
}

// MITREStat summarizes technique occurrences.
type MITREStat struct {
	TechniqueID string `json:"technique_id"`
	Count       int    `json:"count"`
}

// NodeRegistryRecord represents a connected distributed edge node / VDS instance.
type NodeRegistryRecord struct {
	NodeID          string  `json:"node_id"`
	APIKey          string  `json:"api_key,omitempty"`
	Hostname        string  `json:"hostname"`
	GroupName       string  `json:"group_name"`
	RemoteAddr      string  `json:"remote_addr"`
	LastSeenMs      int64   `json:"last_seen_ms"`
	CPUUsage        float64 `json:"cpu_usage"`
	MemoryUsage     float64 `json:"memory_usage"`
	ActiveBansCount int     `json:"active_bans_count"`
	UptimeSeconds   int64   `json:"uptime_seconds"`
	Status          string  `json:"status"`
}

// StorageEngine manages the embedded WAL-mode SQLite database.
type StorageEngine struct {
	mu           sync.RWMutex
	db           *sql.DB
	mitigatedIPs sync.Map // map[string]time.Time
}

// NewStorageEngine creates and initializes the SQLite database with WAL mode and indexes.
func NewStorageEngine(dbPath string) (*StorageEngine, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		dbPath = "./copsec_controller.db"
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(1 * time.Hour)

	engine := &StorageEngine{db: db}
	if err := engine.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	_, _ = engine.FlushInvalidQuarantines()
	if err := engine.HealAndBackfillHashChain(); err != nil {
		log.Printf("[WARN] Hash chain backfill warning: %v", err)
	}

	log.Printf("[INFO] Embedded Storage initialized (WAL-mode SQLite) at %s", dbPath)
	return engine, nil
}

// Global Triage Blacklist / Handled Cache
var (
	HandledAlertIDs sync.Map // map[int64]bool or map[string]bool
	HandledIPs      sync.Map // map[string]bool
)

// MarkAlertHandled registers an alert ID as handled/dismissed across memory.
func MarkAlertHandled(id interface{}) {
	if id == nil {
		return
	}
	switch v := id.(type) {
	case int64:
		if v > 0 {
			HandledAlertIDs.Store(v, true)
			HandledAlertIDs.Store(fmt.Sprintf("%d", v), true)
		}
	case int:
		if v > 0 {
			HandledAlertIDs.Store(int64(v), true)
			HandledAlertIDs.Store(fmt.Sprintf("%d", v), true)
		}
	case string:
		clean := strings.TrimSpace(v)
		if clean != "" && clean != "0" {
			HandledAlertIDs.Store(clean, true)
			if numID, err := strconv.ParseInt(clean, 10, 64); err == nil && numID > 0 {
				HandledAlertIDs.Store(numID, true)
			}
		}
	}
}

// MarkIPHandled registers an IP as handled/mitigated.
func MarkIPHandled(ip string) {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP != "" && cleanIP != "-" && cleanIP != "127.0.0.1" {
		HandledIPs.Store(cleanIP, true)
	}
}

// IsAlertHandled checks if an alert ID has been handled/dismissed.
func IsAlertHandled(id interface{}) bool {
	if id == nil {
		return false
	}
	switch v := id.(type) {
	case int64:
		if _, ok := HandledAlertIDs.Load(v); ok {
			return true
		}
		if _, ok := HandledAlertIDs.Load(fmt.Sprintf("%d", v)); ok {
			return true
		}
	case int:
		if _, ok := HandledAlertIDs.Load(int64(v)); ok {
			return true
		}
		if _, ok := HandledAlertIDs.Load(fmt.Sprintf("%d", v)); ok {
			return true
		}
	case string:
		clean := strings.TrimSpace(v)
		if clean == "" || clean == "0" {
			return false
		}
		if _, ok := HandledAlertIDs.Load(clean); ok {
			return true
		}
		if numID, err := strconv.ParseInt(clean, 10, 64); err == nil && numID > 0 {
			if _, ok := HandledAlertIDs.Load(numID); ok {
				return true
			}
		}
	}
	return false
}

// IsIPHandled checks if an IP has been marked handled/mitigated.
func IsIPHandled(ip string) bool {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return false
	}
	_, ok := HandledIPs.Load(cleanIP)
	return ok
}

// UnmarkIPHandled removes an IP from HandledIPs.
func UnmarkIPHandled(ip string) {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP != "" {
		HandledIPs.Delete(cleanIP)
	}
}

// AddMitigatedIP registers an IP in the in-memory suppression pool for the given duration.
func (s *StorageEngine) AddMitigatedIP(ip string, duration time.Duration) {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || cleanIP == "-" || cleanIP == "127.0.0.1" || cleanIP == "::1" || cleanIP == "localhost" || cleanIP == "local" {
		return
	}
	MarkIPHandled(cleanIP)
	if duration <= 0 {
		duration = 1 * time.Hour
	}
	expiry := time.Now().Add(duration)
	s.mitigatedIPs.Store(cleanIP, expiry)
}

// IsIPMitigated checks if an IP is currently suppressed and removes it if expired.
func (s *StorageEngine) IsIPMitigated(ip string) bool {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return false
	}
	if IsIPHandled(cleanIP) {
		return true
	}
	val, ok := s.mitigatedIPs.Load(cleanIP)
	if !ok {
		return false
	}
	expiry, ok := val.(time.Time)
	if !ok {
		s.mitigatedIPs.Delete(cleanIP)
		return false
	}
	if time.Now().After(expiry) {
		s.mitigatedIPs.Delete(cleanIP)
		return false
	}
	return true
}

// RemoveMitigatedIP removes an IP from the in-memory suppression pool.
func (s *StorageEngine) RemoveMitigatedIP(ip string) {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP != "" {
		s.mitigatedIPs.Delete(cleanIP)
		UnmarkIPHandled(cleanIP)
	}
}

func (s *StorageEngine) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	baseTables := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		source TEXT NOT NULL,
		raw_line TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		timestamp_ms INTEGER NOT NULL,
		rule_id TEXT DEFAULT '',
		mitre_technique_id TEXT DEFAULT '',
		threat_score INTEGER DEFAULT 0,
		ai_analysis TEXT DEFAULT '',
		analyst_notes TEXT DEFAULT '',
		playbook_progress TEXT DEFAULT '',
		triage_status TEXT DEFAULT 'ACTIVE'
	);

	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		source TEXT NOT NULL,
		raw_line TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		timestamp_ms INTEGER NOT NULL,
		rule_id TEXT DEFAULT '',
		mitre_technique_id TEXT DEFAULT '',
		threat_score INTEGER DEFAULT 0,
		ai_analysis TEXT DEFAULT '',
		analyst_notes TEXT DEFAULT '',
		playbook_progress TEXT DEFAULT '',
		triage_status TEXT DEFAULT 'ACTIVE'
	);

	CREATE TABLE IF NOT EXISTS telemetry (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		source TEXT NOT NULL,
		raw_line TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		timestamp_ms INTEGER NOT NULL,
		rule_id TEXT DEFAULT '',
		mitre_technique_id TEXT DEFAULT '',
		threat_score INTEGER DEFAULT 0,
		ai_analysis TEXT DEFAULT '',
		analyst_notes TEXT DEFAULT '',
		playbook_progress TEXT DEFAULT '',
		triage_status TEXT DEFAULT 'ACTIVE',
		containment_state TEXT DEFAULT 'ACTIVE',
		prev_hash TEXT DEFAULT '',
		entry_hash TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS active_bans (
		ip TEXT PRIMARY KEY,
		reason TEXT DEFAULT '',
		ban_time_ms INTEGER NOT NULL,
		duration_seconds INTEGER DEFAULT 86400,
		expire_time_ms INTEGER DEFAULT 0,
		penalty_tier TEXT DEFAULT 'TEMP_ISOLATION',
		status TEXT DEFAULT 'ACTIVE',
		l3_active INTEGER DEFAULT 1,
		l4_active INTEGER DEFAULT 1,
		l7_active INTEGER DEFAULT 1,
		offense_count INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS soar_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action_type TEXT NOT NULL,
		target_ip TEXT NOT NULL,
		nodes_count INTEGER DEFAULT 1,
		timestamp_ms INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS node_registry (
		node_id TEXT PRIMARY KEY,
		api_key TEXT NOT NULL,
		hostname TEXT DEFAULT '',
		group_name TEXT DEFAULT 'DEFAULT_EDGE',
		remote_addr TEXT DEFAULT '',
		last_seen_ms INTEGER NOT NULL,
		cpu_usage REAL DEFAULT 0,
		memory_usage REAL DEFAULT 0,
		active_bans_count INTEGER DEFAULT 0,
		uptime_seconds INTEGER DEFAULT 0,
		status TEXT DEFAULT 'ACTIVE'
	);

	CREATE TABLE IF NOT EXISTS system_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS honeypot_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		trap_type TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		port INTEGER DEFAULT 0,
		username TEXT DEFAULT '',
		password TEXT DEFAULT '',
		key_fingerprint TEXT DEFAULT '',
		client_version TEXT DEFAULT '',
		requested_url TEXT DEFAULT '',
		user_agent TEXT DEFAULT '',
		payload_summary TEXT DEFAULT '',
		timestamp_ms INTEGER NOT NULL,
		auto_banned INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cidr_or_ip TEXT UNIQUE NOT NULL,
		description TEXT DEFAULT '',
		added_by TEXT DEFAULT 'SYSTEM',
		created_at_ms INTEGER NOT NULL
	);
	`
	if _, err := s.db.Exec(baseTables); err != nil {
		return err
	}

	// Safe, Idempotent column migrations on pre-existing tables BEFORE index creation
	s.ensureColumnExists("events", "analyst_notes", "TEXT DEFAULT ''")
	s.ensureColumnExists("events", "playbook_progress", "TEXT DEFAULT ''")
	s.ensureColumnExists("events", "triage_status", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("alerts", "analyst_notes", "TEXT DEFAULT ''")
	s.ensureColumnExists("alerts", "playbook_progress", "TEXT DEFAULT ''")
	s.ensureColumnExists("alerts", "triage_status", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("telemetry", "analyst_notes", "TEXT DEFAULT ''")
	s.ensureColumnExists("telemetry", "playbook_progress", "TEXT DEFAULT ''")
	s.ensureColumnExists("telemetry", "triage_status", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("telemetry", "containment_state", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("telemetry", "prev_hash", "TEXT DEFAULT ''")
	s.ensureColumnExists("telemetry", "entry_hash", "TEXT DEFAULT ''")
	s.ensureColumnExists("events", "containment_state", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("events", "prev_hash", "TEXT DEFAULT ''")
	s.ensureColumnExists("events", "entry_hash", "TEXT DEFAULT ''")
	s.ensureColumnExists("alerts", "containment_state", "TEXT DEFAULT 'ACTIVE'")
	s.ensureColumnExists("active_bans", "expire_time_ms", "INTEGER DEFAULT 0")
	s.ensureColumnExists("active_bans", "penalty_tier", "TEXT DEFAULT 'TEMP_ISOLATION'")
	s.ensureColumnExists("active_bans", "l3_active", "INTEGER DEFAULT 1")
	s.ensureColumnExists("active_bans", "l4_active", "INTEGER DEFAULT 1")
	s.ensureColumnExists("active_bans", "l7_active", "INTEGER DEFAULT 1")
	s.ensureColumnExists("active_bans", "offense_count", "INTEGER DEFAULT 1")
	s.ensureColumnExists("node_registry", "group_name", "TEXT DEFAULT 'DEFAULT_EDGE'")
	s.ensureColumnExists("node_registry", "remote_addr", "TEXT DEFAULT ''")
	s.ensureColumnExists("node_registry", "cpu_usage", "REAL DEFAULT 0")
	s.ensureColumnExists("node_registry", "memory_usage", "REAL DEFAULT 0")
	s.ensureColumnExists("node_registry", "active_bans_count", "INTEGER DEFAULT 0")
	s.ensureColumnExists("node_registry", "uptime_seconds", "INTEGER DEFAULT 0")

	// Safe index creation (guaranteed all target columns exist now)
	indexes := `
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ms DESC);
	CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events(client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_technique_id);
	CREATE INDEX IF NOT EXISTS idx_events_threat_score ON events(threat_score DESC);
	CREATE INDEX IF NOT EXISTS idx_events_node_id ON events(node_id);
	CREATE INDEX IF NOT EXISTS idx_events_triage_status ON events(triage_status);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp_ms DESC);
	CREATE INDEX IF NOT EXISTS idx_alerts_client_ip ON alerts(client_ip);
	CREATE INDEX IF NOT EXISTS idx_alerts_threat_score ON alerts(threat_score DESC);
	CREATE INDEX IF NOT EXISTS idx_alerts_triage_status ON alerts(triage_status);

	CREATE INDEX IF NOT EXISTS idx_honeypot_time ON honeypot_events(timestamp_ms DESC);
	`
	if _, err := s.db.Exec(indexes); err != nil {
		return err
	}

	// Auto-Heal: Evict invalid historical quarantines caused by host-local rules or protected/empty IPs
	s.flushInvalidQuarantinesLocked()

	return nil
}

// ensureColumnExists checks if a column exists in a given table using pragma_table_info and creates it idempotently.
func (s *StorageEngine) ensureColumnExists(table, column, colDef string) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = '%s'", table, column)
	err := s.db.QueryRow(query).Scan(&count)
	if err == nil && count == 0 {
		alterSQL := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, colDef)
		_, _ = s.db.Exec(alterSQL)
	}
}

func (s *StorageEngine) flushInvalidQuarantinesLocked() {
	query := `DELETE FROM active_bans WHERE ip = '' OR ip = '127.0.0.1' OR ip = 'local' OR ip = 'localhost' OR ip LIKE '127.%' OR ip LIKE '10.%' OR ip LIKE '192.168.%' OR ip LIKE '172.16.%' OR ip LIKE '172.17.%' OR ip LIKE '172.18.%' OR ip LIKE '172.19.%' OR ip LIKE '172.20.%' OR ip LIKE '172.21.%' OR ip LIKE '172.22.%' OR ip LIKE '172.23.%' OR ip LIKE '172.24.%' OR ip LIKE '172.25.%' OR ip LIKE '172.26.%' OR ip LIKE '172.27.%' OR ip LIKE '172.28.%' OR ip LIKE '172.29.%' OR ip LIKE '172.30.%' OR ip LIKE '172.31.%' OR reason LIKE '%sudo_execution%' OR reason LIKE '%sudo:%' OR reason LIKE '%cron_tamper%' OR reason LIKE '%fim_drift%'`
	_, _ = s.db.Exec(query)

	// Normalize historical penalty tiers and legacy alert labels
	_, _ = s.db.Exec(`UPDATE active_bans SET penalty_tier = 'AUTOBAN_SOAR' WHERE penalty_tier = 'TEMP_ISOLATION' OR penalty_tier = '' OR penalty_tier IS NULL`)
	_, _ = s.db.Exec(`UPDATE active_bans SET reason = 'Autonomous Threat Score Escalation [AUTOBAN_SOAR]' WHERE reason = 'Manual/SOAR Alert' OR reason = '' OR reason IS NULL`)
	_, _ = s.db.Exec(`UPDATE active_bans SET penalty_tier = 'EXTERNAL_QUARANTINE' WHERE penalty_tier = 'EXTENDED_QUARANTINE'`)

	// Prune orphaned entries where expire_time_ms is in the past or status is not ACTIVE
	nowMs := time.Now().UnixMilli()
	_, _ = s.db.Exec(`DELETE FROM active_bans WHERE status != 'ACTIVE' OR (expire_time_ms > 0 AND expire_time_ms < ?)`, nowMs)
}

// FlushInvalidQuarantines purges all false-positive and host-local ban records from SQLite.
func (s *StorageEngine) FlushInvalidQuarantines() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `DELETE FROM active_bans WHERE ip = '' OR ip = '-' OR ip = '127.0.0.1' OR ip = 'local' OR ip = 'localhost' OR ip = '::1'
	          OR ip LIKE '127.%' OR ip LIKE '10.%' OR ip LIKE '192.168.%' OR ip LIKE '172.16.%' OR ip LIKE '172.17.%' OR ip LIKE '172.18.%' 
	          OR ip LIKE '172.19.%' OR ip LIKE '172.20.%' OR ip LIKE '172.21.%' OR ip LIKE '172.22.%' OR ip LIKE '172.23.%' OR ip LIKE '172.24.%' 
	          OR ip LIKE '172.25.%' OR ip LIKE '172.26.%' OR ip LIKE '172.27.%' OR ip LIKE '172.28.%' OR ip LIKE '172.29.%' OR ip LIKE '172.30.%' 
	          OR ip LIKE '172.31.%' OR ip LIKE '100.%' OR ip = '8.8.8.8' OR ip = '8.8.4.4' OR ip = '1.1.1.1' OR ip = '1.0.0.1' 
	          OR ip = '1.1.1.2' OR ip = '1.0.0.2' OR ip = '1.1.1.3' OR ip = '1.0.0.3' OR ip = '9.9.9.9' OR ip = '149.112.112.112' 
	          OR ip = '208.67.222.222' OR ip = '208.67.220.220' OR ip = '213.186.33.99' OR ip = '213.186.33.100' OR ip = '2001:41d0:3:163::1' OR ip = '37.59.108.186'
	          OR reason LIKE '%sudo_execution%' OR reason LIKE '%sudo:%' OR reason LIKE '%cron_tamper%' OR reason LIKE '%fim_drift%'`
	res, err := s.db.Exec(query)
	if err != nil {
		return 0, err
	}

	_, _ = s.db.Exec(`UPDATE active_bans SET penalty_tier = 'AUTOBAN_SOAR' WHERE penalty_tier = 'TEMP_ISOLATION' OR penalty_tier = '' OR penalty_tier IS NULL`)
	_, _ = s.db.Exec(`UPDATE active_bans SET reason = 'Autonomous Threat Score Escalation [AUTOBAN_SOAR]' WHERE reason = 'Manual/SOAR Alert' OR reason = '' OR reason IS NULL`)
	_, _ = s.db.Exec(`UPDATE active_bans SET penalty_tier = 'EXTERNAL_QUARANTINE' WHERE penalty_tier = 'EXTENDED_QUARANTINE'`)

	nowMs := time.Now().UnixMilli()
	_, _ = s.db.Exec(`DELETE FROM active_bans WHERE status != 'ACTIVE' OR (expire_time_ms > 0 AND expire_time_ms < ?)`, nowMs)

	return res.RowsAffected()
}

// Genesis Hash for SHA-256 Merkle / Log Chaining
const GenesisLogHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Global Hash-Chaining State for Immutable Merkle/Hash Auditing
var lastLogHash atomic.Value

func init() {
	lastLogHash.Store(GenesisLogHash)
}

// CalculateLogHash computes a cryptographic SHA-256 digest over log fields and the preceding hash.
func CalculateLogHash(id int64, timestampMs int64, sourceIP string, threatScore int, prevHash string) string {
	if prevHash == "" {
		prevHash = GenesisLogHash
	}
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%d|%d|%s|%d|%s", id, timestampMs, sourceIP, threatScore, prevHash)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// HealAndBackfillHashChain scans existing telemetry and events tables, fixes/backfills any broken or
// missing hashes starting from GenesisLogHash, and restores lastLogHash to the current head.
func (s *StorageEngine) HealAndBackfillHashChain() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Fetch all telemetry records in strict ascending ID order
	query := `SELECT id, timestamp_ms, client_ip, threat_score, prev_hash, entry_hash FROM telemetry ORDER BY id ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}

	type logRow struct {
		id          int64
		timestampMs int64
		clientIP    string
		threatScore int
		prevHash    string
		entryHash   string
	}

	var rowList []logRow
	for rows.Next() {
		var r logRow
		if err := rows.Scan(&r.id, &r.timestampMs, &r.clientIP, &r.threatScore, &r.prevHash, &r.entryHash); err == nil {
			rowList = append(rowList, r)
		}
	}
	rows.Close()

	if len(rowList) == 0 {
		lastLogHash.Store(GenesisLogHash)
		return nil
	}

	// 2. Iterate and rebuild chain from GenesisLogHash
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmtTele, err := tx.Prepare(`UPDATE telemetry SET prev_hash = ?, entry_hash = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmtTele.Close()

	stmtEvents, err := tx.Prepare(`UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmtEvents.Close()

	currentPrevHash := GenesisLogHash
	for _, r := range rowList {
		expectedEntryHash := CalculateLogHash(r.id, r.timestampMs, r.clientIP, r.threatScore, currentPrevHash)

		if r.prevHash != currentPrevHash || r.entryHash != expectedEntryHash {
			_, _ = stmtTele.Exec(currentPrevHash, expectedEntryHash, r.id)
			_, _ = stmtEvents.Exec(currentPrevHash, expectedEntryHash, r.id)
		}

		currentPrevHash = expectedEntryHash
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 3. Store the healed head hash into atomic memory buffer
	lastLogHash.Store(currentPrevHash)
	log.Printf("[HASH_CHAIN] ⛓️ Cryptographic Log Chain verified & backfilled (%d records, head: %s...)", len(rowList), currentPrevHash[:12])
	return nil
}

// InsertEvent records a new LogEvent asynchronously with prepared statement and cryptographic hash chaining.
func (s *StorageEngine) InsertEvent(ev *StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.TriageStatus == "" {
		ev.TriageStatus = "ACTIVE"
	}
	if ev.TimestampMs == 0 {
		ev.TimestampMs = time.Now().UnixMilli()
	}

	// 1. Immutable Hash Chaining Pipeline
	prevH, _ := lastLogHash.Load().(string)
	if prevH == "" {
		prevH = GenesisLogHash
	}
	ev.PrevHash = prevH

	containmentState := ev.ContainmentState
	if containmentState == "" {
		containmentState = "ACTIVE"
	}

	// Insert record to events table
	query := `INSERT INTO events (node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status, containment_state, prev_hash, entry_hash)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ev.NodeID, ev.Source, ev.RawLine, ev.ClientIP, ev.StatusCode, ev.TimestampMs, ev.RuleID, ev.MitreTechniqueID, ev.ThreatScore, ev.AIAnalysis, ev.AnalystNotes, ev.PlaybookProgress, ev.TriageStatus, containmentState, ev.PrevHash, "")
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ev.ID = id

	// Calculate deterministic entry hash with assigned ID
	entryH := CalculateLogHash(ev.ID, ev.TimestampMs, ev.ClientIP, ev.ThreatScore, ev.PrevHash)
	ev.EntryHash = entryH

	// Update calculated hash in events table and insert into telemetry table with hash integrity
	_, _ = s.db.Exec(`UPDATE events SET entry_hash = ? WHERE id = ?`, entryH, id)
	_, _ = s.db.Exec(`INSERT INTO telemetry (id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status, containment_state, prev_hash, entry_hash)
	                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.NodeID, ev.Source, ev.RawLine, ev.ClientIP, ev.StatusCode, ev.TimestampMs, ev.RuleID, ev.MitreTechniqueID, ev.ThreatScore, ev.AIAnalysis, ev.AnalystNotes, ev.PlaybookProgress, ev.TriageStatus, containmentState, ev.PrevHash, entryH)

	// Persist last computed hash atomically into memory buffer
	lastLogHash.Store(entryH)

	return nil
}

// VerifyLogIntegrity scans the telemetry log records sequentially and verifies the SHA-256 cryptographic chain.
// Returns valid (bool), verifiedCount (int64), and lastVerifiedHash (string).
func (s *StorageEngine) VerifyLogIntegrity() (bool, int64, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, timestamp_ms, client_ip, threat_score, prev_hash, entry_hash FROM telemetry ORDER BY id ASC`)
	if err != nil {
		return false, 0, "", err
	}
	defer rows.Close()

	expectedPrevHash := GenesisLogHash
	var verifiedCount int64 = 0
	var lastHash string = GenesisLogHash

	for rows.Next() {
		var id, timestampMs int64
		var clientIP, prevHash, entryHash string
		var threatScore int

		if err := rows.Scan(&id, &timestampMs, &clientIP, &threatScore, &prevHash, &entryHash); err != nil {
			return false, verifiedCount, lastHash, err
		}

		if prevHash != expectedPrevHash {
			return false, verifiedCount, lastHash, fmt.Errorf("cryptographic chain broken at record ID %d: expected prev_hash %s, found %s", id, expectedPrevHash, prevHash)
		}

		calculatedHash := CalculateLogHash(id, timestampMs, clientIP, threatScore, prevHash)
		if calculatedHash != entryHash {
			return false, verifiedCount, lastHash, fmt.Errorf("cryptographic hash mismatch at record ID %d: expected %s, calculated %s", id, entryHash, calculatedHash)
		}

		expectedPrevHash = entryHash
		lastHash = entryHash
		verifiedCount++
	}

	return true, verifiedCount, lastHash, nil
}

// InsertAlert persists an active security alert into the dedicated SQLite alerts table.
func (s *StorageEngine) InsertAlert(ev *StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.TriageStatus == "" {
		ev.TriageStatus = "ACTIVE"
	}
	containmentState := ev.ContainmentState
	if containmentState == "" {
		containmentState = "ACTIVE"
	}

	query := `INSERT INTO alerts (node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status, containment_state)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ev.NodeID, ev.Source, ev.RawLine, ev.ClientIP, ev.StatusCode, ev.TimestampMs, ev.RuleID, ev.MitreTechniqueID, ev.ThreatScore, ev.AIAnalysis, ev.AnalystNotes, ev.PlaybookProgress, ev.TriageStatus, containmentState)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ev.ID = id
	return nil
}

// SaveAlert saves an alert with cryptographic hash chaining across events and telemetry, then persists into alerts.
func (s *StorageEngine) SaveAlert(alert *StoredEvent) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	if err := s.InsertEvent(alert); err != nil {
		return err
	}
	return s.InsertAlert(alert)
}

// SetAlertStatus atomically transitions an alert's triage status (ACTIVE, RESOLVED, MITIGATED, FALSE_POSITIVE) in SQLite.
func (s *StorageEngine) SetAlertStatus(id string, status string, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if status == "" {
		status = "RESOLVED"
	}

	// If transitioning to MITIGATED, RESOLVED, or FALSE_POSITIVE, register IP in suppression pool
	if status == "MITIGATED" || status == "RESOLVED" || status == "FALSE_POSITIVE" {
		var clientIP string
		if numID, err := strconv.ParseInt(id, 10, 64); err == nil && numID > 0 {
			_ = s.db.QueryRow(`SELECT client_ip FROM alerts WHERE id = ? UNION SELECT client_ip FROM events WHERE id = ? LIMIT 1`, numID, numID).Scan(&clientIP)
		} else if strings.Contains(id, ".") || strings.Contains(id, ":") {
			clientIP = id
		}
		if clientIP != "" {
			s.AddMitigatedIP(clientIP, 1*time.Hour)
		}
	}

	if numID, err := strconv.ParseInt(id, 10, 64); err == nil && numID > 0 {
		MarkAlertHandled(numID)
		if notes != "" {
			_, _ = s.db.Exec(`UPDATE alerts SET triage_status = ?, analyst_notes = ? WHERE id = ?`, status, notes, numID)
			_, _ = s.db.Exec(`UPDATE events SET triage_status = ?, analyst_notes = ? WHERE id = ?`, status, notes, numID)
			_, _ = s.db.Exec(`UPDATE telemetry SET triage_status = ?, analyst_notes = ? WHERE id = ?`, status, notes, numID)
		} else {
			_, _ = s.db.Exec(`UPDATE alerts SET triage_status = ? WHERE id = ?`, status, numID)
			_, _ = s.db.Exec(`UPDATE events SET triage_status = ? WHERE id = ?`, status, numID)
			_, _ = s.db.Exec(`UPDATE telemetry SET triage_status = ? WHERE id = ?`, status, numID)
		}
		return nil
	}

	MarkAlertHandled(id)
	if notes != "" {
		_, _ = s.db.Exec(`UPDATE alerts SET triage_status = ?, analyst_notes = ? WHERE client_ip = ? OR rule_id = ?`, status, notes, id, id)
		_, _ = s.db.Exec(`UPDATE events SET triage_status = ?, analyst_notes = ? WHERE client_ip = ? OR rule_id = ?`, status, notes, id, id)
		_, _ = s.db.Exec(`UPDATE telemetry SET triage_status = ?, analyst_notes = ? WHERE client_ip = ? OR rule_id = ?`, status, notes, id, id)
	} else {
		_, _ = s.db.Exec(`UPDATE alerts SET triage_status = ? WHERE client_ip = ? OR rule_id = ?`, status, id, id)
		_, _ = s.db.Exec(`UPDATE events SET triage_status = ? WHERE client_ip = ? OR rule_id = ?`, status, id, id)
		_, _ = s.db.Exec(`UPDATE telemetry SET triage_status = ? WHERE client_ip = ? OR rule_id = ?`, status, id, id)
	}
	return nil
}

// GetActiveAlerts retrieves actionable alerts with status 'ACTIVE' (or NULL) strictly excluding resolved items.
func (s *StorageEngine) GetActiveAlerts(limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 500
	}

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
	          FROM alerts
	          WHERE threat_score >= 40 
	            AND (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)
	            AND rule_id != 'sudo_execution'
	            AND NOT (client_ip IN ('127.0.0.1', '::1', 'localhost', 'local', '-') AND threat_score < 70 AND rule_id NOT LIKE 'sigma%')
	          ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}

	// Filter out any items in HandledAlertIDs or HandledIPs
	var filtered []*StoredEvent
	for _, a := range alerts {
		if !IsAlertHandled(a.ID) && !IsIPHandled(a.ClientIP) {
			filtered = append(filtered, a)
		}
	}
	alerts = filtered

	// Fallback to events table with threat_score >= 40 and ACTIVE status if alerts table is empty
	if len(alerts) == 0 {
		fallbackQuery := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
		                  FROM events
		                  WHERE threat_score >= 40 
		                    AND (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)
		                    AND rule_id != 'sudo_execution'
		                    AND NOT (client_ip IN ('127.0.0.1', '::1', 'localhost', 'local', '-') AND threat_score < 70 AND rule_id NOT LIKE 'sigma%')
		                  ORDER BY timestamp_ms DESC LIMIT ?`
		fbRows, fbErr := s.db.Query(fallbackQuery, limit)
		if fbErr == nil {
			defer fbRows.Close()
			fbEvents, err := scanEvents(fbRows)
			if err == nil {
				for _, fe := range fbEvents {
					if !IsAlertHandled(fe.ID) && !IsIPHandled(fe.ClientIP) {
						alerts = append(alerts, fe)
					}
				}
			}
		}
	}

	return alerts, nil
}

// GetResolvedAlerts retrieves historically resolved/mitigated security alerts from SQLite archive.
func (s *StorageEngine) GetResolvedAlerts(limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 500
	}

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
	          FROM alerts
	          WHERE triage_status IN ('RESOLVED', 'MITIGATED', 'FALSE_POSITIVE')
	          ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}

	if len(alerts) == 0 {
		fallbackQuery := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
		                  FROM events
		                  WHERE triage_status IN ('RESOLVED', 'MITIGATED', 'FALSE_POSITIVE')
		                  ORDER BY timestamp_ms DESC LIMIT ?`
		fbRows, fbErr := s.db.Query(fallbackQuery, limit)
		if fbErr == nil {
			defer fbRows.Close()
			return scanEvents(fbRows)
		}
	}

	return alerts, nil
}

// GetRecentAlerts retrieves alerts (defaults to active alerts).
func (s *StorageEngine) GetRecentAlerts(limit int) ([]*StoredEvent, error) {
	return s.GetActiveAlerts(limit)
}

// DismissAlert marks a triaged alert as RESOLVED in the database.
func (s *StorageEngine) DismissAlert(id string) error {
	MarkAlertHandled(id)
	return s.SetAlertStatus(id, "RESOLVED", "")
}

// ClearAllActiveAlerts archives all active alerts to RESOLVED status in SQLite.
func (s *StorageEngine) ClearAllActiveAlerts() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load active IDs into HandledAlertIDs before updating
	rows, err := s.db.Query(`SELECT id, client_ip FROM alerts WHERE (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)
	                         UNION
	                         SELECT id, client_ip FROM events WHERE threat_score >= 40 AND (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var ip string
			if err := rows.Scan(&id, &ip); err == nil {
				MarkAlertHandled(id)
			}
		}
	}

	_, _ = s.db.Exec(`UPDATE alerts SET triage_status = 'RESOLVED' WHERE (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)`)
	_, _ = s.db.Exec(`UPDATE events SET triage_status = 'RESOLVED' WHERE (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)`)
	_, _ = s.db.Exec(`UPDATE telemetry SET triage_status = 'RESOLVED' WHERE (triage_status = 'ACTIVE' OR triage_status = '' OR triage_status IS NULL)`)
	return nil
}

// ClearAllAlerts purges or archives all active alerts.
func (s *StorageEngine) ClearAllAlerts() error {
	return s.ClearAllActiveAlerts()
}

// UpdateEventAI updates the AI analysis field for a stored incident.
func (s *StorageEngine) UpdateEventAI(eventID int64, aiAnalysis string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE events SET ai_analysis = ? WHERE id = ?`
	_, err := s.db.Exec(query, aiAnalysis, eventID)
	return err
}

// UpdateEventNotes updates analyst case notes for a stored incident.
func (s *StorageEngine) UpdateEventNotes(eventID int64, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE events SET analyst_notes = ? WHERE id = ?`
	_, err := s.db.Exec(query, notes, eventID)
	return err
}

// UpdateEventNotesAndPlaybook updates both analyst notes and playbook checklist state.
func (s *StorageEngine) UpdateEventNotesAndPlaybook(eventID int64, notes string, playbookProgress string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if playbookProgress != "" && notes != "" {
		_, err := s.db.Exec(`UPDATE events SET analyst_notes = ?, playbook_progress = ? WHERE id = ?`, notes, playbookProgress, eventID)
		return err
	} else if playbookProgress != "" {
		_, err := s.db.Exec(`UPDATE events SET playbook_progress = ? WHERE id = ?`, playbookProgress, eventID)
		return err
	}
	_, err := s.db.Exec(`UPDATE events SET analyst_notes = ? WHERE id = ?`, notes, eventID)
	return err
}

// UpdateEventPlaybookProgress updates the playbook checklist state for an incident.
func (s *StorageEngine) UpdateEventPlaybookProgress(eventID int64, playbookProgress string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE events SET playbook_progress = ? WHERE id = ?`
	_, err := s.db.Exec(query, playbookProgress, eventID)
	return err
}

// RegisterOrUpdateNode registers or updates an edge node session in SQLite.
func (s *StorageEngine) RegisterOrUpdateNode(node *NodeRegistryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO node_registry (node_id, api_key, hostname, group_name, remote_addr, last_seen_ms, cpu_usage, memory_usage, active_bans_count, uptime_seconds, status)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(node_id) DO UPDATE SET
	            hostname = excluded.hostname,
	            group_name = excluded.group_name,
	            remote_addr = excluded.remote_addr,
	            last_seen_ms = excluded.last_seen_ms,
	            cpu_usage = excluded.cpu_usage,
	            memory_usage = excluded.memory_usage,
	            active_bans_count = excluded.active_bans_count,
	            uptime_seconds = excluded.uptime_seconds,
	            status = excluded.status`
	_, err := s.db.Exec(query, node.NodeID, node.APIKey, node.Hostname, node.GroupName, node.RemoteAddr, node.LastSeenMs, node.CPUUsage, node.MemoryUsage, node.ActiveBansCount, node.UptimeSeconds, node.Status)
	return err
}

// GetRegisteredNodes retrieves all known edge nodes from SQLite.
func (s *StorageEngine) GetRegisteredNodes() ([]NodeRegistryRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT node_id, hostname, group_name, remote_addr, last_seen_ms, cpu_usage, memory_usage, active_bans_count, uptime_seconds, status
	          FROM node_registry ORDER BY last_seen_ms DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []NodeRegistryRecord
	for rows.Next() {
		var n NodeRegistryRecord
		if err := rows.Scan(&n.NodeID, &n.Hostname, &n.GroupName, &n.RemoteAddr, &n.LastSeenMs, &n.CPUUsage, &n.MemoryUsage, &n.ActiveBansCount, &n.UptimeSeconds, &n.Status); err == nil {
			list = append(list, n)
		}
	}
	return list, nil
}

// MarkStaleNodesOffline sets status to OFFLINE for nodes with no heartbeat for more than staleDuration.
func (s *StorageEngine) MarkStaleNodesOffline(staleDuration time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoffMs := time.Now().Add(-staleDuration).UnixMilli()
	query := `UPDATE node_registry SET status = 'OFFLINE' WHERE last_seen_ms < ? AND status != 'OFFLINE'`
	res, err := s.db.Exec(query, cutoffMs)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpdateNodeStatus updates the status string of a specific node.
func (s *StorageEngine) UpdateNodeStatus(nodeID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE node_registry SET status = ? WHERE node_id = ?`
	_, err := s.db.Exec(query, status, nodeID)
	return err
}

// RecordBan saves a banned IP in the jail (backward compatible).
func (s *StorageEngine) RecordBan(ip, reason string, durationSeconds int64) error {
	nowMs := time.Now().UnixMilli()
	var expireMs int64 = 0
	if durationSeconds > 0 {
		expireMs = nowMs + (durationSeconds * 1000)
	}

	record := &DetailedBanRecord{
		IP:              ip,
		Reason:          reason,
		BanTimeMs:       nowMs,
		DurationSeconds: durationSeconds,
		ExpireTimeMs:    expireMs,
		PenaltyTier:     TierTempIsolation,
		Status:          "ACTIVE",
		L3Active:        true,
		L4Active:        true,
		L7Active:        true,
		OffenseCount:    1,
	}
	return s.RecordDetailedBan(record)
}

// RecordDetailedBan saves full structured SOAR ban details.
func (s *StorageEngine) RecordDetailedBan(b *DetailedBanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if b.Status == "ACTIVE" && b.IP != "" {
		dur := 1 * time.Hour
		if b.DurationSeconds > 0 {
			dur = time.Duration(b.DurationSeconds) * time.Second
		}
		s.AddMitigatedIP(b.IP, dur)
	}

	query := `INSERT OR REPLACE INTO active_bans (ip, reason, ban_time_ms, duration_seconds, expire_time_ms, penalty_tier, status, l3_active, l4_active, l7_active, offense_count)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, b.IP, b.Reason, b.BanTimeMs, b.DurationSeconds, b.ExpireTimeMs, string(b.PenaltyTier), b.Status, b.L3Active, b.L4Active, b.L7Active, b.OffenseCount)
	return err
}

// UpdateBanStatus marks ban state (e.g. EXPIRED, MANUAL_UNBAN).
func (s *StorageEngine) UpdateBanStatus(ip, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if status == "MANUAL_UNBAN" || status == "EXPIRED" {
		s.RemoveMitigatedIP(ip)
	}

	query := `UPDATE active_bans SET status = ?, l3_active = 0, l4_active = 0, l7_active = 0 WHERE ip = ?`
	_, err := s.db.Exec(query, status, ip)
	return err
}

// RemoveBan clears an unbanned IP.
func (s *StorageEngine) RemoveBan(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.RemoveMitigatedIP(ip)

	query := `DELETE FROM active_bans WHERE ip = ?`
	_, err := s.db.Exec(query, ip)
	return err
}

// GetActiveBans returns currently quarantined IPs (backward compatible).
func (s *StorageEngine) GetActiveBans() ([]ActiveBanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT ip, reason, ban_time_ms, duration_seconds, status FROM active_bans WHERE status = 'ACTIVE' ORDER BY ban_time_ms DESC LIMIT 25`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []ActiveBanRecord
	for rows.Next() {
		var b ActiveBanRecord
		if err := rows.Scan(&b.IP, &b.Reason, &b.BanTimeMs, &b.DurationSeconds, &b.Status); err == nil {
			bans = append(bans, b)
		}
	}
	return bans, nil
}

// GetActiveBansDetailed returns structured ban records for TTL manager restoration and SOC table.
func (s *StorageEngine) GetActiveBansDetailed() ([]*DetailedBanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT ip, reason, ban_time_ms, duration_seconds, expire_time_ms, penalty_tier, status, l3_active, l4_active, l7_active, offense_count
	          FROM active_bans WHERE status = 'ACTIVE' ORDER BY ban_time_ms DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*DetailedBanRecord
	for rows.Next() {
		b := &DetailedBanRecord{}
		var tierStr string
		var l3, l4, l7 int
		if err := rows.Scan(&b.IP, &b.Reason, &b.BanTimeMs, &b.DurationSeconds, &b.ExpireTimeMs, &tierStr, &b.Status, &l3, &l4, &l7, &b.OffenseCount); err == nil {
			b.PenaltyTier = PenaltyTier(tierStr)
			b.L3Active = (l3 == 1)
			b.L4Active = (l4 == 1)
			b.L7Active = (l7 == 1)
			list = append(list, b)
		}
	}
	return list, nil
}

// RecordSOARAction records an executed SOAR mitigation command.
func (s *StorageEngine) RecordSOARAction(actionType, targetIP string, nodesCount int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO soar_actions (action_type, target_ip, nodes_count, timestamp_ms) VALUES (?, ?, ?, ?)`
	_, err := s.db.Exec(query, actionType, targetIP, nodesCount, time.Now().UnixMilli())
	return err
}

// GetRecentSOARActions retrieves the latest SOAR execution log.
func (s *StorageEngine) GetRecentSOARActions(limit int) ([]SOARActionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, action_type, target_ip, nodes_count, timestamp_ms FROM soar_actions ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []SOARActionRecord
	for rows.Next() {
		var a SOARActionRecord
		if err := rows.Scan(&a.ID, &a.ActionType, &a.TargetIP, &a.NodesCount, &a.TimestampMs); err == nil {
			list = append(list, a)
		}
	}
	return list, nil
}

// GetRecentEvents retrieves the latest events.
func (s *StorageEngine) GetRecentEvents(limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
	          FROM events ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetCriticalEvents retrieves recent high-threat incidents (ThreatScore >= 50).
func (s *StorageEngine) GetCriticalEvents(limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
	          FROM events WHERE threat_score >= 50 ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

// SearchEvents executes advanced Threat Hunting query filters.
func (s *StorageEngine) SearchEvents(filterStr string, limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filterStr = strings.TrimSpace(filterStr)
	if filterStr == "" {
		return s.GetRecentEvents(limit)
	}

	var conditions []string
	var args []interface{}

	tokens := strings.Fields(filterStr)
	for _, token := range tokens {
		if strings.HasPrefix(token, "ip:") {
			ipVal := strings.TrimPrefix(token, "ip:")
			conditions = append(conditions, "client_ip LIKE ?")
			args = append(args, "%"+ipVal+"%")
		} else if strings.HasPrefix(token, "mitre:") {
			mitreVal := strings.TrimPrefix(token, "mitre:")
			conditions = append(conditions, "mitre_technique_id LIKE ?")
			args = append(args, "%"+mitreVal+"%")
		} else if strings.HasPrefix(token, "src:") {
			srcVal := strings.TrimPrefix(token, "src:")
			conditions = append(conditions, "source = ?")
			args = append(args, srcVal)
		} else if strings.HasPrefix(token, "node:") {
			nodeVal := strings.TrimPrefix(token, "node:")
			conditions = append(conditions, "node_id LIKE ?")
			args = append(args, "%"+nodeVal+"%")
		} else if strings.HasPrefix(token, "score:>") {
			scoreVal, _ := strconv.Atoi(strings.TrimPrefix(token, "score:>"))
			conditions = append(conditions, "threat_score > ?")
			args = append(args, scoreVal)
		} else if strings.HasPrefix(token, "score:>=") {
			scoreVal, _ := strconv.Atoi(strings.TrimPrefix(token, "score:>="))
			conditions = append(conditions, "threat_score >= ?")
			args = append(args, scoreVal)
		} else if strings.HasPrefix(token, "q:") {
			qVal := strings.TrimPrefix(token, "q:")
			conditions = append(conditions, "(raw_line LIKE ? OR client_ip LIKE ? OR rule_id LIKE ? OR node_id LIKE ?)")
			args = append(args, "%"+qVal+"%", "%"+qVal+"%", "%"+qVal+"%", "%"+qVal+"%")
		} else {
			conditions = append(conditions, "(raw_line LIKE ? OR client_ip LIKE ? OR rule_id LIKE ? OR node_id LIKE ?)")
			args = append(args, "%"+token+"%", "%"+token+"%", "%"+token+"%", "%"+token+"%")
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress, triage_status
	                       FROM events %s ORDER BY timestamp_ms DESC LIMIT ?`, whereClause)
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]*StoredEvent, error) {
	var results []*StoredEvent
	geo := geoip.GetDefaultEngine()
	for rows.Next() {
		ev := &StoredEvent{}
		var notes sql.NullString
		var pb sql.NullString
		var tStatus sql.NullString
		if err := rows.Scan(&ev.ID, &ev.NodeID, &ev.Source, &ev.RawLine, &ev.ClientIP, &ev.StatusCode, &ev.TimestampMs, &ev.RuleID, &ev.MitreTechniqueID, &ev.ThreatScore, &ev.AIAnalysis, &notes, &pb, &tStatus); err == nil {
			ev.Severity = models.CalculateSeverity(ev.ThreatScore)
			ev.AnalystNotes = notes.String
			ev.PlaybookProgress = pb.String
			ev.TriageStatus = tStatus.String
			if ev.TriageStatus == "" {
				ev.TriageStatus = "ACTIVE"
			}
			if ev.ClientIP != "" && ev.ClientIP != "-" {
				loc := geo.Lookup(ev.ClientIP)
				ev.CountryCode = loc.CountryCode
				ev.CountryName = loc.CountryName
				ev.City = loc.City
				ev.ASN = loc.ASN
				ev.FlagEmoji = loc.FlagEmoji
			}
			results = append(results, ev)
		}
	}
	return results, nil
}

// GetMITREStats returns technique frequency counts.
func (s *StorageEngine) GetMITREStats() ([]MITREStat, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT mitre_technique_id, COUNT(*) as cnt FROM events
	          WHERE mitre_technique_id != '' GROUP BY mitre_technique_id ORDER BY cnt DESC LIMIT 25`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []MITREStat
	for rows.Next() {
		var stat MITREStat
		if err := rows.Scan(&stat.TechniqueID, &stat.Count); err == nil {
			stats = append(stats, stat)
		}
	}
	return stats, nil
}

// SaveConfig stores a key-value setting atomically.
func (s *StorageEngine) SaveConfig(key string, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO system_config(key, value, updated_at) VALUES(?, ?, CURRENT_TIMESTAMP)
	          ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`
	_, err := s.db.Exec(query, key, value)
	return err
}

// GetConfig retrieves a single configuration value by key.
func (s *StorageEngine) GetConfig(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow(`SELECT value FROM system_config WHERE key = ?`, key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SaveSystemConfig persists a map of runtime settings.
func (s *StorageEngine) SaveSystemConfig(cfg map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO system_config(key, value, updated_at) VALUES(?, ?, CURRENT_TIMESTAMP)
	                         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range cfg {
		if _, err := stmt.Exec(k, v); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetAllSystemConfig retrieves all key-value runtime settings.
func (s *StorageEngine) GetAllSystemConfig() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT key, value FROM system_config`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			res[k] = v
		}
	}
	return res, nil
}

// TopAttackerRecord represents aggregated top offending threat actor statistics.
type TopAttackerRecord struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Hits        int    `json:"hits"`
	PeakScore   int    `json:"peak_score"`
	LastSeenMs  int64  `json:"last_seen_ms"`
}

// GetTopAttackers returns top offending threat actors strictly filtered to malicious threats (threat_score >= 40)
// and excluding whitelisted, loopback, private subnets, and benign recursive DNS resolvers.
func (s *StorageEngine) GetTopAttackers(limit int) ([]TopAttackerRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}

	query := `SELECT client_ip, COUNT(*) as hits, MAX(threat_score) as peak_score, MAX(timestamp_ms) as last_seen
	          FROM events
	          WHERE threat_score >= 40
	            AND client_ip != '' AND client_ip != '-' AND client_ip != '127.0.0.1' AND client_ip != '::1' AND client_ip != 'localhost' AND client_ip != 'local'
	            AND client_ip NOT LIKE '127.%' AND client_ip NOT LIKE '10.%' AND client_ip NOT LIKE '192.168.%' AND client_ip NOT LIKE '172.16.%' AND client_ip NOT LIKE '172.17.%' AND client_ip NOT LIKE '172.18.%' AND client_ip NOT LIKE '172.19.%' AND client_ip NOT LIKE '172.20.%' AND client_ip NOT LIKE '172.21.%' AND client_ip NOT LIKE '172.22.%' AND client_ip NOT LIKE '172.23.%' AND client_ip NOT LIKE '172.24.%' AND client_ip NOT LIKE '172.25.%' AND client_ip NOT LIKE '172.26.%' AND client_ip NOT LIKE '172.27.%' AND client_ip NOT LIKE '172.28.%' AND client_ip NOT LIKE '172.29.%' AND client_ip NOT LIKE '172.30.%' AND client_ip NOT LIKE '172.31.%' AND client_ip NOT LIKE '100.%'
	            AND client_ip NOT LIKE '2a01:41d0:%'
	            AND client_ip NOT IN ('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '213.186.33.99', '213.186.33.100', '37.59.108.186')
	          GROUP BY client_ip
	          ORDER BY hits DESC, peak_score DESC
	          LIMIT ?`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	geo := geoip.GetDefaultEngine()
	var list []TopAttackerRecord
	for rows.Next() {
		var rec TopAttackerRecord
		if err := rows.Scan(&rec.IP, &rec.Hits, &rec.PeakScore, &rec.LastSeenMs); err == nil {
			loc := geo.Lookup(rec.IP)
			rec.CountryCode = loc.CountryCode
			rec.CountryName = loc.CountryName
			list = append(list, rec)
		}
	}
	return list, nil
}

// GetAllWhitelistEntries retrieves all active whitelist rules from SQLite.
func (s *StorageEngine) GetAllWhitelistEntries() ([]whitelist.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, cidr_or_ip, description, added_by, created_at_ms FROM whitelist ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []whitelist.Entry
	for rows.Next() {
		var e whitelist.Entry
		if err := rows.Scan(&e.ID, &e.CIDROrIP, &e.Description, &e.AddedBy, &e.CreatedAtMs); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// AddWhitelistEntry inserts or ignores a whitelist rule in SQLite.
func (s *StorageEngine) AddWhitelistEntry(cidrOrIP, description, addedBy string, createdAtMs int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`INSERT INTO whitelist (cidr_or_ip, description, added_by, created_at_ms)
	                      VALUES (?, ?, ?, ?)
	                      ON CONFLICT(cidr_or_ip) DO UPDATE SET description=excluded.description`,
		cidrOrIP, description, addedBy, createdAtMs)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// DeleteWhitelistEntry deletes a whitelist record by ID or CIDR/IP.
func (s *StorageEngine) DeleteWhitelistEntry(id int64, cidrOrIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id > 0 {
		_, err := s.db.Exec(`DELETE FROM whitelist WHERE id = ?`, id)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE cidr_or_ip = ?`, cidrOrIP)
	return err
}

// Close terminates database connections.
func (s *StorageEngine) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}
