package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/copsec/controller/pkg/geoip"
	_ "modernc.org/sqlite"
)

// StoredEvent represents a database security incident record.
type StoredEvent struct {
	ID               int64  `json:"id"`
	NodeID           string `json:"node_id"`
	Source           string `json:"source"`
	RawLine          string `json:"raw_line"`
	ClientIP         string `json:"client_ip"`
	StatusCode       int    `json:"status_code"`
	TimestampMs      int64  `json:"timestamp_ms"`
	RuleID           string `json:"rule_id"`
	MitreTechniqueID string `json:"mitre_technique_id"`
	ThreatScore      int    `json:"threat_score"`
	AIAnalysis       string `json:"ai_analysis,omitempty"`
	AnalystNotes     string `json:"analyst_notes,omitempty"`
	PlaybookProgress string `json:"playbook_progress,omitempty"`
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
	SnortConfidence  float64 `json:"snort_confidence,omitempty"`
	SnortPriority    int     `json:"snort_priority,omitempty"`
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
	mu sync.RWMutex
	db *sql.DB
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

	log.Printf("[INFO] Embedded Storage initialized (WAL-mode SQLite) at %s", dbPath)
	return engine, nil
}

func (s *StorageEngine) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schema := `
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
		ai_analysis TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ms DESC);
	CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events(client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_technique_id);
	CREATE INDEX IF NOT EXISTS idx_events_threat_score ON events(threat_score DESC);
	CREATE INDEX IF NOT EXISTS idx_events_node_id ON events(node_id);

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
		updated_at_ms INTEGER NOT NULL
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

	CREATE INDEX IF NOT EXISTS idx_honeypot_time ON honeypot_events(timestamp_ms DESC);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Safe column migration check for active_bans & node_registry if tables existed previously
	cols := []string{
		"ALTER TABLE active_bans ADD COLUMN expire_time_ms INTEGER DEFAULT 0",
		"ALTER TABLE active_bans ADD COLUMN penalty_tier TEXT DEFAULT 'TEMP_ISOLATION'",
		"ALTER TABLE active_bans ADD COLUMN l3_active INTEGER DEFAULT 1",
		"ALTER TABLE active_bans ADD COLUMN l4_active INTEGER DEFAULT 1",
		"ALTER TABLE active_bans ADD COLUMN l7_active INTEGER DEFAULT 1",
		"ALTER TABLE active_bans ADD COLUMN offense_count INTEGER DEFAULT 1",
		"ALTER TABLE node_registry ADD COLUMN group_name TEXT DEFAULT 'DEFAULT_EDGE'",
		"ALTER TABLE node_registry ADD COLUMN remote_addr TEXT DEFAULT ''",
		"ALTER TABLE node_registry ADD COLUMN cpu_usage REAL DEFAULT 0",
		"ALTER TABLE node_registry ADD COLUMN memory_usage REAL DEFAULT 0",
		"ALTER TABLE node_registry ADD COLUMN active_bans_count INTEGER DEFAULT 0",
		"ALTER TABLE node_registry ADD COLUMN uptime_seconds INTEGER DEFAULT 0",
		"ALTER TABLE events ADD COLUMN analyst_notes TEXT DEFAULT ''",
		"ALTER TABLE events ADD COLUMN playbook_progress TEXT DEFAULT ''",
	}
	for _, colSQL := range cols {
		_, _ = s.db.Exec(colSQL)
	}

	// Auto-Heal: Evict invalid historical quarantines caused by host-local rules or protected/empty IPs
	s.flushInvalidQuarantinesLocked()

	return nil
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
	          OR ip = '208.67.222.222' OR ip = '208.67.220.220' OR ip = '37.59.108.186'
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

// InsertEvent records a new LogEvent asynchronously with prepared statement.
func (s *StorageEngine) InsertEvent(ev *StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO events (node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ev.NodeID, ev.Source, ev.RawLine, ev.ClientIP, ev.StatusCode, ev.TimestampMs, ev.RuleID, ev.MitreTechniqueID, ev.ThreatScore, ev.AIAnalysis)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ev.ID = id
	return nil
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

	query := `INSERT OR REPLACE INTO active_bans (ip, reason, ban_time_ms, duration_seconds, expire_time_ms, penalty_tier, status, l3_active, l4_active, l7_active, offense_count)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, b.IP, b.Reason, b.BanTimeMs, b.DurationSeconds, b.ExpireTimeMs, string(b.PenaltyTier), b.Status, b.L3Active, b.L4Active, b.L7Active, b.OffenseCount)
	return err
}

// UpdateBanStatus marks ban state (e.g. EXPIRED, MANUAL_UNBAN).
func (s *StorageEngine) UpdateBanStatus(ip, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE active_bans SET status = ?, l3_active = 0, l4_active = 0, l7_active = 0 WHERE ip = ?`
	_, err := s.db.Exec(query, status, ip)
	return err
}

// RemoveBan clears an unbanned IP.
func (s *StorageEngine) RemoveBan(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress
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

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress
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

	query := fmt.Sprintf(`SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis, analyst_notes, playbook_progress
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
		if err := rows.Scan(&ev.ID, &ev.NodeID, &ev.Source, &ev.RawLine, &ev.ClientIP, &ev.StatusCode, &ev.TimestampMs, &ev.RuleID, &ev.MitreTechniqueID, &ev.ThreatScore, &ev.AIAnalysis, &notes, &pb); err == nil {
			ev.AnalystNotes = notes.String
			ev.PlaybookProgress = pb.String
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

// SaveSystemConfig persists a map of runtime settings.
func (s *StorageEngine) SaveSystemConfig(cfg map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowMs := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO system_config (key, value, updated_at_ms) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range cfg {
		if _, err := stmt.Exec(k, v, nowMs); err != nil {
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

// RecordHoneypotEvent saves intercepted fake SSH or Honey-URL intrusions.
func (s *StorageEngine) RecordHoneypotEvent(ev *HoneypotEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO honeypot_events (trap_type, client_ip, port, username, password, key_fingerprint, client_version, requested_url, user_agent, payload_summary, timestamp_ms, auto_banned)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ev.TrapType, ev.ClientIP, ev.Port, ev.Username, ev.Password, ev.KeyFingerprint, ev.ClientVersion, ev.RequestedURL, ev.UserAgent, ev.PayloadSummary, ev.TimestampMs, ev.AutoBanned)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ev.ID = id
	return nil
}

// GetHoneypotLogs retrieves latest deception trap hits.
func (s *StorageEngine) GetHoneypotLogs(limit int) ([]*HoneypotEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, trap_type, client_ip, port, username, password, key_fingerprint, client_version, requested_url, user_agent, payload_summary, timestamp_ms, auto_banned
	          FROM honeypot_events ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*HoneypotEvent
	geo := geoip.GetDefaultEngine()
	for rows.Next() {
		ev := &HoneypotEvent{}
		var autoBannedInt int
		if err := rows.Scan(&ev.ID, &ev.TrapType, &ev.ClientIP, &ev.Port, &ev.Username, &ev.Password, &ev.KeyFingerprint, &ev.ClientVersion, &ev.RequestedURL, &ev.UserAgent, &ev.PayloadSummary, &ev.TimestampMs, &autoBannedInt); err == nil {
			ev.AutoBanned = (autoBannedInt == 1)
			if ev.ClientIP != "" && ev.ClientIP != "-" {
				loc := geo.Lookup(ev.ClientIP)
				ev.CountryCode = loc.CountryCode
				ev.CountryName = loc.CountryName
				ev.City = loc.City
				ev.ASN = loc.ASN
				ev.FlagEmoji = loc.FlagEmoji
			}
			list = append(list, ev)
		}
	}
	return list, nil
}

// Close terminates database connections.
func (s *StorageEngine) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}
