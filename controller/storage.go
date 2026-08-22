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
		status TEXT DEFAULT 'ACTIVE'
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
		last_seen_ms INTEGER NOT NULL,
		status TEXT DEFAULT 'ACTIVE'
	);
	`
	_, err := s.db.Exec(schema)
	return err
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

// RecordBan saves a banned IP in the jail.
func (s *StorageEngine) RecordBan(ip, reason string, durationSeconds int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT OR REPLACE INTO active_bans (ip, reason, ban_time_ms, duration_seconds, status)
	          VALUES (?, ?, ?, ?, 'ACTIVE')`
	_, err := s.db.Exec(query, ip, reason, time.Now().UnixMilli(), durationSeconds)
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

// GetActiveBans returns currently quarantined IPs.
func (s *StorageEngine) GetActiveBans() ([]ActiveBanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT ip, reason, ban_time_ms, duration_seconds, status FROM active_bans ORDER BY ban_time_ms DESC LIMIT 15`
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

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis
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

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis
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
			conditions = append(conditions, "(raw_line LIKE ? OR client_ip LIKE ? OR rule_id LIKE ?)")
			args = append(args, "%"+qVal+"%", "%"+qVal+"%", "%"+qVal+"%")
		} else {
			// Free text search across raw_line, IP, rule
			conditions = append(conditions, "(raw_line LIKE ? OR client_ip LIKE ? OR rule_id LIKE ?)")
			args = append(args, "%"+token+"%", "%"+token+"%", "%"+token+"%")
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score, ai_analysis
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
	for rows.Next() {
		ev := &StoredEvent{}
		if err := rows.Scan(&ev.ID, &ev.NodeID, &ev.Source, &ev.RawLine, &ev.ClientIP, &ev.StatusCode, &ev.TimestampMs, &ev.RuleID, &ev.MitreTechniqueID, &ev.ThreatScore, &ev.AIAnalysis); err == nil {
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

// Close terminates database connections.
func (s *StorageEngine) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}
