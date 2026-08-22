package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
}

// MITREStat summarizes technique occurrences.
type MITREStat struct {
	TechniqueID string `json:"technique_id"`
	Count       int    `json:"count"`
}

// TrendPoint represents aggregated event counts per interval.
type TrendPoint struct {
	TimestampMs int64 `json:"timestamp_ms"`
	EventCount  int   `json:"event_count"`
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
		threat_score INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ms DESC);
	CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events(client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_technique_id);
	CREATE INDEX IF NOT EXISTS idx_events_node_id ON events(node_id);

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

	query := `INSERT INTO events (node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ev.NodeID, ev.Source, ev.RawLine, ev.ClientIP, ev.StatusCode, ev.TimestampMs, ev.RuleID, ev.MitreTechniqueID, ev.ThreatScore)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ev.ID = id
	return nil
}

// GetRecentEvents retrieves the latest events.
func (s *StorageEngine) GetRecentEvents(limit int) ([]*StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, node_id, source, raw_line, client_ip, status_code, timestamp_ms, rule_id, mitre_technique_id, threat_score
	          FROM events ORDER BY timestamp_ms DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*StoredEvent
	for rows.Next() {
		ev := &StoredEvent{}
		if err := rows.Scan(&ev.ID, &ev.NodeID, &ev.Source, &ev.RawLine, &ev.ClientIP, &ev.StatusCode, &ev.TimestampMs, &ev.RuleID, &ev.MitreTechniqueID, &ev.ThreatScore); err == nil {
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
	          WHERE mitre_technique_id != '' GROUP BY mitre_technique_id ORDER BY cnt DESC LIMIT 10`
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
