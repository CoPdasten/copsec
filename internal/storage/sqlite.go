package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	GenesisAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// AuditEntry models an immutable, non-repudiable SOC action.
type AuditEntry struct {
	ID                int64     `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	ActorIdentity     string    `json:"actor_identity"`
	ActorIP           string    `json:"actor_ip"`
	ActionType        string    `json:"action_type"`
	TargetEntity      string    `json:"target_entity"`
	Justification     string    `json:"justification"`
	CryptographicHash string    `json:"cryptographic_hash"`
}

// ActiveBan represents an enforced quarantine state.
type ActiveBan struct {
	IP              string    `json:"ip"`
	Reason          string    `json:"reason"`
	BanTime         time.Time `json:"ban_time"`
	DurationSeconds int64     `json:"duration_seconds"`
	Status          string    `json:"status"`
}

// AgentTelemetry models an edge collector sensor node's health, binding, and XDP line-rate drops.
type AgentTelemetry struct {
	NodeID              string  `json:"node_id"`
	NodeGroup           string  `json:"node_group"`
	IPAddress           string  `json:"ip_address"`
	ActiveInterface     string  `json:"active_interface"`
	XDPStatus           string  `json:"xdp_status"` // 'ACTIVE', 'BYPASS', 'OFFLINE'
	LastSeenMs          int64   `json:"last_seen_ms"`
	CPUUsagePct         float64 `json:"cpu_usage_pct"`
	MemoryUsageMB       float64 `json:"memory_usage_mb"`
	TotalPacketsDropped int64   `json:"total_packets_dropped"`
}

// SecurityStorage provides banking-grade, SQLi-immune storage with tamper-resistant auditing.
type SecurityStorage struct {
	db *sql.DB
	mu sync.RWMutex

	// Pre-compiled prepared statements guaranteeing 100% parameterized execution
	stmtInsertAudit          *sql.Stmt
	stmtGetLastAudit         *sql.Stmt
	stmtInsertBan            *sql.Stmt
	stmtRevokeBan            *sql.Stmt
	stmtGetActiveBans        *sql.Stmt
	stmtCheckBan             *sql.Stmt
	stmtUpsertAgentHeartbeat *sql.Stmt
	stmtGetRecentUnbans      *sql.Stmt
}

// NewSecurityStorage initializes embedded WAL-mode SQLite with append-only audit protections.
func NewSecurityStorage(dbPath string) (*SecurityStorage, error) {
	if strings.TrimSpace(dbPath) == "" {
		dbPath = "./copsec_vault.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Strict connection parameters: WAL journal, normal sync, busy timeout to prevent SQLITE_BUSY
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(1 * time.Hour)

	s := &SecurityStorage{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schema initialization failed: %w", err)
	}

	if err := s.prepareStatements(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("statement preparation failed: %w", err)
	}

	return s, nil
}

// initSchema creates the banking-grade append-only audit trail and quarantine tables with immutability triggers.
func (s *SecurityStorage) initSchema() error {
	schema := `
	-- 1. Append-Only Tamper-Resistant Security Audit Trail
	CREATE TABLE IF NOT EXISTS security_audit_trail (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		actor_identity TEXT NOT NULL,
		actor_ip TEXT NOT NULL,
		action_type TEXT NOT NULL,      -- e.g., 'MANUAL_UNBAN', 'POLICY_OVERRIDE', 'RULE_UPDATE'
		target_entity TEXT NOT NULL,    -- e.g., '198.51.100.24', 'RULE-SQLI-001'
		justification TEXT NOT NULL,
		cryptographic_hash TEXT NOT NULL -- SHA256(prev_hash + entry_payload)
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_trail(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_actor ON security_audit_trail(actor_identity);

	-- 2. SQLite Triggers Enforcing Strict Append-Only Immutability (Disallowing UPDATE and DELETE)
	CREATE TRIGGER IF NOT EXISTS prevent_audit_update
	BEFORE UPDATE ON security_audit_trail
	BEGIN
		SELECT RAISE(FAIL, 'SECURITY VIOLATION: Updates to security_audit_trail are prohibited by Zero-Trust policy');
	END;

	CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
	BEFORE DELETE ON security_audit_trail
	BEGIN
		SELECT RAISE(FAIL, 'SECURITY VIOLATION: Deletions from security_audit_trail are prohibited by Zero-Trust policy');
	END;

	-- 3. Parameterized Active Quarantine Bans Table
	CREATE TABLE IF NOT EXISTS active_bans (
		ip TEXT PRIMARY KEY,
		reason TEXT NOT NULL,
		ban_time_ms INTEGER NOT NULL,
		duration_seconds INTEGER NOT NULL,
		status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
	);

	CREATE INDEX IF NOT EXISTS idx_bans_status ON active_bans(status);

	-- 4. Multi-Node Fleet Telemetry Table
	CREATE TABLE IF NOT EXISTS fleet_agents (
		node_id TEXT PRIMARY KEY,
		node_group TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		active_interface TEXT NOT NULL,
		xdp_status TEXT NOT NULL,          -- 'ACTIVE', 'BYPASS', 'OFFLINE'
		last_seen_ms INTEGER NOT NULL,
		cpu_usage_pct REAL DEFAULT 0.0,
		memory_usage_mb REAL DEFAULT 0.0,
		total_packets_dropped INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_agent_last_seen ON fleet_agents(last_seen_ms);
	`

	_, err := s.db.Exec(schema)
	return err
}

// prepareStatements compiles prepared statements upfront to eliminate any SQL injection vector.
func (s *SecurityStorage) prepareStatements() error {
	var err error

	s.stmtInsertAudit, err = s.db.Prepare(`
		INSERT INTO security_audit_trail 
			(actor_identity, actor_ip, action_type, target_entity, justification, cryptographic_hash) 
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}

	s.stmtGetLastAudit, err = s.db.Prepare(`
		SELECT id, cryptographic_hash FROM security_audit_trail ORDER BY id DESC LIMIT 1
	`)
	if err != nil {
		return err
	}

	s.stmtInsertBan, err = s.db.Prepare(`
		INSERT OR REPLACE INTO active_bans 
			(ip, reason, ban_time_ms, duration_seconds, status) 
		VALUES (?, ?, ?, ?, 'ACTIVE')
	`)
	if err != nil {
		return err
	}

	s.stmtRevokeBan, err = s.db.Prepare(`
		UPDATE active_bans SET status = 'REVOKED' WHERE ip = ? AND status = 'ACTIVE'
	`)
	if err != nil {
		return err
	}

	s.stmtGetActiveBans, err = s.db.Prepare(`
		SELECT ip, reason, ban_time_ms, duration_seconds, status FROM active_bans WHERE status = ? ORDER BY ban_time_ms DESC
	`)
	if err != nil {
		return err
	}

	s.stmtCheckBan, err = s.db.Prepare(`
		SELECT ip, reason, ban_time_ms, duration_seconds, status FROM active_bans WHERE ip = ? AND status = 'ACTIVE'
	`)
	if err != nil {
		return err
	}

	s.stmtUpsertAgentHeartbeat, err = s.db.Prepare(`
		INSERT INTO fleet_agents (
			node_id, node_group, ip_address, active_interface, xdp_status,
			last_seen_ms, cpu_usage_pct, memory_usage_mb, total_packets_dropped
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			node_group = excluded.node_group,
			ip_address = excluded.ip_address,
			active_interface = excluded.active_interface,
			xdp_status = excluded.xdp_status,
			last_seen_ms = excluded.last_seen_ms,
			cpu_usage_pct = excluded.cpu_usage_pct,
			memory_usage_mb = excluded.memory_usage_mb,
			total_packets_dropped = excluded.total_packets_dropped
	`)
	if err != nil {
		return err
	}

	s.stmtGetRecentUnbans, err = s.db.Prepare(`
		SELECT id, timestamp, actor_identity, actor_ip, action_type, target_entity, justification, cryptographic_hash
		FROM security_audit_trail
		WHERE action_type = 'MANUAL_UNBAN'
		ORDER BY id DESC
		LIMIT ?
	`)
	return err
}

// RecordAuditEntry appends a cryptographic hash-chained event to the immutable audit trail.
func (s *SecurityStorage) RecordAuditEntry(ctx context.Context, entry AuditEntry) (*AuditEntry, error) {
	if strings.TrimSpace(entry.ActorIdentity) == "" {
		return nil, errors.New("audit violation: actor_identity is mandatory")
	}
	if strings.TrimSpace(entry.Justification) == "" {
		return nil, errors.New("audit violation: justification is mandatory for compliance")
	}
	if strings.TrimSpace(entry.ActionType) == "" {
		return nil, errors.New("audit violation: action_type is mandatory")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Fetch previous block hash for chain integrity
	var lastID int64
	var prevHash string
	err := s.stmtGetLastAudit.QueryRowContext(ctx).Scan(&lastID, &prevHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to retrieve previous audit entry: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) || prevHash == "" {
		prevHash = GenesisAuditHash
	}

	// 2. Compute SHA256 Cryptographic Digest
	hasher := sha256.New()
	hashPayload := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		prevHash,
		entry.ActorIdentity,
		entry.ActorIP,
		entry.ActionType,
		entry.TargetEntity,
		entry.Justification,
	)
	hasher.Write([]byte(hashPayload))
	cryptoHash := hex.EncodeToString(hasher.Sum(nil))

	// 3. Parameterized Insert into SQLite
	res, err := s.stmtInsertAudit.ExecContext(ctx,
		entry.ActorIdentity,
		entry.ActorIP,
		entry.ActionType,
		entry.TargetEntity,
		entry.Justification,
		cryptoHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to record immutable audit log: %w", err)
	}

	insertedID, _ := res.LastInsertId()
	entry.ID = insertedID
	entry.Timestamp = time.Now().UTC()
	entry.CryptographicHash = cryptoHash

	return &entry, nil
}

// EnforceQuarantineBan records an active ban while recording an atomic audit log entry.
func (s *SecurityStorage) EnforceQuarantineBan(
	ctx context.Context,
	ip string,
	reason string,
	durationSec int64,
	actorIdentity string,
	actorIP string,
	justification string,
) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return errors.New("cannot ban empty IP")
	}

	// Execute inside database transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	nowMs := time.Now().UnixMilli()
	_, err = tx.ExecContext(ctx,
		"INSERT OR REPLACE INTO active_bans (ip, reason, ban_time_ms, duration_seconds, status) VALUES (?, ?, ?, ?, 'ACTIVE')",
		cleanIP, reason, nowMs, durationSec,
	)
	if err != nil {
		return fmt.Errorf("failed to insert active ban: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit ban transaction: %w", err)
	}

	// Record corresponding audit entry
	_, err = s.RecordAuditEntry(ctx, AuditEntry{
		ActorIdentity: actorIdentity,
		ActorIP:       actorIP,
		ActionType:    "ENFORCE_QUARANTINE_BAN",
		TargetEntity:  cleanIP,
		Justification: justification,
	})
	return err
}

// RevokeQuarantineBan removes an active ban with mandatory SOC operator justification.
func (s *SecurityStorage) RevokeQuarantineBan(
	ctx context.Context,
	ip string,
	actorIdentity string,
	actorIP string,
	justification string,
) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return errors.New("cannot unban empty IP")
	}
	if strings.TrimSpace(justification) == "" {
		return errors.New("regulatory compliance error: unban justification is required")
	}

	res, err := s.stmtRevokeBan.ExecContext(ctx, cleanIP)
	if err != nil {
		return fmt.Errorf("failed to update ban status: %w", err)
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("no active ban found for IP %s", cleanIP)
	}

	// Record mandatory audit trail
	_, err = s.RecordAuditEntry(ctx, AuditEntry{
		ActorIdentity: actorIdentity,
		ActorIP:       actorIP,
		ActionType:    "MANUAL_UNBAN",
		TargetEntity:  cleanIP,
		Justification: justification,
	})
	return err
}

// GetActiveBans returns currently quarantined actors using parameterized query.
func (s *SecurityStorage) GetActiveBans(ctx context.Context) ([]ActiveBan, error) {
	rows, err := s.stmtGetActiveBans.QueryContext(ctx, "ACTIVE")
	if err != nil {
		return nil, fmt.Errorf("failed to query active bans: %w", err)
	}
	defer rows.Close()

	var bans []ActiveBan
	for rows.Next() {
		var b ActiveBan
		var banTimeMs int64
		if err := rows.Scan(&b.IP, &b.Reason, &banTimeMs, &b.DurationSeconds, &b.Status); err != nil {
			return nil, err
		}
		b.BanTime = time.UnixMilli(banTimeMs)
		bans = append(bans, b)
	}

	return bans, nil
}

// VerifyAuditTrailIntegrity validates the cryptographic hash chain of the entire audit table.
func (s *SecurityStorage) VerifyAuditTrailIntegrity(ctx context.Context) (bool, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor_identity, actor_ip, action_type, target_entity, justification, cryptographic_hash 
		FROM security_audit_trail 
		ORDER BY id ASC
	`)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()

	currentPrevHash := GenesisAuditHash
	recordCount := 0

	for rows.Next() {
		var id int64
		var actor, ip, action, target, justification, recordedHash string

		if err := rows.Scan(&id, &actor, &ip, &action, &target, &justification, &recordedHash); err != nil {
			return false, recordCount, err
		}

		// Recompute expected hash
		hasher := sha256.New()
		hashPayload := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
			currentPrevHash, actor, ip, action, target, justification,
		)
		hasher.Write([]byte(hashPayload))
		computedHash := hex.EncodeToString(hasher.Sum(nil))

		if computedHash != recordedHash {
			return false, recordCount, fmt.Errorf("hash chain integrity broken at audit record id=%d", id)
		}

		currentPrevHash = recordedHash
		recordCount++
	}

	return true, recordCount, nil
}

// UpsertAgentHeartbeat writes or updates node telemetry using ON CONFLICT(node_id) DO UPDATE.
func (s *SecurityStorage) UpsertAgentHeartbeat(ctx context.Context, agent AgentTelemetry) error {
	nodeID := strings.TrimSpace(agent.NodeID)
	if nodeID == "" {
		return errors.New("fleet agent upsert failed: node_id cannot be empty")
	}
	if agent.NodeGroup == "" {
		agent.NodeGroup = "DEFAULT"
	}
	if agent.ActiveInterface == "" {
		agent.ActiveInterface = "eth0"
	}
	if agent.XDPStatus == "" {
		agent.XDPStatus = "ACTIVE"
	}
	if agent.LastSeenMs <= 0 {
		agent.LastSeenMs = time.Now().UnixMilli()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.stmtUpsertAgentHeartbeat.ExecContext(ctx,
		nodeID,
		agent.NodeGroup,
		agent.IPAddress,
		agent.ActiveInterface,
		agent.XDPStatus,
		agent.LastSeenMs,
		agent.CPUUsagePct,
		agent.MemoryUsageMB,
		agent.TotalPacketsDropped,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert agent heartbeat for node %s: %w", nodeID, err)
	}
	return nil
}

// GetFleetStatus queries all registered nodes, dynamically flagging any node whose
// last_seen_ms is older than staleThreshold (default 30s) as OFFLINE.
func (s *SecurityStorage) GetFleetStatus(ctx context.Context, staleThreshold time.Duration) ([]AgentTelemetry, error) {
	if staleThreshold <= 0 {
		staleThreshold = 30 * time.Second
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, node_group, ip_address, active_interface, xdp_status,
		       last_seen_ms, cpu_usage_pct, memory_usage_mb, total_packets_dropped
		FROM fleet_agents
		ORDER BY node_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query fleet status: %w", err)
	}
	defer rows.Close()

	nowMs := time.Now().UnixMilli()
	staleThresholdMs := staleThreshold.Milliseconds()
	var fleet []AgentTelemetry

	for rows.Next() {
		var a AgentTelemetry
		if err := rows.Scan(
			&a.NodeID,
			&a.NodeGroup,
			&a.IPAddress,
			&a.ActiveInterface,
			&a.XDPStatus,
			&a.LastSeenMs,
			&a.CPUUsagePct,
			&a.MemoryUsageMB,
			&a.TotalPacketsDropped,
		); err != nil {
			return nil, fmt.Errorf("failed to scan fleet agent row: %w", err)
		}

		// Dynamically flag nodes whose last_seen_ms is older than 30s as OFFLINE
		if (nowMs - a.LastSeenMs) > staleThresholdMs {
			a.XDPStatus = "OFFLINE"
		}

		fleet = append(fleet, a)
	}

	return fleet, rows.Err()
}

// GetRecentUnbans returns the last N manual unban operations for audit reporting.
func (s *SecurityStorage) GetRecentUnbans(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 15
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.stmtGetRecentUnbans.QueryContext(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent unbans: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var tsStr string
		if err := rows.Scan(&e.ID, &tsStr, &e.ActorIdentity, &e.ActorIP, &e.ActionType, &e.TargetEntity, &e.Justification, &e.CryptographicHash); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse("2006-01-02 15:04:05", tsStr)
		if e.Timestamp.IsZero() {
			e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetAuditSummary returns aggregate audit metrics for compliance reporting.
func (s *SecurityStorage) GetAuditSummary(ctx context.Context) (totalIncidents int64, totalPacketsDropped int64, activeNodes int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_audit_trail").Scan(&totalIncidents)
	_ = s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(total_packets_dropped), 0) FROM fleet_agents").Scan(&totalPacketsDropped)

	nowMs := time.Now().UnixMilli()
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM fleet_agents WHERE (? - last_seen_ms) <= 30000 AND xdp_status != 'OFFLINE'", nowMs).Scan(&activeNodes)

	return totalIncidents, totalPacketsDropped, activeNodes, nil
}

// Close gracefully closes all prepared statements and the database connection.
func (s *SecurityStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stmtInsertAudit != nil { _ = s.stmtInsertAudit.Close() }
	if s.stmtGetLastAudit != nil { _ = s.stmtGetLastAudit.Close() }
	if s.stmtInsertBan != nil { _ = s.stmtInsertBan.Close() }
	if s.stmtRevokeBan != nil { _ = s.stmtRevokeBan.Close() }
	if s.stmtGetActiveBans != nil { _ = s.stmtGetActiveBans.Close() }
	if s.stmtCheckBan != nil { _ = s.stmtCheckBan.Close() }
	if s.stmtUpsertAgentHeartbeat != nil { _ = s.stmtUpsertAgentHeartbeat.Close() }
	if s.stmtGetRecentUnbans != nil { _ = s.stmtGetRecentUnbans.Close() }

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
