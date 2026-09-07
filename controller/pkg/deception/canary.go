package deception

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CanaryType defines the category of trackable honey-token decoy.
type CanaryType string

const (
	CanaryTypeAWSKey   CanaryType = "AWS_KEY"
	CanaryTypeAPIToken CanaryType = "API_TOKEN"
	CanaryTypeDBString CanaryType = "DB_STRING"
)

// CanaryToken represents an active trackable honey-token decoy.
type CanaryToken struct {
	TokenValue      string     `json:"token_value"`
	TokenType       CanaryType `json:"token_type"`
	CreatedAtMs     int64      `json:"created_at_ms"`
	TriggeredCount  int64      `json:"triggered_count"`
	LastTriggeredMs int64      `json:"last_triggered_ms,omitempty"`
	Metadata        string     `json:"metadata,omitempty"`
}

// CanaryTriggerCallback is called when a honey-token is consumed.
type CanaryTriggerCallback func(token *CanaryToken, clientIP string, location string)

// CanaryEngine manages dynamic generation, SQLite persistence, in-memory caching,
// and zero-false-positive detection of honey-tokens.
type CanaryEngine struct {
	mu             sync.RWMutex
	db             *sql.DB
	tokens         map[string]*CanaryToken
	totalGenerated uint64
	totalTriggers  uint64
	onTrigger      CanaryTriggerCallback

	// Pre-compiled regex patterns for zero-latency token extraction
	awsRegex *regexp.Regexp
	apiRegex *regexp.Regexp
	dbRegex  *regexp.Regexp
}

var (
	defaultCanaryEngine *CanaryEngine
	canaryOnce          sync.Once
)

// GetDefaultCanaryEngine returns the singleton canary deception engine.
func GetDefaultCanaryEngine() *CanaryEngine {
	canaryOnce.Do(func() {
		defaultCanaryEngine = NewCanaryEngine(nil)
	})
	return defaultCanaryEngine
}

// NewCanaryEngine initializes a new honey-token canary engine.
func NewCanaryEngine(db *sql.DB) *CanaryEngine {
	engine := &CanaryEngine{
		db:       db,
		tokens:   make(map[string]*CanaryToken),
		awsRegex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		apiRegex: regexp.MustCompile(`copsec_canary_live_[0-9a-fA-F]{32}`),
		dbRegex:  regexp.MustCompile(`(?:postgres|mysql|mongodb)://[^\s'"]+`),
	}

	if db != nil {
		if err := engine.InitSchema(); err != nil {
			log.Printf("[CANARY] ⚠️ Failed to initialize honey_tokens schema: %v", err)
		}
		if err := engine.loadTokensFromDB(); err != nil {
			log.Printf("[CANARY] ⚠️ Failed to load tokens from DB: %v", err)
		}
	}

	return engine
}

// SetDB attaches an active SQLite database to persist honey-tokens.
func (e *CanaryEngine) SetDB(db *sql.DB) error {
	e.mu.Lock()
	e.db = db
	e.mu.Unlock()

	if db != nil {
		if err := e.InitSchema(); err != nil {
			return err
		}
		return e.loadTokensFromDB()
	}
	return nil
}

// SetTriggerCallback sets the callback executed when an active canary token is triggered.
func (e *CanaryEngine) SetTriggerCallback(cb CanaryTriggerCallback) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onTrigger = cb
}

// InitSchema creates the honey_tokens table in SQLite.
func (e *CanaryEngine) InitSchema() error {
	e.mu.RLock()
	db := e.db
	e.mu.RUnlock()

	if db == nil {
		return nil
	}

	query := `
	CREATE TABLE IF NOT EXISTS honey_tokens (
		token_value TEXT PRIMARY KEY,
		token_type TEXT NOT NULL,
		created_at_ms INTEGER NOT NULL,
		triggered_count INTEGER DEFAULT 0,
		last_triggered_ms INTEGER DEFAULT 0,
		metadata TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_honey_tokens_type ON honey_tokens(token_type);
	`
	_, err := db.Exec(query)
	return err
}

func (e *CanaryEngine) loadTokensFromDB() error {
	e.mu.RLock()
	db := e.db
	e.mu.RUnlock()

	if db == nil {
		return nil
	}

	rows, err := db.Query("SELECT token_value, token_type, created_at_ms, triggered_count, last_triggered_ms, metadata FROM honey_tokens")
	if err != nil {
		return err
	}
	defer rows.Close()

	e.mu.Lock()
	defer e.mu.Unlock()

	for rows.Next() {
		var t CanaryToken
		if err := rows.Scan(&t.TokenValue, &t.TokenType, &t.CreatedAtMs, &t.TriggeredCount, &t.LastTriggeredMs, &t.Metadata); err != nil {
			continue
		}
		e.tokens[t.TokenValue] = &t
	}

	log.Printf("[CANARY] 🍯 Loaded %d active honey-tokens from SQLite storage", len(e.tokens))
	return nil
}

// GenerateAWSKey creates a realistic fake AWS IAM Access Key ID (`AKIA...`).
func (e *CanaryEngine) GenerateAWSKey(metadata string) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	suffix := make([]byte, 16)
	for i := range suffix {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		suffix[i] = charset[n.Int64()]
	}
	token := fmt.Sprintf("AKIA%s", string(suffix))
	e.RegisterToken(token, CanaryTypeAWSKey, metadata)
	return token
}

// GenerateAPIToken creates a fake API Bearer token (`copsec_canary_live_...`).
func (e *CanaryEngine) GenerateAPIToken(metadata string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := fmt.Sprintf("copsec_canary_live_%s", hex.EncodeToString(buf))
	e.RegisterToken(token, CanaryTypeAPIToken, metadata)
	return token
}

// GenerateDBConnString creates a pseudo-DB connection string embedded with decoys.
func (e *CanaryEngine) GenerateDBConnString(engineType string, metadata string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	secret := hex.EncodeToString(buf)

	if engineType == "" {
		engineType = "postgres"
	}
	engineType = strings.ToLower(engineType)

	var token string
	switch engineType {
	case "mysql":
		token = fmt.Sprintf("mysql://copsec_audit_usr:%s@db-replica-01.internal:3306/production_users", secret)
	case "mongodb":
		token = fmt.Sprintf("mongodb://copsec_admin:%s@mongo-cluster.internal:27017/enterprise_vault", secret)
	default:
		token = fmt.Sprintf("postgres://copsec_db_admin:%s@pg-master.internal:5432/core_accounts", secret)
	}

	e.RegisterToken(token, CanaryTypeDBString, metadata)
	return token
}

// RegisterToken registers a token in memory and persists to SQLite.
func (e *CanaryEngine) RegisterToken(tokenValue string, tokenType CanaryType, metadata string) *CanaryToken {
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return nil
	}

	token := &CanaryToken{
		TokenValue:     tokenValue,
		TokenType:      tokenType,
		CreatedAtMs:    time.Now().UnixMilli(),
		TriggeredCount: 0,
		Metadata:       metadata,
	}

	e.mu.Lock()
	e.tokens[tokenValue] = token
	db := e.db
	e.mu.Unlock()

	atomic.AddUint64(&e.totalGenerated, 1)

	if db != nil {
		go func(t *CanaryToken) {
			_, _ = db.Exec(
				"INSERT OR REPLACE INTO honey_tokens (token_value, token_type, created_at_ms, triggered_count, last_triggered_ms, metadata) VALUES (?, ?, ?, ?, ?, ?)",
				t.TokenValue, string(t.TokenType), t.CreatedAtMs, t.TriggeredCount, t.LastTriggeredMs, t.Metadata,
			)
		}(token)
	}

	return token
}

// GetToken returns the canary token record if active.
func (e *CanaryEngine) GetToken(tokenValue string) (*CanaryToken, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.tokens[tokenValue]
	return t, ok
}

// GetAllTokens returns all active canary tokens.
func (e *CanaryEngine) GetAllTokens() []*CanaryToken {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*CanaryToken, 0, len(e.tokens))
	for _, t := range e.tokens {
		cp := *t
		list = append(list, &cp)
	}
	return list
}

// RecordTrigger increments the trigger count for a token and updates SQLite.
func (e *CanaryEngine) RecordTrigger(tokenValue string, clientIP string, location string) (*CanaryToken, bool) {
	e.mu.Lock()
	token, ok := e.tokens[tokenValue]
	if !ok {
		e.mu.Unlock()
		return nil, false
	}

	token.TriggeredCount++
	token.LastTriggeredMs = time.Now().UnixMilli()
	db := e.db
	cb := e.onTrigger
	tokenCopy := *token
	e.mu.Unlock()

	atomic.AddUint64(&e.totalTriggers, 1)
	log.Printf("[CANARY_ALERT] 🚨 ZERO-FALSE-POSITIVE: Honey-Token %s (%s) triggered by %s at %s (TriggerCount: %d)",
		token.TokenValue, token.TokenType, clientIP, location, token.TriggeredCount)

	if db != nil {
		go func(val string, lastMs int64) {
			_, _ = db.Exec("UPDATE honey_tokens SET triggered_count = triggered_count + 1, last_triggered_ms = ? WHERE token_value = ?", lastMs, val)
		}(tokenValue, token.LastTriggeredMs)
	}

	if cb != nil {
		cb(&tokenCopy, clientIP, location)
	}

	return &tokenCopy, true
}

// InspectString checks a string for any embedded canary tokens.
func (e *CanaryEngine) InspectString(input string, clientIP string, location string) (*CanaryToken, bool) {
	if input == "" {
		return nil, false
	}

	// 1. Check exact matches in token map
	e.mu.RLock()
	for val := range e.tokens {
		if strings.Contains(input, val) {
			e.mu.RUnlock()
			return e.RecordTrigger(val, clientIP, location)
		}
	}
	e.mu.RUnlock()

	// 2. Extract potential candidate tokens via regex
	candidates := make([]string, 0, 4)
	candidates = append(candidates, e.awsRegex.FindAllString(input, -1)...)
	candidates = append(candidates, e.apiRegex.FindAllString(input, -1)...)
	candidates = append(candidates, e.dbRegex.FindAllString(input, -1)...)

	for _, cand := range candidates {
		e.mu.RLock()
		_, exists := e.tokens[cand]
		e.mu.RUnlock()
		if exists {
			return e.RecordTrigger(cand, clientIP, location)
		}
	}

	return nil, false
}

// InspectHTTPRequest scans HTTP headers, query parameters, auth tokens, and payload for canary tokens.
func (e *CanaryEngine) InspectHTTPRequest(r *http.Request) (*CanaryToken, bool) {
	if r == nil {
		return nil, false
	}

	clientIP := r.RemoteAddr
	if host, _, err := strings.Cut(clientIP, ":"); err && host != "" {
		clientIP = host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	// 1. Inspect Authorization & API Key Headers
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if token, triggered := e.InspectString(authHeader, clientIP, "Header:Authorization"); triggered {
			return token, true
		}
	}

	apiKeyHeader := r.Header.Get("X-API-Key")
	if apiKeyHeader != "" {
		if token, triggered := e.InspectString(apiKeyHeader, clientIP, "Header:X-API-Key"); triggered {
			return token, true
		}
	}

	awsKeyHeader := r.Header.Get("X-Amz-Security-Token")
	if awsKeyHeader != "" {
		if token, triggered := e.InspectString(awsKeyHeader, clientIP, "Header:X-Amz-Security-Token"); triggered {
			return token, true
		}
	}

	// 2. Inspect all other headers
	for name, values := range r.Header {
		for _, val := range values {
			if token, triggered := e.InspectString(val, clientIP, fmt.Sprintf("Header:%s", name)); triggered {
				return token, true
			}
		}
	}

	// 3. Inspect URL Path and Query Parameters
	if token, triggered := e.InspectString(r.URL.Path, clientIP, "URL:Path"); triggered {
		return token, true
	}
	if r.URL.RawQuery != "" {
		if unescaped, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
			if token, triggered := e.InspectString(unescaped, clientIP, "URL:Query"); triggered {
				return token, true
			}
		} else {
			if token, triggered := e.InspectString(r.URL.RawQuery, clientIP, "URL:Query"); triggered {
				return token, true
			}
		}
	}

	// 4. Inspect Request Body (read up to 64KB without consuming the stream)
	if r.Body != nil && r.ContentLength != 0 {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil && len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if token, triggered := e.InspectString(string(bodyBytes), clientIP, "HTTP:Body"); triggered {
				return token, true
			}
		}
	}

	return nil, false
}

// InjectDecoyHeaders injects trackable canary tokens into outbound HTTP responses or honeypot traps.
func (e *CanaryEngine) InjectDecoyHeaders(header http.Header) {
	if header == nil {
		return
	}
	apiToken := e.GenerateAPIToken("HTTP_HEADER_DECOY")
	awsKey := e.GenerateAWSKey("HTTP_HEADER_DECOY")

	header.Set("X-Debug-Session-Token", apiToken)
	header.Set("X-Backend-Config-Key", awsKey)
}

// GetStats returns telemetry metrics on canary deception tokens.
func (e *CanaryEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"active_tokens":   len(e.tokens),
		"total_generated": atomic.LoadUint64(&e.totalGenerated),
		"total_triggers":  atomic.LoadUint64(&e.totalTriggers),
	}
}
