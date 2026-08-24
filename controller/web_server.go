package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var embeddedWebFS embed.FS

// WebSOCServer hosts the embedded Web SOC, REST APIs, Deception routes, and WebSocket hub.
type WebSOCServer struct {
	mu              sync.RWMutex
	listenAddr      string
	server          *CentralServer
	storage         *StorageEngine
	ttlManager      *TTLBanManager
	sigmaEngine     *SigmaEngine
	wsHub           *WSHub
	deceptionRouter *HoneyDeceptionRouter
	rateLimiter     *TokenBucketRateLimiter
	httpServer      *http.Server
	honeypotSSH     *HoneypotSSHServer
}

// SystemConfigDTO represents the runtime configuration schema.
type SystemConfigDTO struct {
	GRPCAddr         string `json:"grpc_addr"`
	TelegramToken    string `json:"telegram_token"`
	TelegramChat     string `json:"telegram_chat"`
	HoneypotSSHAddr  string `json:"honeypot_ssh_addr"`
	AutoBanThreshold int    `json:"autoban_threshold"`
	ThreatIntelKey   string `json:"threat_intel_key"`
	Configured       bool   `json:"configured"`
}

// NewWebSOCServer initializes the Web SOC server.
func NewWebSOCServer(
	listenAddr string,
	server *CentralServer,
	storage *StorageEngine,
	ttlManager *TTLBanManager,
	sigmaEngine *SigmaEngine,
	wsHub *WSHub,
	deceptionRouter *HoneyDeceptionRouter,
	rateLimiter *TokenBucketRateLimiter,
	honeypotSSH *HoneypotSSHServer,
) *WebSOCServer {
	return &WebSOCServer{
		listenAddr:      listenAddr,
		server:          server,
		storage:         storage,
		ttlManager:      ttlManager,
		sigmaEngine:     sigmaEngine,
		wsHub:           wsHub,
		deceptionRouter: deceptionRouter,
		rateLimiter:     rateLimiter,
		honeypotSSH:     honeypotSSH,
	}
}

// Start runs the HTTP listener in the background.
func (ws *WebSOCServer) Start() error {
	mux := http.NewServeMux()

	// 1. WebSocket Endpoint
	mux.Handle("/ws/events", ws.wsHub.Handler())

	// 2. REST APIs
	mux.HandleFunc("/api/config", ws.handleConfig)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/events", ws.handleEvents)
	mux.HandleFunc("/api/bans", ws.handleBans)
	mux.HandleFunc("/api/soar/ban", ws.handleSOARBan)
	mux.HandleFunc("/api/soar/unban", ws.handleSOARUnban)
	mux.HandleFunc("/api/sigma/rules", ws.handleSigmaRules)
	mux.HandleFunc("/api/sigma/rule", ws.handleSigmaRuleSubmit)
	mux.HandleFunc("/api/honeypot/logs", ws.handleHoneypotLogs)
	mux.HandleFunc("/api/nodes", ws.handleNodes)

	// 3. Embedded Web SOC and Deception Traps
	mux.HandleFunc("/", ws.handleRootOrTrap)

	// Wrap handler with Token Bucket Rate Limiter
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _ := parseRemoteAddr(r.RemoteAddr)
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			clientIP = strings.TrimSpace(parts[0])
		}

		if ws.rateLimiter != nil {
			allowed, retryAfter := ws.rateLimiter.Allow(clientIP)
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				http.Error(w, "Too Many Requests (Rate Limit Exceeded)", http.StatusTooManyRequests)
				return
			}
		}

		mux.ServeHTTP(w, r)
	})

	ws.httpServer = &http.Server{
		Addr:         ws.listenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("[INFO] 🌐 Embedded Zero-Config Web SOC Console listening on http://%s", ws.listenAddr)

	go func() {
		if err := ws.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Web SOC server error: %v", err)
		}
	}()

	return nil
}

func (ws *WebSOCServer) handleRootOrTrap(w http.ResponseWriter, r *http.Request) {
	// Check if requested path is a honey-URL deception route
	if ws.deceptionRouter != nil && ws.deceptionRouter.IsHoneyURL(r.URL.Path) {
		ws.deceptionRouter.HandleHoneyProbe(w, r)
		return
	}

	// Serve embedded UI for root or SPA fallback
	if r.URL.Path == "/" || r.URL.Path == "/index.html" || !strings.Contains(r.URL.Path, ".") {
		data, err := embeddedWebFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "Embedded dashboard file not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}

	// Static asset loader fallback
	cleanPath := strings.TrimPrefix(r.URL.Path, "/")
	data, err := embeddedWebFS.ReadFile("web/" + cleanPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if strings.HasSuffix(cleanPath, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(cleanPath, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (ws *WebSOCServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		cfg := ws.loadSystemConfig()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == http.MethodPost {
		var req SystemConfigDTO
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := ws.saveSystemConfig(&req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Dynamically apply settings without process restart
		ws.applyRuntimeConfig(&req)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Configuration saved and applied dynamically",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (ws *WebSOCServer) loadSystemConfig() *SystemConfigDTO {
	dto := &SystemConfigDTO{
		GRPCAddr:         "0.0.0.0:8443",
		HoneypotSSHAddr:  ":2222",
		AutoBanThreshold: 50,
		Configured:       false,
	}

	if ws.storage == nil {
		return dto
	}

	cfgMap, err := ws.storage.GetAllSystemConfig()
	if err != nil || len(cfgMap) == 0 {
		return dto
	}

	if v, ok := cfgMap["grpc_addr"]; ok && v != "" {
		dto.GRPCAddr = v
	}
	if v, ok := cfgMap["telegram_token"]; ok {
		dto.TelegramToken = v
	}
	if v, ok := cfgMap["telegram_chat"]; ok {
		dto.TelegramChat = v
	}
	if v, ok := cfgMap["honeypot_ssh_addr"]; ok && v != "" {
		dto.HoneypotSSHAddr = v
	}
	if v, ok := cfgMap["threat_intel_key"]; ok {
		dto.ThreatIntelKey = v
	}
	if v, ok := cfgMap["autoban_threshold"]; ok {
		if t, err := strconv.Atoi(v); err == nil && t > 0 {
			dto.AutoBanThreshold = t
		}
	}
	if v, ok := cfgMap["configured"]; ok && v == "true" {
		dto.Configured = true
	}

	return dto
}

func (ws *WebSOCServer) saveSystemConfig(cfg *SystemConfigDTO) error {
	if ws.storage == nil {
		return nil
	}

	cfgMap := map[string]string{
		"grpc_addr":          cfg.GRPCAddr,
		"telegram_token":     cfg.TelegramToken,
		"telegram_chat":      cfg.TelegramChat,
		"honeypot_ssh_addr":  cfg.HoneypotSSHAddr,
		"autoban_threshold":  strconv.Itoa(cfg.AutoBanThreshold),
		"threat_intel_key":   cfg.ThreatIntelKey,
		"configured":         "true",
	}

	return ws.storage.SaveSystemConfig(cfgMap)
}

func (ws *WebSOCServer) applyRuntimeConfig(cfg *SystemConfigDTO) {
	if ws.server != nil {
		ws.server.SetAutoBanPolicy(true, cfg.AutoBanThreshold)

		// Reconfigure Telegram SOAR Bot dynamically
		if cfg.TelegramToken != "" && cfg.TelegramChat != "" {
			tgBot := NewTelegramSOARBot(TelegramBotConfig{
				BotToken: cfg.TelegramToken,
				ChatID:   cfg.TelegramChat,
			}, ws.server)
			ws.server.SetTelegramBot(tgBot)
			log.Printf("[CONFIG] Telegram SOAR Bot dynamically updated (Chat ID: %s)", cfg.TelegramChat)
		}
	}
}

func (ws *WebSOCServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	eps := uint64(0)
	total := uint64(0)
	nodesCount := 0

	if ws.server != nil {
		eps = ws.server.GetEPS()
		total = ws.server.GetTotalEvents()
		nodesCount = len(ws.server.GetNodesSnapshot())
	}

	activeBansCount := 0
	if ws.ttlManager != nil {
		activeBansCount = len(ws.ttlManager.GetActiveBans())
	}

	var mitreStats []MITREStat
	if ws.storage != nil {
		mitreStats, _ = ws.storage.GetMITREStats()
	}

	data := map[string]interface{}{
		"eps":          eps,
		"total_events": total,
		"nodes_count":  nodesCount,
		"active_bans":  activeBansCount,
		"mitre_stats":  mitreStats,
		"timestamp":    time.Now().UnixMilli(),
	}

	json.NewEncoder(w).Encode(data)
}

func (ws *WebSOCServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.storage == nil {
		json.NewEncoder(w).Encode([]*StoredEvent{})
		return
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	var events []*StoredEvent
	var err error

	if query != "" {
		events, err = ws.storage.SearchEvents(query, limit)
	} else {
		events, err = ws.storage.GetRecentEvents(limit)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if events == nil {
		events = []*StoredEvent{}
	}

	json.NewEncoder(w).Encode(events)
}

func (ws *WebSOCServer) handleBans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.ttlManager == nil {
		json.NewEncoder(w).Encode([]DetailedBanRecord{})
		return
	}

	bans := ws.ttlManager.GetActiveBans()
	json.NewEncoder(w).Encode(bans)
}

func (ws *WebSOCServer) handleSOARBan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		IP              string `json:"ip"`
		DurationSeconds int64  `json:"duration_seconds"`
		Reason          string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if ws.ttlManager == nil {
		http.Error(w, "TTL ban manager not initialized", http.StatusInternalServerError)
		return
	}

	record, err := ws.ttlManager.BanIP(req.IP, req.Reason, req.DurationSeconds, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(record)
}

func (ws *WebSOCServer) handleSOARUnban(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if ws.ttlManager == nil {
		http.Error(w, "TTL ban manager not initialized", http.StatusInternalServerError)
		return
	}

	if err := ws.ttlManager.UnbanIP(req.IP); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("IP %s unbanned across all layers", req.IP),
	})
}

func (ws *WebSOCServer) handleSigmaRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.sigmaEngine == nil {
		json.NewEncoder(w).Encode([]*CompiledSigmaRule{})
		return
	}

	rules := ws.sigmaEngine.GetRules()
	json.NewEncoder(w).Encode(rules)
}

func (ws *WebSOCServer) handleSigmaRuleSubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		YAML string `json:"yaml"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if ws.sigmaEngine == nil {
		http.Error(w, "Sigma engine not initialized", http.StatusInternalServerError)
		return
	}

	rule, err := ws.sigmaEngine.ParseSigmaYAML(req.YAML)
	if err != nil {
		http.Error(w, fmt.Sprintf("YAML parse/compilation failed: %v", err), http.StatusBadRequest)
		return
	}

	ws.sigmaEngine.AddRule(rule)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule":    rule,
	})
}

func (ws *WebSOCServer) handleHoneypotLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.storage == nil {
		json.NewEncoder(w).Encode([]*HoneypotEvent{})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	logs, err := ws.storage.GetHoneypotLogs(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(logs)
}

func (ws *WebSOCServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.server == nil {
		json.NewEncoder(w).Encode([]NodeSession{})
		return
	}

	nodes := ws.server.GetNodesSnapshot()
	json.NewEncoder(w).Encode(nodes)
}
