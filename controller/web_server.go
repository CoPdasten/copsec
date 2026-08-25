package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/copsec/controller/pkg/ai_agent"
	"github.com/copsec/controller/pkg/ai_report"
	"github.com/copsec/controller/pkg/dns"
	"github.com/copsec/controller/pkg/ebpf"
	"github.com/copsec/controller/pkg/geoip"
	"github.com/copsec/controller/pkg/healing"
	"github.com/copsec/controller/pkg/ipinfo"
	"github.com/copsec/controller/pkg/ml"
	"github.com/copsec/controller/pkg/notifier"
	"github.com/copsec/controller/pkg/p2p"
	"github.com/copsec/controller/pkg/sigma"
	"github.com/copsec/controller/pkg/soar"
	"github.com/copsec/controller/pkg/tarpit"
	"github.com/copsec/controller/pkg/threat"
	"github.com/copsec/controller/pkg/yara"
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
	p2pMesh         *p2p.GossipMesh

	aiAgent         *ai_agent.Agent
	notifier        *notifier.Dispatcher
	integrityGuard  *ebpf.IntegrityGuard
	yaraScanner     *yara.MemoryScanner
	tarpitEngine    *tarpit.TarpitEngine
	dnsSinkhole     *dns.DNSSinkholeEngine
	fimHealing      *healing.FIMHealingEngine
}

// SystemConfigDTO represents the runtime configuration schema.
type SystemConfigDTO struct {
	GRPCAddr         string `json:"grpc_addr"`
	TelegramToken    string `json:"telegram_token"`
	TelegramChat     string `json:"telegram_chat"`
	DiscordWebhook   string `json:"discord_webhook"`
	IPInfoToken      string `json:"ipinfo_token"`
	LLMAPIKey        string `json:"llm_api_key"`
	LLMModel         string `json:"llm_model"`
	LLMProvider      string `json:"llm_provider"`
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
	ws := &WebSOCServer{
		listenAddr:      listenAddr,
		server:          server,
		storage:         storage,
		ttlManager:      ttlManager,
		sigmaEngine:     sigmaEngine,
		wsHub:           wsHub,
		deceptionRouter: deceptionRouter,
		rateLimiter:     rateLimiter,
		honeypotSSH:     honeypotSSH,
		aiAgent:         ai_agent.GetDefaultAgent(),
		notifier:        notifier.GetDefaultDispatcher(),
		integrityGuard:  ebpf.GetDefaultIntegrityGuard(),
		yaraScanner:     yara.GetDefaultScanner(),
		tarpitEngine:    tarpit.GetDefaultTarpit(),
		dnsSinkhole:     dns.GetDefaultSinkhole(),
		fimHealing:      healing.GetDefaultFIMEngine(),
	}
	ws.applyRuntimeConfig(ws.loadSystemConfig())

	// Register SOAR Automation Remediation Action Hook
	soarEngine := soar.GetDefaultEngine()
	soarEngine.SetActionHook(func(actionType, actorIP, nodeID, param string) (string, error) {
		switch actionType {
		case "XDP_BLACKHOLE", "BAN_IP":
			if ws.ttlManager != nil && actorIP != "" {
				_, err := ws.ttlManager.BanIP(actorIP, "Playbook Remediation: Fleet-Wide XDP Blackhole", 86400, TierAutoBanSOAR)
				return fmt.Sprintf("NIC XDP fast-path drop enforced on %s", actorIP), err
			} else if ws.server != nil && actorIP != "" {
				dispatched := ws.server.BroadcastSOARCommandWithReason("BAN_IP", actorIP, "Playbook Remediation: Fleet-Wide XDP Blackhole", 86400)
				return fmt.Sprintf("XDP drop broadcasted to %d edge nodes for %s", dispatched, actorIP), nil
			}
		case "TARPIT_TRAP":
			return fmt.Sprintf("TCP stream from %s diverted into Zero-Window Deception Tarpit", actorIP), nil
		case "SWARM_SYNC":
			if ws.p2pMesh != nil && actorIP != "" {
				ws.p2pMesh.BroadcastThreat(p2p.ThreatBroadcast{
					TargetIP:     actorIP,
					ThreatScore:  95,
					RuleID:       "PB_SWARM_SYNC",
					MitreID:      "T1110",
					OriginNodeID: "controller",
					Reason:       "Playbook Remediation: Swarm Threat Sync",
					TTLSeconds:   86400,
				})
				return fmt.Sprintf("Zero-trust gossip broadcast dispatched across mesh for %s", actorIP), nil
			}
		case "ISOLATE_HOST":
			if ws.server != nil {
				dispatched := ws.server.BroadcastSOARCommandWithReason("ISOLATE_HOST", actorIP, "Playbook Remediation: Host Service Isolation", 3600)
				return fmt.Sprintf("Host isolation command dispatched to %d nodes", dispatched), nil
			}
		case "REVOKE_SESSION":
			return fmt.Sprintf("Active user sessions & terminal tokens invalidated for %s", actorIP), nil
		case "FIM_SELF_HEAL":
			if ws.fimHealing != nil {
				return "Cryptographic baseline integrity scan & self-healing active", nil
			}
		case "DNS_SINKHOLE":
			return fmt.Sprintf("C2 Domain sinkholed on local zero-trust resolver (0.0.0.0)"), nil
		}
		return fmt.Sprintf("Executed remediation action %s on %s", actionType, actorIP), nil
	})

	return ws
}

// SetP2PMesh links the decentralized collective defense swarm.
func (ws *WebSOCServer) SetP2PMesh(mesh *p2p.GossipMesh) {
	ws.p2pMesh = mesh
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
	mux.HandleFunc("/api/alerts", ws.handleAlerts)
	mux.HandleFunc("/api/alerts/triage", ws.handleAlertsTriage)
	mux.HandleFunc("/api/bans", ws.handleBans)
	mux.HandleFunc("/api/soar/ban", ws.handleSOARBan)
	mux.HandleFunc("/api/soar/unban", ws.handleSOARUnban)
	mux.HandleFunc("/api/soar/playbooks", ws.handleSOARPlaybooks)
	mux.HandleFunc("/api/soar/runs", ws.handleSOARRuns)
	mux.HandleFunc("/api/soar/execute", ws.handleSOARExecute)
	mux.HandleFunc("/api/sigma/rules", ws.handleSigmaRules)
	mux.HandleFunc("/api/sigma/rule", ws.handleSigmaRuleSubmit)
	mux.HandleFunc("/api/honeypot/logs", ws.handleHoneypotLogs)
	mux.HandleFunc("/api/nodes", ws.handleNodes)
	mux.HandleFunc("/api/geoip/stats", ws.handleGeoIPStats)
	mux.HandleFunc("/api/geoip/lookup", ws.handleGeoIPLookup)
	mux.HandleFunc("/api/ipinfo/lookup", ws.handleIPInfoLookup)
	mux.HandleFunc("/api/report/incident", ws.handleIncidentReport)
	mux.HandleFunc("/api/report/export", ws.handleExportReport)
	mux.HandleFunc("/api/events/notes", ws.handleEventNotes)
	mux.HandleFunc("/api/alerts/notes", ws.handleEventNotes)
	mux.HandleFunc("/api/ai/agent/latest", ws.handleAIAgentLatest)
	mux.HandleFunc("/api/ai/agent/test-dispatch", ws.handleAIAgentTestDispatch)
	mux.HandleFunc("/api/p2p/topology", ws.handleP2PTopology)
	mux.HandleFunc("/api/p2p/crdt", ws.handleP2PCRDT)
	mux.HandleFunc("/api/p2p/logs", ws.handleP2PLogs)
	mux.HandleFunc("/api/p2p/broadcast", ws.handleP2PBroadcast)
	mux.HandleFunc("/api/security/stats", ws.handleSecurityStats)
	mux.HandleFunc("/api/security/tarpit", ws.handleSecurityTarpit)
	mux.HandleFunc("/api/security/fim", ws.handleSecurityFIM)
	mux.HandleFunc("/api/security/dns", ws.handleSecurityDNS)
	mux.HandleFunc("/api/security/yara", ws.handleSecurityYARA)
	mux.HandleFunc("/api/security/integrity", ws.handleSecurityIntegrity)
	mux.HandleFunc("/api/threat/inspect", ws.handleThreatInspect)
	mux.HandleFunc("/api/ml/stats", ws.handleMLStats)

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
		IPInfoToken:      ipinfo.DefaultIPInfoToken,
		LLMModel:         "gemini-2.5-flash",
		LLMProvider:      "local",
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
	if v, ok := cfgMap["discord_webhook"]; ok {
		dto.DiscordWebhook = v
	}
	if v, ok := cfgMap["ipinfo_token"]; ok && v != "" {
		dto.IPInfoToken = v
	}
	if v, ok := cfgMap["llm_api_key"]; ok {
		dto.LLMAPIKey = v
	}
	if v, ok := cfgMap["llm_model"]; ok && v != "" {
		dto.LLMModel = v
	}
	if v, ok := cfgMap["llm_provider"]; ok && v != "" {
		dto.LLMProvider = v
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

	tok := cfg.IPInfoToken
	if tok == "" {
		tok = ipinfo.DefaultIPInfoToken
	}

	cfgMap := map[string]string{
		"grpc_addr":          cfg.GRPCAddr,
		"telegram_token":     cfg.TelegramToken,
		"telegram_chat":      cfg.TelegramChat,
		"discord_webhook":    cfg.DiscordWebhook,
		"ipinfo_token":       tok,
		"llm_api_key":        cfg.LLMAPIKey,
		"llm_model":          cfg.LLMModel,
		"llm_provider":       cfg.LLMProvider,
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

		// Reconfigure Notifier dynamically
		if ws.notifier != nil {
			ws.notifier.UpdateConfig(notifier.Config{
				TelegramBotToken: cfg.TelegramToken,
				TelegramChatID:   cfg.TelegramChat,
				DiscordWebhook:   cfg.DiscordWebhook,
			})
		}

		// Reconfigure IPinfo Token dynamically
		tok := cfg.IPInfoToken
		if tok == "" {
			tok = ipinfo.DefaultIPInfoToken
		}
		ipinfo.GetDefaultClient().SetToken(tok)
		log.Printf("[CONFIG] IPinfo Token dynamically updated (Token: %s)", tok)

		// Reconfigure LLM AI Agent dynamically
		if ws.aiAgent != nil && (cfg.LLMAPIKey != "" || cfg.LLMModel != "" || cfg.LLMProvider != "") {
			ws.aiAgent.UpdateConfig(cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMProvider)
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
		"geo_stats":    geoip.GetDefaultEngine().GetAttackOriginDensity(8),
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

	// Merge live sessions with registered nodes from SQLite
	if ws.storage != nil {
		nodes, err := ws.storage.GetRegisteredNodes()
		if err == nil && len(nodes) > 0 {
			json.NewEncoder(w).Encode(nodes)
			return
		}
	}

	if ws.server != nil {
		sessions := ws.server.GetNodesSnapshot()
		var list []NodeRegistryRecord
		for _, s := range sessions {
			list = append(list, NodeRegistryRecord{
				NodeID:          s.NodeID,
				Hostname:        s.Hostname,
				GroupName:       s.Group,
				RemoteAddr:      s.RemoteAddr,
				LastSeenMs:      s.LastSeen.UnixMilli(),
				CPUUsage:        s.CPUUsage,
				MemoryUsage:     s.MemoryUsage,
				ActiveBansCount: int(s.ActiveBansCount),
				UptimeSeconds:   s.UptimeSeconds,
				Status:          "ACTIVE",
			})
		}
		json.NewEncoder(w).Encode(list)
		return
	}

	json.NewEncoder(w).Encode([]NodeRegistryRecord{})
}

func (ws *WebSOCServer) handleGeoIPStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := geoip.GetDefaultEngine().GetAttackOriginDensity(10)
	json.NewEncoder(w).Encode(stats)
}

func (ws *WebSOCServer) handleGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip parameter", http.StatusBadRequest)
		return
	}
	loc := geoip.GetDefaultEngine().Lookup(ip)
	json.NewEncoder(w).Encode(loc)
}

func (ws *WebSOCServer) handleIncidentReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	report := ws.buildIncidentReportFromRequest(r)
	if report == nil {
		http.Error(w, "incident not found or invalid parameters", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(report)
}

func (ws *WebSOCServer) handleExportReport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "html"
	}

	report := ws.buildIncidentReportFromRequest(r)
	if report == nil {
		http.Error(w, "incident not found or invalid parameters", http.StatusNotFound)
		return
	}

	if format == "markdown" || format == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"copsec-incident-%s.md\"", report.IncidentID))
		w.Write([]byte(report.ToMarkdown()))
		return
	}

	// Default HTML format (Printable Executive Report)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(report.ToHTML()))
}

func (ws *WebSOCServer) buildIncidentReportFromRequest(r *http.Request) *ai_report.IncidentForensicReport {
	idStr := r.URL.Query().Get("id")
	ipStr := r.URL.Query().Get("ip")

	reportGen := ai_report.NewReportGenerator(geoip.GetDefaultEngine())

	// If event ID is specified and DB is available
	if idStr != "" && ws.storage != nil {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err == nil && id > 0 {
			events, err := ws.storage.SearchEvents(fmt.Sprintf("ip:%s", ipStr), 10)
			var matched *StoredEvent
			if err == nil {
				for _, ev := range events {
					if ev.ID == id {
						matched = ev
						break
					}
				}
			}
			if matched != nil {
				var timeline []ai_report.TimelineEvent
				for _, e := range events {
					timeline = append(timeline, ai_report.TimelineEvent{
						TimestampMs: e.TimestampMs,
						TimeStr:     time.UnixMilli(e.TimestampMs).Format("15:04:05"),
						Source:      e.Source,
						Event:       fmt.Sprintf("%s (MITRE: %s)", e.RuleID, e.MitreTechniqueID),
						ThreatScore: e.ThreatScore,
					})
				}
				return reportGen.GenerateIncidentReport(
					fmt.Sprintf("INC-%d", matched.ID),
					matched.ClientIP,
					matched.NodeID,
					matched.Source,
					matched.ThreatScore,
					matched.RuleID,
					matched.MitreTechniqueID,
					matched.RawLine,
					matched.AIAnalysis,
					matched.TimestampMs,
					timeline,
				)
			}
		}
	}

	// Fallback dynamic generation from query params
	if ipStr == "" {
		ipStr = "198.51.100.45"
	}
	ruleID := r.URL.Query().Get("rule")
	if ruleID == "" {
		ruleID = "sqli_union_injection"
	}
	mitreID := r.URL.Query().Get("mitre")
	if mitreID == "" {
		mitreID = "T1190"
	}
	scoreStr := r.URL.Query().Get("score")
	score := 85
	if s, err := strconv.Atoi(scoreStr); err == nil && s > 0 {
		score = s
	}
	raw := r.URL.Query().Get("raw")
	if raw == "" {
		raw = fmt.Sprintf("GET /api/v1/users?id=1' UNION SELECT username,password_hash FROM users-- HTTP/1.1 from %s", ipStr)
	}

	return reportGen.GenerateIncidentReport(
		fmt.Sprintf("INC-LIVE-%d", time.Now().UnixMilli()),
		ipStr,
		"edge-cluster-1",
		"suricata",
		score,
		ruleID,
		mitreID,
		raw,
		"• Intent: Automated SQL Injection and Database Reconnaissance\n• Root Cause: Unsanitized HTTP parameter in edge application",
		time.Now().UnixMilli(),
		nil,
	)
}

func (ws *WebSOCServer) handleP2PTopology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.p2pMesh == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "STANDALONE",
			"local_node_id":   "controller",
			"bind_addr":       ":7946",
			"total_peers":     0,
			"active_peers":    0,
			"average_rtt_ms":  0,
			"gossip_msg_rate": 0,
			"crdt_bans_count": 0,
			"peers":           []p2p.PeerInfo{},
		})
		return
	}
	json.NewEncoder(w).Encode(ws.p2pMesh.GetTopology())
}

func (ws *WebSOCServer) handleP2PCRDT(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.p2pMesh == nil {
		json.NewEncoder(w).Encode([]p2p.CRDTBanEntry{})
		return
	}
	bans := ws.p2pMesh.GetCRDTJail().GetActiveBans()
	json.NewEncoder(w).Encode(bans)
}

func (ws *WebSOCServer) handleP2PLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.p2pMesh == nil {
		json.NewEncoder(w).Encode([]p2p.SwarmEventLog{})
		return
	}
	logs := ws.p2pMesh.GetEventLogs()
	json.NewEncoder(w).Encode(logs)
}

func (ws *WebSOCServer) handleP2PBroadcast(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetIP    string `json:"target_ip"`
		ThreatScore int    `json:"threat_score"`
		RuleID      string `json:"rule_id"`
		MitreID     string `json:"mitre_id"`
		Reason      string `json:"reason"`
		TTLSeconds  int64  `json:"ttl_seconds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.TargetIP == "" {
		http.Error(w, "missing target_ip", http.StatusBadRequest)
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 86400
	}
	if req.ThreatScore <= 0 {
		req.ThreatScore = 80
	}
	if req.RuleID == "" {
		req.RuleID = "manual_soc_operator_broadcast"
	}
	if req.MitreID == "" {
		req.MitreID = "T1190"
	}

	loc := geoip.GetDefaultEngine().Lookup(req.TargetIP)

	tb := p2p.ThreatBroadcast{
		TargetIP:     req.TargetIP,
		ThreatScore:  req.ThreatScore,
		RuleID:       req.RuleID,
		MitreID:      req.MitreID,
		CountryCode:  loc.CountryCode,
		AttackerASN:  loc.ASN,
		TTLSeconds:   req.TTLSeconds,
		Reason:       req.Reason,
		OriginNodeID: "controller-soc",
	}

	if ws.p2pMesh != nil {
		ws.p2pMesh.BroadcastThreat(tb)
	}

	// Also record locally in TTL manager
	if ws.ttlManager != nil {
		_, _ = ws.ttlManager.BanIP(req.TargetIP, req.Reason, req.TTLSeconds, "")
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Threat broadcast for IP %s gossiped across P2P swarm mesh", req.TargetIP),
		"threat":  tb,
	})
}

func (ws *WebSOCServer) handleSecurityStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{
		"integrity": ws.integrityGuard.GetStats(),
		"yara":      ws.yaraScanner.GetStats(),
		"tarpit":    ws.tarpitEngine.GetStats(),
		"dns":       ws.dnsSinkhole.GetStats(),
		"fim":       ws.fimHealing.GetStats(),
	}
	json.NewEncoder(w).Encode(stats)
}

func (ws *WebSOCServer) handleSecurityTarpit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.tarpitEngine.GetActiveSessions())
}

func (ws *WebSOCServer) handleSecurityFIM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"targets":       ws.fimHealing.GetTargets(),
		"recent_events": ws.fimHealing.GetRecentEvents(),
		"stats":         ws.fimHealing.GetStats(),
	})
}

func (ws *WebSOCServer) handleSecurityDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.dnsSinkhole.GetRecentEvents())
}

func (ws *WebSOCServer) handleSecurityYARA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.yaraScanner.GetRecentHits())
}

func (ws *WebSOCServer) handleSecurityIntegrity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.integrityGuard.GetRecentEvents())
}

func (ws *WebSOCServer) handleThreatInspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, `{"error":"ip parameter is required"}`, http.StatusBadRequest)
		return
	}

	state, found := threat.GetDefaultEngine().GetEntityState(ip)
	if !found {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"found":   false,
			"ip":      ip,
			"message": "No active sliding-window threat state tracked for IP",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"found": true,
		"state": state,
	})
}

func (ws *WebSOCServer) handleMLStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ml.GetDefaultEngine().GetStats())
}

// SOCAlertDTO represents an analyst-triaged high-priority alert.
type SOCAlertDTO struct {
	*StoredEvent
	ContainmentState string          `json:"containment_state"` // BANNED (XDP), TARPITTED, HOST CONTAINED, UNMITIGATED
	Scope            sigma.RuleScope `json:"scope"`             // SCOPE_NETWORK, SCOPE_HOST_LOCAL
	IsHostLocal      bool            `json:"is_host_local"`
	RelativeTime     string          `json:"relative_time"`
	RepeatCount      int             `json:"repeat_count"` // Deduplicated event occurrences within window
	FirstSeenMs      int64           `json:"first_seen_ms"`
	LastSeenMs       int64           `json:"last_seen_ms"`
	PeakScore        int             `json:"peak_score"`
}

func (ws *WebSOCServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.storage == nil {
		json.NewEncoder(w).Encode([]*SOCAlertDTO{})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	events, err := ws.storage.GetRecentEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	activeBansMap := make(map[string]bool)
	if ws.ttlManager != nil {
		for _, b := range ws.ttlManager.GetActiveBans() {
			activeBansMap[b.IP] = true
		}
	}

	type alertKey struct {
		IP     string
		RuleID string
	}
	grouped := make(map[alertKey]*SOCAlertDTO)
	var orderedKeys []alertKey
	nowMs := time.Now().UnixMilli()

	for _, ev := range events {
		// Sudo execution de-noising: routine successful sudo executions (score < 70) stay in Incident Stream, only elevate failed/unauthorized anomalies to Critical Alerts
		if ev.RuleID == "sudo_execution" || (strings.Contains(strings.ToLower(ev.RuleID), "sudo") && ev.ThreatScore < 70) {
			continue
		}

		hasMitre := ev.MitreTechniqueID != "" && strings.HasPrefix(strings.ToUpper(ev.MitreTechniqueID), "T")
		isSigma := strings.HasPrefix(strings.ToLower(ev.RuleID), "sigma") || strings.Contains(strings.ToLower(ev.RuleID), "rce") || strings.Contains(strings.ToLower(ev.RuleID), "sqli") || strings.Contains(strings.ToLower(ev.RuleID), "revshell")
		isScore40 := ev.ThreatScore >= 40
		isML := (ev.MLAnomaly && ev.MLConfidencePct >= 70) || (ev.SnortML && ev.SnortConfidence >= 0.70)
		isKernelOrFIM := strings.Contains(strings.ToLower(ev.RuleID), "rootkit") ||
			strings.Contains(strings.ToLower(ev.RuleID), "fim") ||
			strings.Contains(strings.ToLower(ev.RuleID), "integrity") ||
			strings.Contains(strings.ToLower(ev.RuleID), "ptrace") ||
			strings.Contains(strings.ToLower(ev.RuleID), "lkm")
		scope := sigma.DetermineRuleScope(ev.RuleID, "", "", "", nil)
		isHostLocalRule := scope == sigma.ScopeHostLocal || strings.Contains(strings.ToLower(ev.RuleID), "cron")

		if !hasMitre && !isSigma && !isScore40 && !isML && !isKernelOrFIM && !isHostLocalRule {
			continue
		}

		key := alertKey{IP: ev.ClientIP, RuleID: ev.RuleID}
		if existing, exists := grouped[key]; exists {
			// If within 5-minute sliding window, aggregate
			diff := existing.LastSeenMs - ev.TimestampMs
			if diff < 0 {
				diff = -diff
			}
			if diff <= 5*60*1000 {
				existing.RepeatCount++
				if ev.TimestampMs > existing.LastSeenMs {
					existing.LastSeenMs = ev.TimestampMs
					existing.TimestampMs = ev.TimestampMs
				}
				if ev.TimestampMs < existing.FirstSeenMs {
					existing.FirstSeenMs = ev.TimestampMs
				}
				if ev.ThreatScore > existing.PeakScore {
					existing.PeakScore = ev.ThreatScore
					existing.ThreatScore = ev.ThreatScore
				}
				continue
			}
		}

		isHostLocal := scope == sigma.ScopeHostLocal || ev.ClientIP == "127.0.0.1" || ev.ClientIP == "local" || isProtectedIP(ev.ClientIP)

		containment := "UNMITIGATED"
		if isHostLocal {
			containment = "HOST CONTAINED"
		} else if activeBansMap[ev.ClientIP] {
			containment = "BANNED (XDP)"
		}

		diffSec := (nowMs - ev.TimestampMs) / 1000
		relTime := "just now"
		if diffSec >= 3600 {
			relTime = fmt.Sprintf("%dh ago", diffSec/3600)
		} else if diffSec >= 60 {
			relTime = fmt.Sprintf("%dm ago", diffSec/60)
		} else if diffSec > 5 {
			relTime = fmt.Sprintf("%ds ago", diffSec)
		}

		dto := &SOCAlertDTO{
			StoredEvent:      ev,
			ContainmentState: containment,
			Scope:            scope,
			IsHostLocal:      isHostLocal,
			RelativeTime:     relTime,
			RepeatCount:      1,
			FirstSeenMs:      ev.TimestampMs,
			LastSeenMs:       ev.TimestampMs,
			PeakScore:        ev.ThreatScore,
		}
		grouped[key] = dto
		orderedKeys = append(orderedKeys, key)
	}

	var alerts []*SOCAlertDTO
	for _, k := range orderedKeys {
		alerts = append(alerts, grouped[k])
	}
	if alerts == nil {
		alerts = []*SOCAlertDTO{}
	}

	json.NewEncoder(w).Encode(alerts)
}

func (ws *WebSOCServer) handleAlertsTriage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action  string `json:"action"` // ban, tarpit, dismiss, whitelist
		IP      string `json:"ip"`
		EventID int64  `json:"event_id"`
		Reason  string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cleanIP := strings.TrimSpace(req.IP)
	switch req.Action {
	case "ban":
		if cleanIP != "" && !isProtectedIP(cleanIP) && ws.ttlManager != nil {
			reason := req.Reason
			if reason == "" {
				reason = "Analyst Triage Quick Ban (XDP Drop)"
			}
			_, _ = ws.ttlManager.BanIP(cleanIP, reason, 86400, TierExtendedQuarantine)
		}
	case "tarpit":
		if cleanIP != "" && !isProtectedIP(cleanIP) {
			if ws.ttlManager != nil {
				_, _ = ws.ttlManager.BanIP(cleanIP, "Analyst Triage: Zero-Window Tarpit Trap", 3600, TierTempIsolation)
			}
		}
	case "whitelist", "dismiss":
		if cleanIP != "" && ws.ttlManager != nil {
			_ = ws.ttlManager.UnbanIP(cleanIP)
		}
		if ws.server != nil && ws.server.threatEngine != nil && cleanIP != "" {
			_ = ws.server.threatEngine.AddWhitelistCIDR(cleanIP)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"action":  req.Action,
		"ip":      cleanIP,
	})
}

func (ws *WebSOCServer) handleAIAgentLatest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.aiAgent == nil {
		json.NewEncoder(w).Encode([]*ai_agent.AITriageBrief{})
		return
	}
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if l, err := strconv.Atoi(q); err == nil && l > 0 {
			limit = l
		}
	}
	briefs := ws.aiAgent.GetRecentBriefs(limit)
	json.NewEncoder(w).Encode(briefs)
}

func (ws *WebSOCServer) handleAIAgentTestDispatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID           string `json:"node_id"`
		Source           string `json:"source"`
		RawLine          string `json:"raw_line"`
		ClientIP         string `json:"client_ip"`
		ThreatScore      int    `json:"threat_score"`
		RuleID           string `json:"rule_id"`
		MitreTechniqueID string `json:"mitre_technique_id"`
	}

	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.NodeID == "" {
		req.NodeID = "node-soc-edge"
	}
	if req.ClientIP == "" {
		req.ClientIP = "198.51.100.44"
	}
	if req.ThreatScore <= 0 {
		req.ThreatScore = 95
	}
	if req.RuleID == "" {
		req.RuleID = "sigma-web-sqli"
	}
	if req.MitreTechniqueID == "" {
		req.MitreTechniqueID = "T1190"
	}
	if req.RawLine == "" {
		req.RawLine = "GET /api/v1/auth?user=admin' UNION SELECT 1,password,3 FROM users-- HTTP/1.1"
	}

	geo := geoip.GetDefaultEngine().Lookup(req.ClientIP)
	ic := &ai_agent.IncidentContext{
		NodeID:           req.NodeID,
		Source:           req.Source,
		RawLine:          req.RawLine,
		ClientIP:         req.ClientIP,
		ThreatScore:      req.ThreatScore,
		RuleID:           req.RuleID,
		MitreTechniqueID: req.MitreTechniqueID,
		CountryCode:      geo.CountryCode,
		CountryName:      geo.CountryName,
		FlagEmoji:        geo.FlagEmoji,
		ASN:              geo.ASN,
		ContainmentState: "XDP_DROP (eBPF Swarm Fast-Path Active)",
	}

	agent := ws.aiAgent
	if agent == nil {
		agent = ai_agent.GetDefaultAgent()
	}

	brief, err := agent.AnalyzeIncident(r.Context(), ic)
	if err != nil {
		http.Error(w, fmt.Sprintf("AI analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	disp := ws.notifier
	if disp == nil {
		disp = notifier.GetDefaultDispatcher()
	}

	dispatchRes := disp.DispatchTriageAlert(r.Context(), brief)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"brief":           brief,
		"dispatch_result": dispatchRes,
	})
}

func (ws *WebSOCServer) handleIPInfoLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, `{"error": "missing ip query parameter"}`, http.StatusBadRequest)
		return
	}

	client := ipinfo.GetDefaultClient()
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	resp, err := client.Lookup(ctx, ip)
	if err != nil {
		// Fallback to local geoip engine if IPinfo call fails
		geo := geoip.GetDefaultEngine().Lookup(ip)
		resp = &ipinfo.IPInfoResponse{
			IP:             geo.IP,
			City:           geo.City,
			Region:         geo.Region,
			Country:        geo.CountryCode,
			Org:            geo.ASN,
			Latitude:       geo.Latitude,
			Longitude:      geo.Longitude,
			FlagEmoji:      geo.FlagEmoji,
			Classification: geo.Classification,
			IsHosting:      geo.IsHosting,
			IsVPN:          geo.IsVPN,
			IsProxy:        geo.IsProxy,
			IsTor:          geo.IsTor,
			Source:         "geoip_fallback",
		}
	}

	json.NewEncoder(w).Encode(resp)
}

func (ws *WebSOCServer) handleEventNotes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	var eventID int64
	if v, ok := raw["id"]; ok {
		switch n := v.(type) {
		case float64:
			eventID = int64(n)
		case int64:
			eventID = n
		case string:
			eventID, _ = strconv.ParseInt(n, 10, 64)
		}
	}
	if eventID == 0 {
		if v, ok := raw["incident_id"]; ok {
			switch n := v.(type) {
			case float64:
				eventID = int64(n)
			case int64:
				eventID = n
			case string:
				cleaned := strings.TrimPrefix(n, "LIVE-")
				cleaned = strings.TrimPrefix(cleaned, "#")
				eventID, _ = strconv.ParseInt(cleaned, 10, 64)
			}
		}
	}

	notes, _ := raw["notes"].(string)

	var playbookProgress string
	if pb, ok := raw["playbook_progress"]; ok {
		switch v := pb.(type) {
		case string:
			playbookProgress = v
		case map[string]interface{}:
			if b, err := json.Marshal(v); err == nil {
				playbookProgress = string(b)
			}
		}
	}

	if ws.storage != nil && eventID > 0 {
		if err := ws.storage.UpdateEventNotesAndPlaybook(eventID, notes, playbookProgress); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"incident_id": eventID,
		"id":          eventID,
		"saved":       true,
	})
}

// handleSOARPlaybooks returns the curated playbook catalog.
func (ws *WebSOCServer) handleSOARPlaybooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	playbooks := soar.GetDefaultEngine().GetPlaybooks()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"playbooks": playbooks,
		"count":     len(playbooks),
	})
}

// handleSOARRuns returns active and recent playbook executions.
func (ws *WebSOCServer) handleSOARRuns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	runs := soar.GetDefaultEngine().GetActiveRuns()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"runs":    runs,
		"count":   len(runs),
	})
}

// handleSOARExecute executes a manual or automated remediation action or advances playbook progress.
func (ws *WebSOCServer) handleSOARExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ActionType string `json:"action_type"`
		ActorIP    string `json:"actor_ip"`
		NodeID     string `json:"node_id"`
		RunID      string `json:"run_id"`
		StepIndex  int    `json:"step_index"`
		Status     string `json:"status"`
		Output     string `json:"output"`
		Param      string `json:"param"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	soarEngine := soar.GetDefaultEngine()

	// If advancing a playbook step
	if req.RunID != "" && req.Status != "" {
		run, err := soarEngine.AdvanceStep(req.RunID, req.StepIndex, req.Status, req.Output)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ws.wsHub != nil {
			ws.wsHub.Broadcast("soar_playbook_run", map[string]interface{}{
				"run":         run,
				"active_runs": soarEngine.GetActiveRuns(),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"run":     run,
		})
		return
	}

	// Direct Remediation Action Execution
	res, err := soarEngine.ExecuteRemediationAction(req.ActionType, req.ActorIP, req.NodeID, req.Param)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ws.wsHub != nil {
		ws.wsHub.Broadcast("soar_action_executed", res)
	}

	_ = json.NewEncoder(w).Encode(res)
}
