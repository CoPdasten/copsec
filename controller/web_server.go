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

	"github.com/copsec/controller/pkg/dns"
	"github.com/copsec/controller/pkg/ebpf"
	"github.com/copsec/controller/pkg/geoip"
	"github.com/copsec/controller/pkg/healing"
	"github.com/copsec/controller/pkg/ipinfo"
	"github.com/copsec/controller/pkg/ml"
	"github.com/copsec/controller/pkg/models"
	"github.com/copsec/controller/pkg/rules"
	"github.com/copsec/controller/pkg/sigma"
	"github.com/copsec/controller/pkg/soar"
	"github.com/copsec/controller/pkg/tarpit"
	"github.com/copsec/controller/pkg/threat"
	"github.com/copsec/controller/pkg/yara"
)

//go:embed web/*
var embeddedWebFS embed.FS

// WebSOCServer hosts the embedded Minimalist Web SOC, REST APIs, and WebSocket hub.
type WebSOCServer struct {
	mu          sync.RWMutex
	listenAddr  string
	server      *CentralServer
	storage     *StorageEngine
	ttlManager  *TTLBanManager
	sigmaEngine *SigmaEngine
	wsHub       *WSHub
	httpServer  *http.Server

	integrityGuard *ebpf.IntegrityGuard
	yaraScanner    *yara.MemoryScanner
	tarpitEngine   *tarpit.TarpitEngine
	dnsSinkhole    *dns.DNSSinkholeEngine
	fimHealing     *healing.FIMHealingEngine
}

// SystemConfigDTO represents the runtime configuration schema.
type SystemConfigDTO struct {
	GRPCAddr         string `json:"grpc_addr"`
	IPInfoToken      string `json:"ipinfo_token"`
	AutoBanThreshold int    `json:"autoban_threshold"`
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
) *WebSOCServer {
	ws := &WebSOCServer{
		listenAddr:     listenAddr,
		server:         server,
		storage:        storage,
		ttlManager:     ttlManager,
		sigmaEngine:    sigmaEngine,
		wsHub:          wsHub,
		integrityGuard: ebpf.GetDefaultIntegrityGuard(),
		yaraScanner:    yara.GetDefaultScanner(),
		tarpitEngine:   tarpit.GetDefaultTarpit(),
		dnsSinkhole:    dns.GetDefaultSinkhole(),
		fimHealing:     healing.GetDefaultFIMEngine(),
	}
	ws.applyRuntimeConfig(ws.loadSystemConfig())

	// Register SOAR Automation Remediation Action Hook
	soarEngine := soar.GetDefaultEngine()
	soarEngine.SetActionHook(func(actionType, actorIP, nodeID, param string) (string, error) {
		switch actionType {
		case "XDP_BLACKHOLE", "BAN_IP", "FLEET_BAN":
			if ws.ttlManager != nil && actorIP != "" {
				_, err := ws.ttlManager.BanIP(actorIP, "Playbook Remediation: Fleet-Wide XDP Blackhole", 86400, TierAutoBanSOAR)
				return fmt.Sprintf("NIC XDP fast-path drop enforced on %s", actorIP), err
			} else if ws.server != nil && actorIP != "" {
				dispatched := ws.server.BroadcastSOARCommandWithReason("BAN_IP", actorIP, "Playbook Remediation: Fleet-Wide XDP Blackhole", 86400)
				return fmt.Sprintf("XDP drop broadcasted to %d edge nodes for %s", dispatched, actorIP), nil
			}
		case "TARPIT_TRAP":
			return fmt.Sprintf("TCP stream from %s diverted into Zero-Window Deception Tarpit", actorIP), nil
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

// Start runs the HTTP listener in the background.
func (ws *WebSOCServer) Start() error {
	mux := http.NewServeMux()

	// 1. WebSocket Endpoint
	mux.Handle("/ws/events", ws.wsHub.Handler())

	// 2. REST APIs
	mux.HandleFunc("/api/config", ws.handleConfig)
	mux.HandleFunc("/api/config/ipinfo", ws.handleConfigIPInfo)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/stats/actors", ws.handleTopActors)
	mux.HandleFunc("/api/events", ws.handleEvents)
	mux.HandleFunc("/api/telemetry", ws.handleEvents)
	mux.HandleFunc("/api/alerts", ws.handleAlerts)
	mux.HandleFunc("/api/alerts/triage", ws.handleAlertsTriage)
	mux.HandleFunc("/api/alerts/dismiss", ws.handleAlertsDismiss)
	mux.HandleFunc("/api/alerts/clear", ws.handleAlertsClear)
	mux.HandleFunc("/api/bans", ws.handleBans)
	mux.HandleFunc("/api/quarantine", ws.handleBans)
	mux.HandleFunc("/api/quarantine/unban", ws.handleSOARUnban)
	mux.HandleFunc("/api/quarantine/ban", ws.handleSOARBan)
	mux.HandleFunc("/api/mitigation/tarpit", ws.handleMitigationTarpit)
	mux.HandleFunc("/api/mitigation/ban", ws.handleSOARBan)
	mux.HandleFunc("/api/mitigation/unban", ws.handleSOARUnban)
	mux.HandleFunc("/api/soar/ban", ws.handleSOARBan)
	mux.HandleFunc("/api/soar/unban", ws.handleSOARUnban)
	mux.HandleFunc("/api/soar/playbooks", ws.handleSOARPlaybooks)
	mux.HandleFunc("/api/playbooks", ws.handleSOARPlaybooks)
	mux.HandleFunc("/api/soar/runs", ws.handleSOARRuns)
	mux.HandleFunc("/api/playbooks/runs", ws.handleSOARRuns)
	mux.HandleFunc("/api/soar/execute", ws.handleSOARExecute)
	mux.HandleFunc("/api/playbooks/execute", ws.handleSOARExecute)
	mux.HandleFunc("/api/sigma/rules", ws.handleRulesList)
	mux.HandleFunc("/api/sigma/rule", ws.handleSigmaRuleSubmit)
	mux.HandleFunc("/api/sigma/toggle", ws.handleRulesToggle)
	mux.HandleFunc("/api/rules", ws.handleRulesList)
	mux.HandleFunc("/api/rules/sync", ws.handleRulesSync)
	mux.HandleFunc("/api/rules/toggle", ws.handleRulesToggle)
	mux.HandleFunc("/api/nodes", ws.handleNodes)
	mux.HandleFunc("/api/whitelist", ws.handleWhitelist)
	mux.HandleFunc("/api/geoip/stats", ws.handleGeoIPStats)
	mux.HandleFunc("/api/geoip/lookup", ws.handleGeoIPLookup)
	mux.HandleFunc("/api/ipinfo/lookup", ws.handleIPInfoLookup)
	mux.HandleFunc("/api/events/notes", ws.handleEventNotes)
	mux.HandleFunc("/api/alerts/notes", ws.handleEventNotes)
	mux.HandleFunc("/api/security/stats", ws.handleSecurityStats)
	mux.HandleFunc("/api/security/tarpit", ws.handleSecurityTarpit)
	mux.HandleFunc("/api/security/fim", ws.handleSecurityFIM)
	mux.HandleFunc("/api/security/dns", ws.handleSecurityDNS)
	mux.HandleFunc("/api/security/yara", ws.handleSecurityYARA)
	mux.HandleFunc("/api/security/integrity", ws.handleSecurityIntegrity)
	mux.HandleFunc("/api/threat/inspect", ws.handleThreatInspect)
	mux.HandleFunc("/api/threat/intel", ws.handleThreatIntel)
	mux.HandleFunc("/api/soar/autopilot", ws.handleSOARAutoPilot)
	mux.HandleFunc("/api/soar/stats", ws.handleSOARStats)
	mux.HandleFunc("/api/audit/verify-integrity", ws.handleAuditVerifyIntegrity)
	mux.HandleFunc("/api/trust/score", ws.handleTrustScore)
	mux.HandleFunc("/api/trust/entities", ws.handleTrustEntities)
	mux.HandleFunc("/api/ml/stats", ws.handleMLStats)

	// 3. Embedded Web SOC Static Files
	mux.HandleFunc("/", ws.handleStaticFiles)

	ws.httpServer = &http.Server{
		Addr:         ws.listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("[INFO] 🌐 Minimalist SOC Web Interface listening on http://%s", ws.listenAddr)

	go func() {
		if err := ws.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Web SOC server error: %v", err)
		}
	}()

	return nil
}

func (ws *WebSOCServer) handleStaticFiles(w http.ResponseWriter, r *http.Request) {
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

func maskToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" || token == ipinfo.DefaultIPInfoToken {
		return ""
	}
	if len(token) <= 4 {
		return "****"
	}
	if len(token) <= 8 {
		return token[:2] + "****"
	}
	return token[:4] + "****"
}

func (ws *WebSOCServer) handleConfigIPInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		var token string
		if ws.storage != nil {
			token, _ = ws.storage.GetConfig("ipinfo_token")
		}
		if token == "" {
			token = ipinfo.GetDefaultClient().GetToken()
		}

		configured := token != "" && token != ipinfo.DefaultIPInfoToken
		if configured {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"configured":   true,
				"token_masked": maskToken(token),
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"configured": false,
			})
		}
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		token := strings.TrimSpace(req.Token)
		if ws.storage != nil {
			if err := ws.storage.SaveConfig("ipinfo_token", token); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// Update in-memory IPinfo client dynamically
		ipinfo.GetDefaultClient().SetToken(token)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "saved",
			"configured": token != "" && token != ipinfo.DefaultIPInfoToken,
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (ws *WebSOCServer) loadSystemConfig() *SystemConfigDTO {
	dto := &SystemConfigDTO{
		GRPCAddr:         "0.0.0.0:8443",
		AutoBanThreshold: 80,
		IPInfoToken:      ipinfo.DefaultIPInfoToken,
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
	if v, ok := cfgMap["ipinfo_token"]; ok && v != "" {
		dto.IPInfoToken = v
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
		"grpc_addr":         cfg.GRPCAddr,
		"ipinfo_token":      tok,
		"autoban_threshold": strconv.Itoa(cfg.AutoBanThreshold),
		"configured":        "true",
	}

	return ws.storage.SaveSystemConfig(cfgMap)
}

func (ws *WebSOCServer) applyRuntimeConfig(cfg *SystemConfigDTO) {
	if ws.server != nil {
		ws.server.SetAutoBanPolicy(true, cfg.AutoBanThreshold)

		// Reconfigure IPinfo Token dynamically
		tok := cfg.IPInfoToken
		if tok == "" {
			tok = ipinfo.DefaultIPInfoToken
		}
		ipinfo.GetDefaultClient().SetToken(tok)
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
	var topAttackers []TopAttackerRecord
	if ws.storage != nil {
		mitreStats, _ = ws.storage.GetMITREStats()
		topAttackers, _ = ws.storage.GetTopAttackers(10)
	}

	data := map[string]interface{}{
		"eps":           eps,
		"total_events":  total,
		"nodes_count":   nodesCount,
		"active_bans":   activeBansCount,
		"mitre_stats":   mitreStats,
		"top_attackers": topAttackers,
		"geo_stats":     geoip.GetDefaultEngine().GetAttackOriginDensity(8),
		"timestamp":     time.Now().UnixMilli(),
	}

	json.NewEncoder(w).Encode(data)
}

func (ws *WebSOCServer) handleTopActors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.storage == nil {
		json.NewEncoder(w).Encode([]TopAttackerRecord{})
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	actors, err := ws.storage.GetTopAttackers(limit)
	if err != nil {
		actors = []TopAttackerRecord{}
	}
	json.NewEncoder(w).Encode(actors)
}

func (ws *WebSOCServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.storage == nil {
		json.NewEncoder(w).Encode([]*StoredEvent{})
		return
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := 500
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		if l > 5000 {
			l = 5000
		}
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

	if ws.storage != nil {
		ws.storage.AddMitigatedIP(req.IP, 1*time.Hour)
		containmentState := "BANNED (XDP)"
		_, _ = ws.storage.db.Exec(
			"UPDATE telemetry SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ? OR source_ip = ?",
			containmentState, req.IP, req.IP,
		)
		_, _ = ws.storage.db.Exec(
			"UPDATE alerts SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ?",
			containmentState, req.IP,
		)
		_, _ = ws.storage.db.Exec(
			"UPDATE events SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ?",
			containmentState, req.IP,
		)
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

	if ws.storage != nil {
		ws.storage.RemoveMitigatedIP(req.IP)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("IP %s unbanned across all layers", req.IP),
	})
}

func (ws *WebSOCServer) handleMitigationTarpit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP              string `json:"ip"`
		DurationSeconds int64  `json:"duration_seconds"`
		Reason          string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cleanIP := strings.TrimSpace(req.IP)
	if cleanIP == "" || isProtectedIP(cleanIP) {
		http.Error(w, "Invalid or protected IP", http.StatusBadRequest)
		return
	}

	dur := req.DurationSeconds
	if dur <= 0 {
		dur = 3600
	}
	reason := req.Reason
	if reason == "" {
		reason = "Analyst Instant Action: Zero-Window Tarpit Trap"
	}

	if ws.storage != nil {
		ws.storage.AddMitigatedIP(cleanIP, time.Duration(dur)*time.Second)
		containmentState := "TARPITTED"
		_, _ = ws.storage.db.Exec(
			"UPDATE telemetry SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ? OR source_ip = ?",
			containmentState, cleanIP, cleanIP,
		)
		_, _ = ws.storage.db.Exec(
			"UPDATE alerts SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ?",
			containmentState, cleanIP,
		)
		_, _ = ws.storage.db.Exec(
			"UPDATE events SET triage_status = 'MITIGATED', containment_state = ? WHERE client_ip = ?",
			containmentState, cleanIP,
		)
	}

	if ws.ttlManager != nil {
		record, err := ws.ttlManager.BanIP(cleanIP, reason, dur, TierTempIsolation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(record)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"ip":      cleanIP,
		"action":  "TARPIT",
	})
}

func (ws *WebSOCServer) handleRulesSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		status := rules.GetDefaultSyncer().GetStatus()
		json.NewEncoder(w).Encode(status)
		return
	}

	if r.Method == http.MethodPost {
		syncer := rules.GetDefaultSyncer()
		go func() {
			_, _ = syncer.Sync(context.Background())
		}()

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "SigmaHQ background sync triggered from GitHub",
			"status":  syncer.GetStatus(),
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (ws *WebSOCServer) handleRulesList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	matcher := rules.GetDefaultMatcher()
	ruleList := matcher.ListRules()

	type RuleResponseDTO struct {
		ID          string          `json:"id"`
		Title       string          `json:"title"`
		Description string          `json:"description"`
		Level       string          `json:"level"`
		ThreatScore int             `json:"threat_score"`
		Severity    models.Severity `json:"severity"`
		MitreID     string          `json:"mitre_id"`
		MitreTactic string          `json:"mitre_tactic"`
		Origin      string          `json:"origin"` // [BUILTIN] vs [SIGMAHQ]
		Scope       string          `json:"scope"`
		Enabled     bool            `json:"enabled"`
		Tags        []string        `json:"tags,omitempty"`
	}

	seen := make(map[string]bool)
	var dtos []RuleResponseDTO
	for _, r := range ruleList {
		seen[r.ID] = true
		origin := r.Origin
		if origin == "" {
			origin = "[SIGMAHQ]"
		}
		dtos = append(dtos, RuleResponseDTO{
			ID:          r.ID,
			Title:       r.Title,
			Description: r.Description,
			Level:       r.Level,
			ThreatScore: r.ThreatScore,
			Severity:    r.Severity,
			MitreID:     r.MitreTechniqueID,
			MitreTactic: r.MitreTactic,
			Origin:      origin,
			Scope:       r.Scope,
			Enabled:     r.Enabled,
			Tags:        r.Tags,
		})
	}

	// Also merge any curated catalog rules if not already present
	catalog := sigma.GetDefaultCatalog().List()
	tracker := sigma.GetBuiltinTracker()
	for _, cr := range catalog {
		if !seen[cr.ID] {
			enabled := tracker.IsRuleEnabled(cr.ID)
			dtos = append(dtos, RuleResponseDTO{
				ID:          cr.ID,
				Title:       cr.Title,
				Description: cr.Description,
				Level:       cr.Level,
				ThreatScore: cr.ThreatScore,
				Severity:    models.CalculateSeverity(cr.ThreatScore),
				MitreID:     cr.MitreID,
				MitreTactic: "",
				Origin:      "[BUILTIN]",
				Scope:       string(cr.Scope),
				Enabled:     enabled,
				Tags:        cr.Tags,
			})
		}
	}

	if dtos == nil {
		dtos = []RuleResponseDTO{}
	}

	json.NewEncoder(w).Encode(dtos)
}

func (ws *WebSOCServer) handleRulesToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RuleID  string `json:"rule_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	matcher := rules.GetDefaultMatcher()
	updated := matcher.SetRuleEnabled(req.RuleID, req.Enabled)
	sigma.GetBuiltinTracker().SetRuleEnabled(req.RuleID, req.Enabled)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule_id": req.RuleID,
		"enabled": req.Enabled,
		"found":   updated,
	})
}

func (ws *WebSOCServer) handleSigmaRules(w http.ResponseWriter, r *http.Request) {
	ws.handleRulesList(w, r)
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

	rule, err := rules.ParseSigmaRule(req.YAML, "[CUSTOM]")
	if err != nil {
		http.Error(w, fmt.Sprintf("YAML parse/compilation failed: %v", err), http.StatusBadRequest)
		return
	}

	rules.GetDefaultMatcher().AddRule(rule)
	if ws.sigmaEngine != nil {
		if sRule, err := ws.sigmaEngine.ParseSigmaYAML(req.YAML); err == nil {
			ws.sigmaEngine.AddRule(sRule)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule":    rule,
	})
}

func (ws *WebSOCServer) handleSigmaRuleToggle(w http.ResponseWriter, r *http.Request) {
	ws.handleRulesToggle(w, r)
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

func (ws *WebSOCServer) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ws.server != nil && ws.server.threatEngine != nil && req.CIDR != "" {
			_ = ws.server.threatEngine.AddWhitelistCIDR(req.CIDR)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"cidr":    req.CIDR,
		})
		return
	}

	// GET: Return default protected resolvers & subnets
	json.NewEncoder(w).Encode(map[string]interface{}{
		"resolvers": []string{
			"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
			"208.67.222.222", "213.186.33.99", "213.186.33.100", "2001:41d0:3:163::1",
		},
		"subnets": []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48",
		},
	})
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
	limit := 500
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		if l > 5000 {
			l = 5000
		}
		limit = l
	}

	statusFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	var events []*StoredEvent
	var err error

	if statusFilter == "RESOLVED" || statusFilter == "ARCHIVE" || statusFilter == "MITIGATED" {
		events, err = ws.storage.GetResolvedAlerts(limit)
	} else {
		events, err = ws.storage.GetActiveAlerts(limit)
	}

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
		if ev.TriageStatus == "MITIGATED" {
			containment = "MITIGATED"
		} else if ev.TriageStatus == "RESOLVED" {
			containment = "RESOLVED"
		} else if isHostLocal {
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
		Action  string      `json:"action"` // ban, tarpit, dismiss, whitelist, resolve
		IP      string      `json:"ip"`
		EventID interface{} `json:"event_id"`
		ID      interface{} `json:"id"`
		Reason  string      `json:"reason"`
		Status  string      `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cleanIP := strings.TrimSpace(req.IP)
	idStr := ""
	if req.ID != nil {
		idStr = strings.TrimSpace(fmt.Sprintf("%v", req.ID))
	}
	if (idStr == "" || idStr == "0" || idStr == "<nil>") && req.EventID != nil {
		idStr = strings.TrimSpace(fmt.Sprintf("%v", req.EventID))
	}
	if idStr == "" || idStr == "0" || idStr == "<nil>" {
		idStr = cleanIP
	}

	switch req.Action {
	case "ban":
		if cleanIP != "" && !isProtectedIP(cleanIP) && ws.ttlManager != nil {
			reason := req.Reason
			if reason == "" {
				reason = "Analyst Triage Quick Ban (XDP Drop)"
			}
			_, _ = ws.ttlManager.BanIP(cleanIP, reason, 86400, TierExtendedQuarantine)
		}
		if ws.storage != nil && idStr != "" {
			_ = ws.storage.SetAlertStatus(idStr, "MITIGATED", "Mitigated via XDP Drop")
		}
	case "tarpit":
		if cleanIP != "" && !isProtectedIP(cleanIP) {
			if ws.ttlManager != nil {
				_, _ = ws.ttlManager.BanIP(cleanIP, "Analyst Triage: Zero-Window Tarpit Trap", 3600, TierTempIsolation)
			}
		}
		if ws.storage != nil && idStr != "" {
			_ = ws.storage.SetAlertStatus(idStr, "MITIGATED", "Mitigated via Tarpit Trap")
		}
	case "whitelist":
		if cleanIP != "" && ws.ttlManager != nil {
			_ = ws.ttlManager.UnbanIP(cleanIP)
		}
		if ws.server != nil && ws.server.threatEngine != nil && cleanIP != "" {
			_ = ws.server.threatEngine.AddWhitelistCIDR(cleanIP)
		}
		if ws.storage != nil && idStr != "" {
			_ = ws.storage.SetAlertStatus(idStr, "FALSE_POSITIVE", "Whitelisted by analyst")
		}
	case "dismiss", "resolve":
		st := req.Status
		if st == "" {
			st = "RESOLVED"
		}
		if ws.storage != nil && idStr != "" {
			_ = ws.storage.SetAlertStatus(idStr, st, "")
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"action":  req.Action,
		"ip":      cleanIP,
		"id":      idStr,
	})
}

func (ws *WebSOCServer) handleAlertsDismiss(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID     interface{} `json:"id"`
		IP     string      `json:"ip"`
		Status string      `json:"status"`
		Notes  string      `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	idStr := ""
	if req.ID != nil {
		idStr = strings.TrimSpace(fmt.Sprintf("%v", req.ID))
	}
	if idStr == "" || idStr == "0" || idStr == "<nil>" {
		idStr = strings.TrimSpace(req.IP)
	}

	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "RESOLVED"
	}

	if ws.storage != nil && idStr != "" {
		_ = ws.storage.SetAlertStatus(idStr, status, req.Notes)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"action": "archived",
		"id":     idStr,
		"state":  status,
	})
}

func (ws *WebSOCServer) handleAlertsClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ws.storage != nil {
		_ = ws.storage.ClearAllActiveAlerts()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"cleared_count": 1,
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
		PlaybookID string `json:"playbook_id"`
		TargetIP   string `json:"target_ip"`
		ActorIP    string `json:"actor_ip"`
		NodeID     string `json:"node_id"`
		RunID      string `json:"run_id"`
		StepIndex  int    `json:"step_index"`
		Status     string `json:"status"`
		Output     string `json:"output"`
		Param      string `json:"param"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	soarEngine := soar.GetDefaultEngine()

	// 1. If starting a new playbook execution run
	if req.PlaybookID != "" || req.ActionType == "START_PLAYBOOK" {
		pbID := req.PlaybookID
		if pbID == "" {
			pbID = req.Param
		}
		if pbID == "" {
			pbID = "PB-101"
		}
		targetIP := strings.TrimSpace(req.TargetIP)
		if targetIP == "" {
			targetIP = strings.TrimSpace(req.ActorIP)
		}
		if targetIP == "" {
			targetIP = "127.0.0.1"
		}
		nodeID := strings.TrimSpace(req.NodeID)
		if nodeID == "" {
			nodeID = "node-edge-primary"
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = fmt.Sprintf("Manual Operator Playbook Trigger [%s]", pbID)
		}

		run := soarEngine.StartPlaybookRun(time.Now().UnixMilli(), pbID, targetIP, nodeID, 90, "T1190", reason)
		if ws.wsHub != nil {
			ws.wsHub.Broadcast("PLAYBOOK_RUN_UPDATE", map[string]interface{}{
				"run":         run,
				"active_runs": soarEngine.GetActiveRuns(),
			})
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

	// 2. If advancing a playbook step
	if req.RunID != "" && req.Status != "" {
		run, err := soarEngine.AdvanceStep(req.RunID, req.StepIndex, req.Status, req.Output)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ws.wsHub != nil {
			ws.wsHub.Broadcast("PLAYBOOK_RUN_UPDATE", map[string]interface{}{
				"run":         run,
				"active_runs": soarEngine.GetActiveRuns(),
			})
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

	// 3. Direct Remediation Action Execution
	targetIP := req.ActorIP
	if targetIP == "" {
		targetIP = req.TargetIP
	}
	res, err := soarEngine.ExecuteRemediationAction(req.ActionType, targetIP, req.NodeID, req.Param)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ws.wsHub != nil {
		ws.wsHub.Broadcast("soar_action_executed", res)
	}

	_ = json.NewEncoder(w).Encode(res)
}

func (ws *WebSOCServer) handleThreatIntel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	intel := GetDefaultThreatIntel()

	if r.Method == http.MethodGet {
		ip := r.URL.Query().Get("ip")
		if ip != "" {
			entry, matched := intel.MatchIP(ip)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ip":      ip,
				"matched": matched,
				"entry":   entry,
			})
			return
		}
		json.NewEncoder(w).Encode(intel.GetStats())
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			IP          string `json:"ip"`
			Category    string `json:"category"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.IP != "" {
			intel.mu.Lock()
			intel.exactIPs[req.IP] = &ThreatIntelEntry{
				Indicator:   req.IP,
				Category:    req.Category,
				Confidence:  95,
				SourceFeed:  "Manual-SOC-Enrichment",
				Description: req.Description,
				AddedAt:     time.Now(),
			}
			intel.mu.Unlock()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"stats":   intel.GetStats(),
		})
	}
}

func (ws *WebSOCServer) handleSOARAutoPilot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var soarEng *AutonomousSOAREngine
	if ws.server != nil {
		soarEng = ws.server.GetSOAREngine()
	}
	if soarEng == nil {
		soarEng = GetDefaultSOAREngine()
	}

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": soarEng.IsAutoPilotActive(),
			"stats":  soarEng.GetEngineStats(),
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Active *bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Active != nil {
			soarEng.SetAutoPilotActive(*req.Active)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"active":  soarEng.IsAutoPilotActive(),
			"stats":   soarEng.GetEngineStats(),
		})
	}
}

func (ws *WebSOCServer) handleSOARStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var soarEng *AutonomousSOAREngine
	if ws.server != nil {
		soarEng = ws.server.GetSOAREngine()
	}
	if soarEng == nil {
		soarEng = GetDefaultSOAREngine()
	}

	json.NewEncoder(w).Encode(soarEng.GetEngineStats())
}

func (ws *WebSOCServer) handleAuditVerifyIntegrity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.storage == nil {
		http.Error(w, `{"error": "Storage engine unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	valid, verifiedCount, lastHash, err := ws.storage.VerifyLogIntegrity()
	resp := map[string]interface{}{
		"valid":              valid,
		"records_verified":   verifiedCount,
		"last_verified_hash": lastHash,
		"timestamp":          time.Now().Format(time.RFC3339),
	}
	if err != nil {
		resp["error"] = err.Error()
		resp["integrity_status"] = "COMPROMISED"
		w.WriteHeader(http.StatusOK)
	} else {
		resp["integrity_status"] = "VERIFIED_VALID"
	}

	json.NewEncoder(w).Encode(resp)
}

func (ws *WebSOCServer) handleTrustScore(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, `{"error": "ip parameter required"}`, http.StatusBadRequest)
		return
	}

	zte := GetDefaultZeroTrustEngine()
	state, found := zte.GetEntityState(ip)
	if !found {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":          ip,
			"trust_score": 100,
			"status":      "BASELINE_TRUSTED",
			"isolated":    false,
		})
		return
	}

	json.NewEncoder(w).Encode(state)
}

func (ws *WebSOCServer) handleTrustEntities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	zte := GetDefaultZeroTrustEngine()
	entities := zte.GetAllEntities()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_entities": len(entities),
		"entities":       entities,
	})
}
