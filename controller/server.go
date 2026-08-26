package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"github.com/copsec/controller/pkg/geoip"
	"github.com/copsec/controller/pkg/ipinfo"
	"github.com/copsec/controller/pkg/ml"
	"github.com/copsec/controller/pkg/sigma"
	"github.com/copsec/controller/pkg/snort"
	"github.com/copsec/controller/pkg/soar"
	"github.com/copsec/controller/pkg/threat"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// NodeSession tracks live agent status and command communication channels.
type NodeSession struct {
	NodeID          string                        `json:"node_id"`
	APIKey          string                        `json:"api_key"`
	Hostname        string                        `json:"hostname"`
	Group           string                        `json:"group"`
	RemoteAddr      string                        `json:"remote_addr"`
	LastSeen        time.Time                     `json:"last_seen"`
	CPUUsage        float64                       `json:"cpu_usage"`
	MemoryUsage     float64                       `json:"memory_usage"`
	ActiveBansCount int32                         `json:"active_bans_count"`
	UptimeSeconds   int64                         `json:"uptime_seconds"`
	CommandChan     chan *copsecproto.SOARCommand `json:"-"`
}

// CentralServer implements the direct gRPC Hub-and-Spoke CopsecStreamService.
type CentralServer struct {
	copsecproto.UnimplementedCopsecStreamServiceServer

	mu           sync.RWMutex
	storage      *StorageEngine
	analyzer     *RuleEngine
	sigmaEngine  *SigmaEngine
	ttlManager   *TTLBanManager
	wsHub        *WSHub
	threatEngine *threat.ScoringEngine
	nodes        map[string]*NodeSession
	eventSubChan chan *StoredEvent

	// Autonomous Auto-Ban Tracker
	autoBanMu        sync.Mutex
	autoBanEnabled   bool
	autoBanThreshold int
	ipHistory        map[string][]int64
	autoBanned       map[string]int64

	totalEventsProcessed uint64
	currentEPS           uint64
	epsEventsThisSec     uint64
}

// NewCentralServer creates a new CentralServer instance.
func NewCentralServer(storage *StorageEngine, analyzer *RuleEngine) *CentralServer {
	srv := &CentralServer{
		storage:          storage,
		analyzer:         analyzer,
		threatEngine:     threat.GetDefaultEngine(),
		nodes:            make(map[string]*NodeSession),
		eventSubChan:     make(chan *StoredEvent, 4096),
		autoBanEnabled:   true,
		autoBanThreshold: 80,
		ipHistory:        make(map[string][]int64),
		autoBanned:       make(map[string]int64),
	}

	// EPS Calculator ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			count := atomic.SwapUint64(&srv.epsEventsThisSec, 0)
			atomic.StoreUint64(&srv.currentEPS, count)

			// Broadcast live system stats to Web SOC WebSocket clients
			if srv.wsHub != nil {
				mitreStats, _ := srv.storage.GetMITREStats()
				activeBansCount := 0
				if srv.ttlManager != nil {
					activeBansCount = len(srv.ttlManager.GetActiveBans())
				}
				srv.wsHub.Broadcast("stats", map[string]interface{}{
					"eps":          count,
					"total_events": atomic.LoadUint64(&srv.totalEventsProcessed),
					"nodes_count":  len(srv.GetNodesSnapshot()),
					"active_bans":  activeBansCount,
					"mitre_stats":  mitreStats,
				})
			}
		}
	}()

	return srv
}

// SetSigmaEngine attaches the in-memory SigmaHQ detection engine.
func (s *CentralServer) SetSigmaEngine(engine *SigmaEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sigmaEngine = engine
}

// SetTTLManager attaches the SOAR dynamic TTL lifecycle manager.
func (s *CentralServer) SetTTLManager(mgr *TTLBanManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttlManager = mgr
}

// SetWSHub attaches the zero-backpressure WebSocket broadcast hub.
func (s *CentralServer) SetWSHub(hub *WSHub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wsHub = hub
}

// SetAutoBanPolicy configures autonomous auto-ban behavior.
func (s *CentralServer) SetAutoBanPolicy(enabled bool, threshold int) {
	s.autoBanMu.Lock()
	defer s.autoBanMu.Unlock()
	s.autoBanEnabled = enabled
	if threshold > 0 {
		s.autoBanThreshold = threshold
	}
}

// GetAnalyzer returns the rule engine instance.
func (s *CentralServer) GetAnalyzer() *RuleEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.analyzer
}

// SubscribeEvents returns a receive-only channel for live stream consumers.
func (s *CentralServer) SubscribeEvents() <-chan *StoredEvent {
	return s.eventSubChan
}

// authenticate validates headers and maintains active edge node sessions.
func (s *CentralServer) authenticate(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "metadata missing")
	}

	nodeIDs := md.Get("x-node-id")
	apiKeys := md.Get("x-api-key")

	if len(nodeIDs) == 0 || len(apiKeys) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing node credentials")
	}

	nodeID := nodeIDs[0]
	apiKey := apiKeys[0]

	if !strings.HasPrefix(nodeID, "node-") || len(apiKey) < 8 {
		return "", status.Errorf(codes.Unauthenticated, "invalid credentials format")
	}

	group := "DEFAULT_EDGE"
	if groups := md.Get("x-node-group"); len(groups) > 0 && groups[0] != "" {
		group = groups[0]
	}

	hostname := ""
	if hostnames := md.Get("x-hostname"); len(hostnames) > 0 && hostnames[0] != "" {
		hostname = hostnames[0]
	}
	if hostname == "" {
		hostname = strings.TrimPrefix(nodeID, "node-")
	}

	remoteAddr := ""
	if p, ok := peer.FromContext(ctx); ok {
		remoteAddr = p.Addr.String()
	}

	s.mu.Lock()
	session, exists := s.nodes[nodeID]
	if !exists {
		session = &NodeSession{
			NodeID:      nodeID,
			APIKey:      apiKey,
			Hostname:    hostname,
			Group:       group,
			RemoteAddr:  remoteAddr,
			LastSeen:    time.Now(),
			CommandChan: make(chan *copsecproto.SOARCommand, 128),
		}
		s.nodes[nodeID] = session
		log.Printf("[AUTH] Registered new edge node: %s (Host: %s, Group: %s, Addr: %s)", nodeID, hostname, group, remoteAddr)
	} else {
		session.LastSeen = time.Now()
		if group != "DEFAULT_EDGE" {
			session.Group = group
		}
		if hostname != "" {
			session.Hostname = hostname
		}
		if remoteAddr != "" {
			session.RemoteAddr = remoteAddr
		}
	}
	s.mu.Unlock()

	// Persist to storage node registry
	if s.storage != nil {
		_ = s.storage.RegisterOrUpdateNode(&NodeRegistryRecord{
			NodeID:          nodeID,
			APIKey:          apiKey,
			Hostname:        hostname,
			GroupName:       group,
			RemoteAddr:      remoteAddr,
			LastSeenMs:      time.Now().UnixMilli(),
			CPUUsage:        session.CPUUsage,
			MemoryUsage:     session.MemoryUsage,
			ActiveBansCount: int(session.ActiveBansCount),
			UptimeSeconds:   session.UptimeSeconds,
			Status:          "ACTIVE",
		})
	}

	return nodeID, nil
}

// StreamEvents handles high-velocity event ingestion from edge collectors.
func (s *CentralServer) StreamEvents(stream copsecproto.CopsecStreamService_StreamEventsServer) error {
	nodeID, err := s.authenticate(stream.Context())
	if err != nil {
		return err
	}

	var count uint64
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&copsecproto.StreamAck{
				Success:        true,
				ProcessedCount: count,
				Message:        "All events ingested successfully",
			})
		}
		if err != nil {
			return err
		}

		s.processEvent(nodeID, event)
		count++
	}
}

func (s *CentralServer) processEvent(nodeID string, event *copsecproto.LogEvent) {
	// Filter out Suricata heartbeat & internal statistics telemetry from incident stream
	if event.Source == "suricata" || strings.Contains(event.RawLine, `"event_type"`) {
		if strings.Contains(event.RawLine, `"event_type":"stats"`) ||
			strings.Contains(event.RawLine, `"event_type": "stats"`) ||
			strings.Contains(event.RawLine, `"event_type":"heartbeat"`) ||
			strings.Contains(event.RawLine, `"event_type": "heartbeat"`) {
			return
		}
	}

	atomic.AddUint64(&s.totalEventsProcessed, 1)
	atomic.AddUint64(&s.epsEventsThisSec, 1)

	ruleID := event.RuleId
	mitreID := event.MitreTechniqueId
	threatScore := int(event.ThreatScore)

	// 1. In-Memory Sigma Detection Engine (Detection-as-Code) Evaluation
	s.mu.RLock()
	sigmaEng := s.sigmaEngine
	s.mu.RUnlock()

	if sigmaEng != nil {
		fields := map[string]string{
			"source":    event.Source,
			"client_ip": event.ClientIp,
			"status":    fmt.Sprintf("%d", event.StatusCode),
			"raw":       event.RawLine,
		}
		if matchedSigmaRule, matched := sigmaEng.EvaluateEvent(event.RawLine, fields); matched {
			if ruleID == "" {
				ruleID = matchedSigmaRule.ID
			}
			if mitreID == "" {
				mitreID = matchedSigmaRule.MitreTechniqueID
			}
			if threatScore < matchedSigmaRule.ThreatScore {
				threatScore = matchedSigmaRule.ThreatScore
			}
		}
	}

	// 2. RuleEngine Inspection Fallback
	if s.analyzer != nil {
		matchedRule, matchedMitre, matchedScore, matched := s.analyzer.Analyze(event.RawLine, int(event.StatusCode), event.Source)
		if matched {
			if ruleID == "" {
				ruleID = matchedRule
			}
			if mitreID == "" {
				mitreID = matchedMitre
			}
			if threatScore < matchedScore {
				threatScore = matchedScore
			}
		}
	}

	// Strict Host-Local vs Network Scope Classification & IP Sanitization
	ruleScope := sigma.DetermineRuleScope(ruleID, "", "", "", nil)
	if ruleScope == sigma.ScopeHostLocal || ruleID == "sudo_execution" || strings.Contains(strings.ToLower(event.RawLine), "sudo:") {
		// Host-local event: ClientIP must explicitly be 127.0.0.1 or local, never bind random WAN IP
		if event.ClientIp == "" || !strings.Contains(event.RawLine, " from ") {
			event.ClientIp = "127.0.0.1"
		}
	}

	// 3. Snort 3 / Snort ML Telemetry Normalization & Threat Bridge
	var snortML bool
	var snortMsg string
	var snortModelID string
	var snortAnomalyScore float64
	var snortConfidence float64
	var snortPriority int

	if snortEv, ok := snort.ParseSnortAlert([]byte(event.RawLine)); ok {
		if event.ClientIp == "" && snortEv.SrcAddr != "" {
			event.ClientIp = snortEv.SrcAddr
		}
		if ruleID == "" && snortEv.Rule != "" {
			ruleID = snortEv.Rule
		}
		if mitreID == "" {
			mitreID = "T1071"
		}
		snortMsg = snortEv.Msg
		snortPriority = snortEv.Priority
		if snortEv.ML != nil {
			snortML = true
			snortModelID = snortEv.ML.ModelID
			snortAnomalyScore = snortEv.ML.AnomalyScore
			snortConfidence = snortEv.ML.Confidence
		}

		if snortEv.IsHighConfidenceAnomaly() {
			if threatScore < 85 {
				threatScore += 50
			}
			if threatScore > 100 {
				threatScore = 100
			}
		}
	}

	// 4. Pure-Go ML Flow Anomaly Engine Evaluation
	var mlAnomaly bool
	var mlConfidence float64
	var mlDescription string
	if event.ClientIp != "" {
		mlRes := ml.GetDefaultEngine().EvaluateFlow(
			event.ClientIp,
			[]byte(event.RawLine),
			0,
			int(event.StatusCode),
			event.TimestampMs,
		)
		if mlRes.IsAnomaly {
			mlAnomaly = true
			mlConfidence = mlRes.ConfidencePct
			mlDescription = mlRes.Description
			if threatScore < 80 {
				threatScore += 40
			}
			if ruleID == "" {
				ruleID = "ml_flow_anomaly"
			}
			if mitreID == "" {
				mitreID = "T1071"
			}
		}
	}

	// Suricata flow & DNS de-noising: Generic flows, standard DNS queries and TLS handshakes must NEVER have false MITRE tags or elevated score
	rawLower := strings.ToLower(event.RawLine)
	isSuricataNonAlert := event.Source == "suricata" && !strings.Contains(rawLower, `"event_type":"alert"`) && !strings.Contains(rawLower, `"event_type": "alert"`)
	isStandardDNS := ruleID == "suricata_dns" || strings.Contains(rawLower, `"event_type":"dns"`) || strings.Contains(rawLower, `"dest_port":53`) || strings.Contains(rawLower, `"dest_port": 53`)

	if ruleID == "suricata_flow" || ruleID == "suricata_dns" || isSuricataNonAlert || isStandardDNS {
		// Only elevate DNS if explicitly verified as tunneling/DGA/sinkhole IOC match
		if !strings.Contains(rawLower, "tunnel") && !strings.Contains(rawLower, "dga") && !strings.Contains(rawLower, "c2_ioc_match") {
			threatScore = 0
			mitreID = ""
		}
	}

	// Normal audit logs de-noising (non-critical audit events have mitre_id = "")
	if event.Source == "audit" && threatScore < 70 {
		mitreID = ""
	}

	// Global Infrastructure & Public DNS Whitelist protection
	if isProtectedIP(event.ClientIp) || (s.threatEngine != nil && s.threatEngine.IsWhitelisted(event.ClientIp)) {
		threatScore = 0
		mitreID = ""
	} else {
		// Ensure non-whitelisted MITRE technique matches or Sigma rules have baseline score >= 60
		if mitreID != "" && strings.HasPrefix(strings.ToUpper(mitreID), "T") && threatScore < 60 && ruleID != "suricata_flow" && ruleID != "suricata_dns" {
			threatScore = 60
		}
		if strings.HasPrefix(strings.ToLower(ruleID), "sigma") && threatScore < 60 {
			threatScore = 60
		}
	}

	// 5. Dynamic Sliding-Window & Time-Decayed Threat Scoring Engine
	loc := geoip.GetDefaultEngine().Lookup(event.ClientIp)
	var assessment threat.ThreatAssessment
	if s.threatEngine != nil && event.ClientIp != "" {
		assessment = s.threatEngine.Evaluate(
			event.ClientIp,
			threatScore,
			ruleID,
			mitreID,
			int(event.StatusCode),
			loc.ASN,
		)
		threatScore = assessment.FinalScore
	}

	stored := &StoredEvent{
		NodeID:             nodeID,
		Source:             event.Source,
		RawLine:            event.RawLine,
		ClientIP:           event.ClientIp,
		StatusCode:         int(event.StatusCode),
		TimestampMs:        event.TimestampMs,
		RuleID:             ruleID,
		MitreTechniqueID:   mitreID,
		ThreatScore:        threatScore,
		ScoreBreakdown:     assessment.Breakdown,
		ThreatTier:         assessment.Tier,
		CountryCode:        loc.CountryCode,
		CountryName:        loc.CountryName,
		City:               loc.City,
		ASN:                loc.ASN,
		FlagEmoji:          loc.FlagEmoji,
		MLAnomaly:          mlAnomaly,
		MLConfidencePct:    mlConfidence,
		MLDescription:      mlDescription,
		SnortML:            snortML,
		SnortMsg:           snortMsg,
		SnortModelID:       snortModelID,
		SnortAnomalyScore:  snortAnomalyScore,
		SnortConfidence:    snortConfidence,
		SnortPriority:      snortPriority,
	}

	if stored.TimestampMs == 0 {
		stored.TimestampMs = time.Now().UnixMilli()
	}

	// Persist to embedded SQLite
	_ = s.storage.InsertEvent(stored)

	// Asynchronously enrich IP with IPinfo threat intelligence
	if stored.ClientIP != "" {
		ipinfo.GetDefaultClient().LookupAsync(stored.ClientIP)
	}

	// Check Autonomous Auto-Ban Policy & Dynamic TTL Management
	s.checkAutonomousBanPolicy(stored)

	// Broadcast event directly to Web SOC via WebSocket Hub
	s.mu.RLock()
	hub := s.wsHub
	s.mu.RUnlock()

	if hub != nil {
		hub.Broadcast("event", stored)
	}

	// Broadcast to channel subscriber non-blockingly
	select {
	case s.eventSubChan <- stored:
	default:
	}
}

// checkAutonomousBanPolicy evaluates static critical scores (>=80) and correlation spike windows.
func (s *CentralServer) checkAutonomousBanPolicy(event *StoredEvent) {
	// Inhibit network quarantine (Auto-Ban) for SCOPE_HOST_LOCAL rules
	scope := sigma.DetermineRuleScope(event.RuleID, "", "", "", nil)
	if scope == sigma.ScopeHostLocal || event.RuleID == "sudo_execution" || strings.Contains(strings.ToLower(event.RawLine), "sudo:") {
		return
	}

	ip := strings.TrimSpace(event.ClientIP)
	if ip == "" || isProtectedIP(ip) || (s.threatEngine != nil && s.threatEngine.IsWhitelisted(ip)) {
		return
	}

	s.autoBanMu.Lock()
	defer s.autoBanMu.Unlock()

	if !s.autoBanEnabled {
		return
	}

	now := time.Now().Unix()

	// Check if already auto-banned within last 1 hour
	if lastBan, exists := s.autoBanned[ip]; exists && now-lastBan < 3600 {
		return
	}

	// Calculate recent correlated events count within 60s
	history := s.ipHistory[ip]
	var recent []int64
	for _, ts := range history {
		if now-ts <= 60 {
			recent = append(recent, ts)
		}
	}
	recent = append(recent, now)
	s.ipHistory[ip] = recent
	recentCount := len(recent)

	// High-Fidelity SOAR Trigger Gating
	soarEngine := soar.GetDefaultEngine()
	shouldTrigger, reason, pbID := soarEngine.ShouldTriggerSOAR(
		event.ThreatScore,
		ip,
		event.RuleID,
		event.MitreTechniqueID,
		event.RawLine,
		recentCount,
	)

	// Fallback check against configured threshold (strictly >= 80 with matching rule signature)
	threshold := s.autoBanThreshold
	if threshold <= 0 {
		threshold = 80
	}
	if !shouldTrigger && event.ThreatScore >= threshold && event.RuleID != "" && event.RuleID != "suricata_flow" && event.RuleID != "suricata_dns" {
		shouldTrigger = true
		reason = fmt.Sprintf("Autonomous Threshold Match (Score: %d, Rule: %s)", event.ThreatScore, event.RuleID)
		pbID = "PB-101"
	}

	if shouldTrigger {
		s.autoBanned[ip] = now
		banReason := fmt.Sprintf("SOAR Auto-Quarantine [%s]: %s", pbID, reason)

		// Start and track dedicated Playbook Run
		run := soarEngine.StartPlaybookRun(event.ID, pbID, ip, event.NodeID, event.ThreatScore, event.MitreTechniqueID, reason)

		// Enforce via TTLBanManager if present, or direct broadcast fallback
		s.mu.RLock()
		ttlMgr := s.ttlManager
		hub := s.wsHub
		s.mu.RUnlock()

		dispatched := 0
		if ttlMgr != nil {
			_, _ = ttlMgr.BanIP(ip, banReason, 86400, TierAutoBanSOAR)
			dispatched = len(s.GetNodesSnapshot())
		} else {
			dispatched = s.BroadcastSOARCommandWithReason("BAN_IP", ip, banReason, 86400)
			if s.storage != nil {
				_ = s.storage.RecordDetailedBan(&DetailedBanRecord{
					IP:              ip,
					Reason:          banReason,
					BanTimeMs:       time.Now().UnixMilli(),
					DurationSeconds: 86400,
					ExpireTimeMs:    time.Now().UnixMilli() + 86400000,
					PenaltyTier:     TierAutoBanSOAR,
					Status:          "ACTIVE",
					L3Active:        true,
					L4Active:        true,
					L7Active:        true,
					OffenseCount:    1,
				})
			}
		}

		// Advance Playbook Step 1 & 2 to show active containment in SOAR Hub
		_, _ = soarEngine.AdvanceStep(run.RunID, 0, "COMPLETED", fmt.Sprintf("Correlated telemetry: %s", event.RuleID))
		_, _ = soarEngine.AdvanceStep(run.RunID, 1, "COMPLETED", fmt.Sprintf("Enforced auto-quarantine across %d node(s)", dispatched))

		log.Printf("[SOAR_AUTOBAN] High-Fidelity Auto-Ban executed for IP %s (Playbook: %s, Reason: %s, Dispatched: %d nodes)", ip, pbID, banReason, dispatched)

		// Broadcast SOAR Playbook Run update to Web SOC
		if hub != nil {
			hub.Broadcast("soar_playbook_run", map[string]interface{}{
				"run":         run,
				"active_runs": soarEngine.GetActiveRuns(),
			})
		}
	}
}

// SendHeartbeat receives node health and performance metrics.
func (s *CentralServer) SendHeartbeat(ctx context.Context, hb *copsecproto.Heartbeat) (*copsecproto.HeartbeatResponse, error) {
	nodeID, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	session, ok := s.nodes[nodeID]
	if ok {
		session.LastSeen = time.Now()
		session.UptimeSeconds = hb.UptimeSeconds
		session.CPUUsage = hb.CpuUsage
		session.MemoryUsage = hb.MemoryUsage
		session.ActiveBansCount = hb.ActiveBansCount
	}
	s.mu.Unlock()

	if ok && s.storage != nil {
		_ = s.storage.RegisterOrUpdateNode(&NodeRegistryRecord{
			NodeID:          nodeID,
			Hostname:        session.Hostname,
			GroupName:       session.Group,
			RemoteAddr:      session.RemoteAddr,
			LastSeenMs:      time.Now().UnixMilli(),
			CPUUsage:        hb.CpuUsage,
			MemoryUsage:     hb.MemoryUsage,
			ActiveBansCount: int(hb.ActiveBansCount),
			UptimeSeconds:   hb.UptimeSeconds,
			Status:          "ACTIVE",
		})
	}

	return &copsecproto.HeartbeatResponse{
		Acknowledged: true,
	}, nil
}

// SyncCommands handles bidirectional SOAR dispatch.
func (s *CentralServer) SyncCommands(stream copsecproto.CopsecStreamService_SyncCommandsServer) error {
	nodeID, err := s.authenticate(stream.Context())
	if err != nil {
		return err
	}

	s.mu.RLock()
	session := s.nodes[nodeID]
	s.mu.RUnlock()

	// Goroutine to receive acknowledgments from the agent
	go func() {
		for {
			ack, err := stream.Recv()
			if err != nil {
				return
			}
			log.Printf("[SOAR_ACK] Node: %s, CommandID: %s, Success: %v, Output: %s",
				nodeID, ack.CommandId, ack.Success, ack.Output)
		}
	}()

	// Stream outgoing commands to the edge node
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case cmd, ok := <-session.CommandChan:
			if !ok {
				return nil
			}
			if err := stream.Send(cmd); err != nil {
				return err
			}
		}
	}
}

// BroadcastSOARCommand sends a command to all connected edge nodes (Fleet Ban).
func (s *CentralServer) BroadcastSOARCommand(actionType, targetIP string, durationSec int64) int {
	return s.BroadcastSOARCommandWithReason(actionType, targetIP, "Manual/SOAR Alert", durationSec)
}

// BroadcastSOARCommandWithReason sends a command with specific reason attribution to all connected edge nodes.
func (s *CentralServer) BroadcastSOARCommandWithReason(actionType, targetIP, reason string, durationSec int64) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cmdID := fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	cmd := &copsecproto.SOARCommand{
		CommandId:       cmdID,
		ActionType:      actionType,
		TargetIp:        targetIP,
		DurationSeconds: durationSec,
	}

	dispatched := 0
	for _, session := range s.nodes {
		select {
		case session.CommandChan <- cmd:
			dispatched++
		default:
			log.Printf("[WARN] Command channel full for node %s", session.NodeID)
		}
	}

	if s.storage != nil {
		if actionType == "BAN_IP" {
			_ = s.storage.RecordBan(targetIP, reason, durationSec)
		} else if actionType == "UNBAN_IP" || actionType == "WHITELIST_IP" {
			_ = s.storage.RemoveBan(targetIP)
		}
		_ = s.storage.RecordSOARAction(actionType, targetIP, dispatched)
	}

	log.Printf("[SOAR_BROADCAST] Dispatched %s for IP %s to %d nodes (Reason: %s)", actionType, targetIP, dispatched, reason)
	return dispatched
}

// GetNodesSnapshot returns a read-only view of connected nodes.
func (s *CentralServer) GetNodesSnapshot() []NodeSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []NodeSession
	for _, n := range s.nodes {
		list = append(list, *n)
	}
	return list
}

// GetEPS returns the calculated events per second.
func (s *CentralServer) GetEPS() uint64 {
	return atomic.LoadUint64(&s.currentEPS)
}

// GetTotalEvents returns the total lifetime ingested count.
func (s *CentralServer) GetTotalEvents() uint64 {
	return atomic.LoadUint64(&s.totalEventsProcessed)
}

// StartGRPCServer initializes the gRPC listener with CopsecStreamServiceServer registration and aggressive keepalive policies.
func StartGRPCServer(addr string, server *CentralServer) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	keepaliveParams := grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Minute,
		MaxConnectionAge:      2 * time.Hour,
		MaxConnectionAgeGrace: 5 * time.Minute,
		Time:                  15 * time.Second,
		Timeout:               5 * time.Second,
	})

	enforcementPolicy := grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	})

	grpcServer := grpc.NewServer(keepaliveParams, enforcementPolicy)
	copsecproto.RegisterCopsecStreamServiceServer(grpcServer, server)

	go func() {
		log.Printf("[INFO] Controller gRPC Server listening on %s", addr)
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[ERROR] gRPC server error: %v", err)
		}
	}()

	return grpcServer, nil
}
