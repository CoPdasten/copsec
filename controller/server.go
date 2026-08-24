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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// NodeSession tracks live agent status and command communication channels.
type NodeSession struct {
	NodeID          string    `json:"node_id"`
	APIKey          string    `json:"api_key"`
	Hostname        string    `json:"hostname"`
	Group           string    `json:"group"`
	RemoteAddr      string    `json:"remote_addr"`
	LastSeen        time.Time `json:"last_seen"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     float64   `json:"memory_usage"`
	ActiveBansCount int32     `json:"active_bans_count"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	CommandChan     chan *copsecproto.SOARCommand `json:"-"`
}

// CentralServer implements the gRPC CopsecStreamService with threat analysis, auto-auth & autonomous SOAR.
type CentralServer struct {
	copsecproto.UnimplementedCopsecStreamServiceServer

	mu           sync.RWMutex
	storage      *StorageEngine
	analyzer     *RuleEngine
	sigmaEngine  *SigmaEngine
	ttlManager   *TTLBanManager
	wsHub        *WSHub
	telegramBot  *TelegramSOARBot
	aiEngine     *AIEngine
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
		aiEngine:         NewAIEngine(),
		nodes:            make(map[string]*NodeSession),
		eventSubChan:     make(chan *StoredEvent, 4096),
		autoBanEnabled:   true,
		autoBanThreshold: 50,
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

// SetTelegramBot configures the telegram alert bot.
func (s *CentralServer) SetTelegramBot(bot *TelegramSOARBot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telegramBot = bot
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
	atomic.AddUint64(&s.totalEventsProcessed, 1)
	atomic.AddUint64(&s.epsEventsThisSec, 1)

	ruleID := event.RuleId
	mitreID := event.MitreTechniqueId
	threatScore := int(event.ThreatScore)

	// 1. In-Memory Sigma Detection Engine (Detection-as-Code) Evaluation
	s.mu.RLock()
	sigma := s.sigmaEngine
	s.mu.RUnlock()

	if sigma != nil {
		fields := map[string]string{
			"source":    event.Source,
			"client_ip": event.ClientIp,
			"status":    fmt.Sprintf("%d", event.StatusCode),
			"raw":       event.RawLine,
		}
		if matchedSigmaRule, matched := sigma.EvaluateEvent(event.RawLine, fields); matched {
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

	stored := &StoredEvent{
		NodeID:           nodeID,
		Source:           event.Source,
		RawLine:          event.RawLine,
		ClientIP:         event.ClientIp,
		StatusCode:       int(event.StatusCode),
		TimestampMs:      event.TimestampMs,
		RuleID:           ruleID,
		MitreTechniqueID: mitreID,
		ThreatScore:      threatScore,
	}

	if stored.TimestampMs == 0 {
		stored.TimestampMs = time.Now().UnixMilli()
	}

	// Persist to embedded SQLite
	_ = s.storage.InsertEvent(stored)

	// Check Autonomous Auto-Ban Policy & Dynamic TTL Management
	s.checkAutonomousBanPolicy(stored)

	// Trigger AI Threat Intelligence analysis for severe incidents
	s.mu.RLock()
	ai := s.aiEngine
	bot := s.telegramBot
	hub := s.wsHub
	s.mu.RUnlock()

	if ai != nil && (stored.ThreatScore >= 65 || strings.Contains(stored.RuleID, "anomaly") || strings.Contains(stored.RuleID, "rce") || strings.Contains(stored.RuleID, "sqli") || strings.Contains(stored.RuleID, "sigma")) {
		go func(ev *StoredEvent) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			intel := ai.AnalyzeIntent(ctx, ev)
			summary := fmt.Sprintf("• Intent: %s\n• Root Cause: %s\n• Mitigation: %s", intel.AttackerIntent, intel.RootCause, intel.Mitigation)
			ev.AIAnalysis = summary
			_ = s.storage.UpdateEventAI(ev.ID, summary)

			if bot != nil && (ev.ThreatScore >= 40 || ev.StatusCode >= 400) {
				bot.ProcessEvent(ev)
			}

			// Broadcast AI updated event to Web SOC
			if hub != nil {
				hub.Broadcast("event", ev)
			}
		}(stored)
	} else {
		if bot != nil && (stored.ThreatScore >= 40 || stored.StatusCode >= 400) {
			go bot.ProcessEvent(stored)
		}
		// Non-blocking Web SOC WebSocket broadcast
		if hub != nil {
			hub.Broadcast("event", stored)
		}
	}

	// Broadcast to channel subscriber non-blockingly
	select {
	case s.eventSubChan <- stored:
	default:
	}
}

// checkAutonomousBanPolicy evaluates static critical scores (>=50) and correlation spike windows.
func (s *CentralServer) checkAutonomousBanPolicy(event *StoredEvent) {
	ip := strings.TrimSpace(event.ClientIP)
	if ip == "" || isProtectedIP(ip) {
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

	triggerAutoBan := false
	banReason := ""

	// Condition 1: Static Critical / High-Threat Threshold (ThreatScore >= 50)
	threshold := s.autoBanThreshold
	if threshold <= 0 {
		threshold = 50
	}
	if event.ThreatScore >= threshold {
		triggerAutoBan = true
		banReason = fmt.Sprintf("Auto-ban: Threat Score %d/100 triggered (Rule: %s, MITRE: %s)", event.ThreatScore, event.RuleID, event.MitreTechniqueID)
	}

	// Condition 2: Correlational Spike / Brute-Force Threshold (>= 3 high-threat events in 60s)
	if event.ThreatScore >= 35 {
		history := s.ipHistory[ip]
		var recent []int64
		for _, ts := range history {
			if now-ts <= 60 {
				recent = append(recent, ts)
			}
		}
		recent = append(recent, now)
		s.ipHistory[ip] = recent

		if len(recent) >= 3 && !triggerAutoBan {
			triggerAutoBan = true
			banReason = fmt.Sprintf("Correlational Spike Threshold (%d attacks in 60s)", len(recent))
		}
	}

	if triggerAutoBan {
		s.autoBanned[ip] = now

		// Enforce via TTLBanManager if present, or direct broadcast fallback
		s.mu.RLock()
		ttlMgr := s.ttlManager
		bot := s.telegramBot
		s.mu.RUnlock()

		dispatched := 0
		if ttlMgr != nil {
			_, _ = ttlMgr.BanIP(ip, banReason, 86400, TierExtendedQuarantine)
			dispatched = len(s.GetNodesSnapshot())
		} else {
			dispatched = s.BroadcastSOARCommand("BAN_IP", ip, 86400)
			if s.storage != nil {
				_ = s.storage.RecordBan(ip, banReason, 86400)
			}
		}

		log.Printf("[SOAR_AUTOBAN] Autonomous Ban executed for IP %s (Reason: %s, Dispatched: %d nodes)", ip, banReason, dispatched)

		// Dispatch high-priority autonomous Telegram alert
		if bot != nil {
			go bot.SendAutoBanAlert(event, banReason, dispatched)
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
			_ = s.storage.RecordBan(targetIP, "Manual/SOAR Alert", durationSec)
		} else if actionType == "UNBAN_IP" || actionType == "WHITELIST_IP" {
			_ = s.storage.RemoveBan(targetIP)
		}
		_ = s.storage.RecordSOARAction(actionType, targetIP, dispatched)
	}

	log.Printf("[SOAR_BROADCAST] Dispatched %s for IP %s to %d nodes", actionType, targetIP, dispatched)
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
