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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// NodeSession tracks live agent status and command communication channels.
type NodeSession struct {
	NodeID          string
	APIKey          string
	Hostname        string
	LastSeen        time.Time
	UptimeSeconds   int64
	CPUUsage        float64
	MemoryUsage     float64
	ActiveBansCount int32
	CommandChan     chan *copsecproto.SOARCommand
}

// CentralServer implements the gRPC CopsecStreamService with threat analysis, auto-auth & autonomous SOAR.
type CentralServer struct {
	copsecproto.UnimplementedCopsecStreamServiceServer

	mu           sync.RWMutex
	storage      *StorageEngine
	analyzer     *RuleEngine
	telegramBot  *TelegramSOARBot
	aiEngine     *AIEngine
	nodes        map[string]*NodeSession
	eventSubChan chan *StoredEvent

	// Autonomous Auto-Ban Tracker
	autoBanMu  sync.Mutex
	ipHistory  map[string][]int64
	autoBanned map[string]int64

	totalEventsProcessed uint64
	currentEPS           uint64
	epsEventsThisSec     uint64
}

// NewCentralServer creates a new CentralServer instance.
func NewCentralServer(storage *StorageEngine, analyzer *RuleEngine) *CentralServer {
	srv := &CentralServer{
		storage:      storage,
		analyzer:     analyzer,
		aiEngine:     NewAIEngine(),
		nodes:        make(map[string]*NodeSession),
		eventSubChan: make(chan *StoredEvent, 4096),
		ipHistory:    make(map[string][]int64),
		autoBanned:   make(map[string]int64),
	}

	// EPS Calculator ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			count := atomic.SwapUint64(&srv.epsEventsThisSec, 0)
			atomic.StoreUint64(&srv.currentEPS, count)
		}
	}()

	return srv
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

	if !strings.HasPrefix(nodeID, "node-vps-") || len(apiKey) < 8 {
		return "", status.Errorf(codes.Unauthenticated, "invalid credentials format")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.nodes[nodeID]
	if !exists {
		session = &NodeSession{
			NodeID:      nodeID,
			APIKey:      apiKey,
			LastSeen:    time.Now(),
			CommandChan: make(chan *copsecproto.SOARCommand, 128),
		}
		s.nodes[nodeID] = session
		log.Printf("[AUTH] Registered new edge node: %s", nodeID)
	} else {
		session.LastSeen = time.Now()
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

	// Run deep inspection via RuleEngine
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

	// Check Autonomous Auto-Ban Policy
	s.checkAutonomousBanPolicy(stored)

	// Trigger AI Threat Intelligence analysis for severe incidents
	s.mu.RLock()
	ai := s.aiEngine
	bot := s.telegramBot
	s.mu.RUnlock()

	if ai != nil && (stored.ThreatScore >= 65 || strings.Contains(stored.RuleID, "anomaly") || strings.Contains(stored.RuleID, "rce") || strings.Contains(stored.RuleID, "sqli")) {
		go func(ev *StoredEvent) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			intel := ai.AnalyzeIntent(ctx, ev)
			summary := fmt.Sprintf("• Intent: %s\n• Root Cause: %s\n• Mitigation: %s", intel.AttackerIntent, intel.RootCause, intel.Mitigation)
			ev.AIAnalysis = summary
			_ = s.storage.UpdateEventAI(ev.ID, summary)

			if bot != nil && ev.ThreatScore >= 50 {
				bot.ProcessEvent(ev)
			}
		}(stored)
	} else if bot != nil && stored.ThreatScore >= 50 {
		go bot.ProcessEvent(stored)
	}

	// Broadcast to TUI subscriber non-blockingly
	select {
	case s.eventSubChan <- stored:
	default:
	}
}

// checkAutonomousBanPolicy evaluates static critical scores and correlation spike windows.
func (s *CentralServer) checkAutonomousBanPolicy(event *StoredEvent) {
	ip := strings.TrimSpace(event.ClientIP)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "100.64.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return
	}
	if net.ParseIP(ip) == nil {
		return
	}

	s.autoBanMu.Lock()
	defer s.autoBanMu.Unlock()

	now := time.Now().Unix()

	// Check if already auto-banned within last 1 hour
	if lastBan, exists := s.autoBanned[ip]; exists && now-lastBan < 3600 {
		return
	}

	triggerAutoBan := false
	banReason := ""

	// Condition 1: Static Critical Threshold (ThreatScore >= 85)
	if event.ThreatScore >= 85 {
		triggerAutoBan = true
		banReason = fmt.Sprintf("Static Critical Threshold (ThreatScore: %d >= 85)", event.ThreatScore)
	}

	// Condition 2: Correlational Spike / Brute-Force Threshold (>= 3 high-threat events in 60s)
	if event.ThreatScore >= 50 {
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
		jailTag := fmt.Sprintf("⚡ AUTO-BAN (%s)", event.MitreTechniqueID)
		if event.MitreTechniqueID == "" {
			jailTag = "⚡ AUTO-BAN"
		}

		dispatched := s.BroadcastSOARCommand("BAN_IP", ip, 3600)
		if s.storage != nil {
			_ = s.storage.RecordBan(ip, jailTag, 3600)
		}

		log.Printf("[SOAR_AUTOBAN] Autonomous Ban executed for IP %s (Reason: %s, Dispatched: %d nodes)", ip, banReason, dispatched)

		// Dispatch high-priority autonomous Telegram alert
		s.mu.RLock()
		bot := s.telegramBot
		s.mu.RUnlock()
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
	if session, ok := s.nodes[nodeID]; ok {
		session.LastSeen = time.Now()
		session.UptimeSeconds = hb.UptimeSeconds
		session.CPUUsage = hb.CpuUsage
		session.MemoryUsage = hb.MemoryUsage
		session.ActiveBansCount = hb.ActiveBansCount
	}
	s.mu.Unlock()

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

// StartGRPCServer initializes the gRPC listener with CopsecStreamServiceServer registration.
func StartGRPCServer(addr string, server *CentralServer) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	grpcServer := grpc.NewServer()
	copsecproto.RegisterCopsecStreamServiceServer(grpcServer, server)

	go func() {
		log.Printf("[INFO] Controller gRPC Server listening on %s", addr)
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[ERROR] gRPC server error: %v", err)
		}
	}()

	return grpcServer, nil
}
