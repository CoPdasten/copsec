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

// CentralServer implements the gRPC CopsecStreamService with threat analysis, auto-auth & fleet dispatch.
type CentralServer struct {
	copsecproto.UnimplementedCopsecStreamServiceServer

	mu                   sync.RWMutex
	storage              *StorageEngine
	analyzer             *RuleEngine
	telegramBot          *TelegramSOARBot
	aiEngine             *AIEngine
	nodes                map[string]*NodeSession
	eventSubChan         chan *StoredEvent

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

// SetTelegramBot wires the SOAR alert bot.
func (s *CentralServer) SetTelegramBot(bot *TelegramSOARBot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telegramBot = bot
}

// SetAIEngine overrides or updates the AI engine.
func (s *CentralServer) SetAIEngine(ai *AIEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aiEngine = ai
}

// SubscribeEvents returns the channel receiving real-time events for TUI / Telegram.
func (s *CentralServer) SubscribeEvents() <-chan *StoredEvent {
	return s.eventSubChan
}

// GetEPS returns the live events per second throughput.
func (s *CentralServer) GetEPS() uint64 {
	return atomic.LoadUint64(&s.currentEPS)
}

// GetAnalyzer returns the rule engine instance.
func (s *CentralServer) GetAnalyzer() *RuleEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.analyzer
}

// GetTotalEvents returns total processed events count.
func (s *CentralServer) GetTotalEvents() uint64 {
	return atomic.LoadUint64(&s.totalEventsProcessed)
}

// authenticate extracts and validates x-node-id and x-api-key from incoming gRPC context metadata.
func (s *CentralServer) authenticate(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "metadata is missing")
	}

	nodeIDs := md.Get("x-node-id")
	apiKeys := md.Get("x-api-key")
	if len(nodeIDs) == 0 || len(apiKeys) == 0 || nodeIDs[0] == "" || apiKeys[0] == "" {
		return "", status.Errorf(codes.Unauthenticated, "x-node-id and x-api-key are required")
	}

	nodeID := nodeIDs[0]
	apiKey := apiKeys[0]

	s.mu.Lock()
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
	s.mu.Unlock()

	return nodeID, nil
}

// StreamEvents handles the high-throughput log ingestion stream from edge nodes.
func (s *CentralServer) StreamEvents(stream grpc.ClientStreamingServer[copsecproto.LogEvent, copsecproto.StreamAck]) error {
	nodeID, err := s.authenticate(stream.Context())
	if err != nil {
		return err
	}

	var batchCount uint64
	for {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&copsecproto.StreamAck{
				Success:        true,
				ProcessedCount: batchCount,
				Message:        "Batch processed successfully",
			})
		}
		if err != nil {
			return err
		}

		batchCount++
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

		// Trigger AI Threat Intelligence analysis for severe incidents
		s.mu.RLock()
		ai := s.aiEngine
		bot := s.telegramBot
		s.mu.RUnlock()

		if ai != nil && (stored.ThreatScore >= 65 || strings.Contains(stored.RuleID, "anomaly") || strings.Contains(stored.RuleID, "rce") || strings.Contains(stored.RuleID, "sqli")) {
			go func(event *StoredEvent) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				intel := ai.AnalyzeIntent(ctx, event)
				summary := fmt.Sprintf("• Intent: %s\n• Root Cause: %s\n• Mitigation: %s", intel.AttackerIntent, intel.RootCause, intel.Mitigation)
				event.AIAnalysis = summary
				_ = s.storage.UpdateEventAI(event.ID, summary)

				if bot != nil && event.ThreatScore >= 50 {
					bot.ProcessEvent(event)
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
		Acknowledged:        true,
		SyncIntervalSeconds: 3,
	}, nil
}

// SyncCommands maintains a long-lived bidirectional stream for real-time SOAR directives.
func (s *CentralServer) SyncCommands(stream grpc.BidiStreamingServer[copsecproto.CommandAck, copsecproto.SOARCommand]) error {
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
		} else if actionType == "UNBAN_IP" {
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

// StartGRPCServer binds and serves gRPC requests on targetAddr.
func StartGRPCServer(addr string, srv *CentralServer) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	grpcServer := grpc.NewServer()
	copsecproto.RegisterCopsecStreamServiceServer(grpcServer, srv)

	go func() {
		log.Printf("[INFO] Central gRPC Server listening on %s", addr)
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[ERROR] gRPC server failed: %v", err)
		}
	}()

	return grpcServer, nil
}
