package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	fleetproto "github.com/copsec/collector/proto/fleet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EdgeAgentSession represents an actively connected edge agent stream in the mesh.
type EdgeAgentSession struct {
	NodeID      string
	Hostname    string
	IPAddress   string
	LastSeen    time.Time
	Health      *fleetproto.AgentHealth
	CommandChan chan *fleetproto.ControllerCommand
}

// FleetManager orchestrates multi-node edge agent synchronization, real-time ban broadcasting,
// telemetry streaming, and automated node lifecycle monitoring.
type FleetManager struct {
	fleetproto.UnimplementedFleetServiceServer

	mu          sync.RWMutex
	agents      map[string]*EdgeAgentSession // node_id -> session
	storage     *StorageEngine
	server      *CentralServer
	stopChan    chan struct{}
	staleTicker *time.Ticker

	// Telemetry stats
	totalBatchesReceived uint64
	totalBansBroadcast    uint64
}

var (
	defaultFleetManager *FleetManager
	fleetOnce           sync.Once
)

// GetDefaultFleetManager returns the singleton FleetManager instance.
func GetDefaultFleetManager(storage *StorageEngine, server *CentralServer) *FleetManager {
	fleetOnce.Do(func() {
		defaultFleetManager = NewFleetManager(storage, server)
	})
	return defaultFleetManager
}

// NewFleetManager creates a new multi-node fleet management hub.
func NewFleetManager(storage *StorageEngine, server *CentralServer) *FleetManager {
	fm := &FleetManager{
		agents:   make(map[string]*EdgeAgentSession),
		storage:  storage,
		server:   server,
		stopChan: make(chan struct{}),
	}

	// Start background lifecycle monitor: mark agents OFFLINE if no packet received for > 45s
	go fm.runLifecycleMonitor(45 * time.Second)

	return fm
}

// RegisterService registers FleetManager with a gRPC server.
func (fm *FleetManager) RegisterService(grpcServer *grpc.Server) {
	fleetproto.RegisterFleetServiceServer(grpcServer, fm)
	log.Println("[FLEET_MANAGER] Registered gRPC FleetServiceServer")
}

// Close gracefully terminates background monitors.
func (fm *FleetManager) Close() {
	select {
	case <-fm.stopChan:
		return
	default:
		close(fm.stopChan)
	}
}

// ConnectFleet establishes a bidirectional stream with an edge agent.
// Edge agents continuously stream AgentMessage (health + identity pulses)
// and receive ControllerCommand directives (e.g. COMMAND_ENFORCE_BAN, COMMAND_REVOKE_BAN).
func (fm *FleetManager) ConnectFleet(stream fleetproto.FleetService_ConnectFleetServer) error {
	ctx := stream.Context()

	// Wait for the initial handshake AgentMessage
	firstMsg, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return status.Errorf(codes.InvalidArgument, "failed to receive initial agent handshake: %v", err)
	}

	nodeID := strings.TrimSpace(firstMsg.NodeId)
	if nodeID == "" {
		return status.Errorf(codes.InvalidArgument, "node_id must not be empty")
	}

	session := &EdgeAgentSession{
		NodeID:      nodeID,
		Hostname:    firstMsg.Hostname,
		IPAddress:   firstMsg.IpAddress,
		LastSeen:    time.Now(),
		Health:      firstMsg.Health,
		CommandChan: make(chan *fleetproto.ControllerCommand, 256),
	}

	fm.mu.Lock()
	// Replace existing session if node reconnected
	if old, exists := fm.agents[nodeID]; exists && old.CommandChan != nil {
		close(old.CommandChan)
	}
	fm.agents[nodeID] = session
	fm.mu.Unlock()

	log.Printf("[FLEET_MANAGER] 🚀 Node connected to fleet: %s (Host: %s, IP: %s)", nodeID, firstMsg.Hostname, firstMsg.IpAddress)

	// Update SQLite node registry
	fm.recordNodeState(session, "ACTIVE")

	// Send initial Heartbeat ACK
	ackCmd := &fleetproto.ControllerCommand{
		CommandId:   fmt.Sprintf("ack-%d", time.Now().UnixNano()),
		Type:        fleetproto.ControllerCommand_COMMAND_HEARTBEAT_ACK,
		TimestampMs: time.Now().UnixMilli(),
	}
	_ = stream.Send(ackCmd)

	// Goroutine for receiving continuous agent messages (health pulse)
	errChan := make(chan error, 2)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}
			if msg != nil {
				fm.handleAgentMessage(nodeID, msg, stream)
			}
		}
	}()

	// Outgoing command loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case cmd, ok := <-session.CommandChan:
				if !ok {
					errChan <- nil
					return
				}
				if err := stream.Send(cmd); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	streamErr := <-errChan

	// Clean up session upon disconnect
	fm.mu.Lock()
	if curr, ok := fm.agents[nodeID]; ok && curr == session {
		delete(fm.agents, nodeID)
	}
	fm.mu.Unlock()

	fm.recordNodeState(session, "OFFLINE")
	log.Printf("[FLEET_MANAGER] 🔌 Node disconnected from fleet: %s (Reason: %v)", nodeID, streamErr)

	if streamErr == io.EOF || streamErr == context.Canceled {
		return nil
	}
	return streamErr
}

// handleAgentMessage updates node health and sends ACK.
func (fm *FleetManager) handleAgentMessage(nodeID string, msg *fleetproto.AgentMessage, stream fleetproto.FleetService_ConnectFleetServer) {
	fm.mu.Lock()
	session, exists := fm.agents[nodeID]
	if exists {
		session.LastSeen = time.Now()
		if msg.Hostname != "" {
			session.Hostname = msg.Hostname
		}
		if msg.IpAddress != "" {
			session.IPAddress = msg.IpAddress
		}
		session.Health = msg.Health
	}
	fm.mu.Unlock()

	if exists {
		fm.recordNodeState(session, "ACTIVE")

		// Send ACK back
		ack := &fleetproto.ControllerCommand{
			CommandId:   fmt.Sprintf("ack-%d", time.Now().UnixNano()),
			Type:        fleetproto.ControllerCommand_COMMAND_HEARTBEAT_ACK,
			TimestampMs: time.Now().UnixMilli(),
		}
		select {
		case session.CommandChan <- ack:
		default:
		}
	}
}

// StreamTelemetry ingests batched edge telemetry events.
func (fm *FleetManager) StreamTelemetry(stream fleetproto.FleetService_StreamTelemetryServer) error {
	var lastBatchID int64
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&fleetproto.StreamAck{
				BatchId: lastBatchID,
				Success: true,
			})
		}
		if err != nil {
			return err
		}

		lastBatchID = batch.BatchId
		atomic.AddUint64(&fm.totalBatchesReceived, 1)

		// Forward raw events into CentralServer if available
		if fm.server != nil && batch.NodeId != "" {
			for _, rawEventBytes := range batch.RawEvents {
				rawLine := string(rawEventBytes)
				fm.server.processEvent(batch.NodeId, &copsecproto.LogEvent{
					NodeId:      batch.NodeId,
					Source:      "fleet_telemetry",
					RawLine:     rawLine,
					TimestampMs: time.Now().UnixMilli(),
				})
			}
		}
	}
}

// BroadcastBan dispatches COMMAND_ENFORCE_BAN to all active connected edge nodes concurrently
// via non-blocking channels, dropping the attacker across the entire cluster simultaneously.
func (fm *FleetManager) BroadcastBan(ip, reason string, durationSec int64) int {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return 0
	}

	fm.mu.RLock()
	sessions := make([]*EdgeAgentSession, 0, len(fm.agents))
	for _, s := range fm.agents {
		sessions = append(sessions, s)
	}
	fm.mu.RUnlock()

	cmdID := fmt.Sprintf("fleet-ban-%d", time.Now().UnixNano())
	cmd := &fleetproto.ControllerCommand{
		CommandId:   cmdID,
		Type:        fleetproto.ControllerCommand_COMMAND_ENFORCE_BAN,
		TargetIp:    cleanIP,
		Reason:      reason,
		DurationSec: durationSec,
		TimestampMs: time.Now().UnixMilli(),
	}

	dispatched := 0
	for _, s := range sessions {
		select {
		case s.CommandChan <- cmd:
			dispatched++
		default:
			log.Printf("[FLEET_MANAGER] ⚠️ Warning: CommandChan full for node %s, dropping ban push", s.NodeID)
		}
	}

	atomic.AddUint64(&fm.totalBansBroadcast, 1)

	// Persist ban in SQLite
	if fm.storage != nil {
		_ = fm.storage.RecordBan(cleanIP, reason, durationSec)
		_ = fm.storage.RecordSOARAction("FLEET_ENFORCE_BAN", cleanIP, dispatched)
	}

	log.Printf("[FLEET_MANAGER] ⚡ BROADCAST_BAN: Pushed COMMAND_ENFORCE_BAN for IP %s to %d/%d nodes (Reason: %s, Duration: %ds)",
		cleanIP, dispatched, len(sessions), reason, durationSec)

	return dispatched
}

// BroadcastRevokeBan dispatches COMMAND_REVOKE_BAN to all active edge nodes.
func (fm *FleetManager) BroadcastRevokeBan(ip string) int {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return 0
	}

	fm.mu.RLock()
	sessions := make([]*EdgeAgentSession, 0, len(fm.agents))
	for _, s := range fm.agents {
		sessions = append(sessions, s)
	}
	fm.mu.RUnlock()

	cmd := &fleetproto.ControllerCommand{
		CommandId:   fmt.Sprintf("fleet-unban-%d", time.Now().UnixNano()),
		Type:        fleetproto.ControllerCommand_COMMAND_REVOKE_BAN,
		TargetIp:    cleanIP,
		TimestampMs: time.Now().UnixMilli(),
	}

	dispatched := 0
	for _, s := range sessions {
		select {
		case s.CommandChan <- cmd:
			dispatched++
		default:
		}
	}

	if fm.storage != nil {
		_ = fm.storage.RemoveBan(cleanIP)
		_ = fm.storage.RecordSOARAction("FLEET_REVOKE_BAN", cleanIP, dispatched)
	}

	log.Printf("[FLEET_MANAGER] 🟢 BROADCAST_REVOKE_BAN: Pushed COMMAND_REVOKE_BAN for IP %s to %d nodes", cleanIP, dispatched)
	return dispatched
}

// GetConnectedAgents returns a slice of currently active edge agent snapshots.
func (fm *FleetManager) GetConnectedAgents() []EdgeAgentSession {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var result []EdgeAgentSession
	for _, s := range fm.agents {
		result = append(result, *s)
	}
	return result
}

// runLifecycleMonitor periodically marks nodes OFFLINE if no packet received for > staleThreshold (45s).
func (fm *FleetManager) runLifecycleMonitor(staleThreshold time.Duration) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			fm.mu.Lock()
			for nodeID, s := range fm.agents {
				if now.Sub(s.LastSeen) > staleThreshold {
					log.Printf("[FLEET_MANAGER] ⏱️ Node %s timed out (> %v without heartbeat). Marking OFFLINE.", nodeID, staleThreshold)
					if s.CommandChan != nil {
						close(s.CommandChan)
					}
					delete(fm.agents, nodeID)
					if fm.storage != nil {
						_ = fm.storage.UpdateNodeStatus(nodeID, "OFFLINE")
					}
				}
			}
			fm.mu.Unlock()

			// Check database for any stale nodes in case of past crashes
			if fm.storage != nil {
				_, _ = fm.storage.MarkStaleNodesOffline(staleThreshold)
			}
		}
	}
}

func (fm *FleetManager) recordNodeState(session *EdgeAgentSession, status string) {
	if fm.storage == nil || session == nil {
		return
	}

	var cpu, mem float64
	var activeBans int32
	var uptime int64

	if session.Health != nil {
		cpu = session.Health.CpuUsage
		mem = session.Health.MemoryUsage
		activeBans = session.Health.ActiveBans
		uptime = session.Health.UptimeSec
	}

	_ = fm.storage.RegisterOrUpdateNode(&NodeRegistryRecord{
		NodeID:          session.NodeID,
		Hostname:        session.Hostname,
		GroupName:       "DEFAULT_EDGE",
		RemoteAddr:      session.IPAddress,
		LastSeenMs:      session.LastSeen.UnixMilli(),
		CPUUsage:        cpu,
		MemoryUsage:     mem,
		ActiveBansCount: int(activeBans),
		UptimeSeconds:   uptime,
		Status:          status,
	})
}
