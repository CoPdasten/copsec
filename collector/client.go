package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GrpcClientConfig stores gRPC connection and server parameters.
type GrpcClientConfig struct {
	ServerAddress   string
	HeartbeatPeriod time.Duration
	MaxBatchSize    int
}

// ControllerClient coordinates live gRPC event streaming, auto-reconnect, and offline buffering.
type ControllerClient struct {
	cfg            GrpcClientConfig
	identity       *IdentityManager
	buffer         *OfflineBuffer
	fallbackEngine *FallbackEngine

	incomingChan chan *copsecproto.LogEvent
	isConnected  int32 // atomic bool (1=connected, 0=disconnected)
	startTime    time.Time

	conn   *grpc.ClientConn
	client copsecproto.CopsecStreamServiceClient
}

// NewControllerClient initializes the hybrid gRPC client.
func NewControllerClient(cfg GrpcClientConfig, identity *IdentityManager, buffer *OfflineBuffer) *ControllerClient {
	if cfg.HeartbeatPeriod == 0 {
		cfg.HeartbeatPeriod = 3 * time.Second
	}
	if cfg.MaxBatchSize == 0 {
		cfg.MaxBatchSize = 100
	}

	return &ControllerClient{
		cfg:          cfg,
		identity:     identity,
		buffer:       buffer,
		incomingChan: make(chan *copsecproto.LogEvent, 100),
		startTime:    time.Now(),
	}
}

// SetFallbackEngine links the offline autonomous threat engine.
func (c *ControllerClient) SetFallbackEngine(engine *FallbackEngine) {
	c.fallbackEngine = engine
}

// Submit enqueues a log event into the submission channel or disk buffer.
func (c *ControllerClient) Submit(event *copsecproto.LogEvent) {
	event.NodeId = c.identity.GetNodeID()

	if atomic.LoadInt32(&c.isConnected) == 0 && c.fallbackEngine != nil {
		c.fallbackEngine.InspectOffline(event.RawLine, event.Source)
	}

	select {
	case c.incomingChan <- event:
	default:
		// Queue full or backpressure: divert directly to disk buffer
		_ = c.buffer.Enqueue(event)
	}
}

// Start launches the background connection manager and worker loops.
func (c *ControllerClient) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Printf("[INFO] Controller gRPC Client starting for target: %s", c.cfg.ServerAddress)

	// Stream worker
	wg.Add(1)
	go c.runStreamLoop(ctx, wg)

	// Heartbeat worker
	wg.Add(1)
	go c.runHeartbeatLoop(ctx, wg)

	// Command sync worker
	wg.Add(1)
	go c.runCommandSyncLoop(ctx, wg)
}

// runStreamLoop manages connection lifecycle, offline buffer draining, and live streaming.
func (c *ControllerClient) runStreamLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	var backoff time.Duration = 1 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			c.closeConnection()
			return
		default:
		}

		conn, client, err := c.connect(ctx)
		if err != nil {
			atomic.StoreInt32(&c.isConnected, 0)
			edgeEngine.SetControllerConnection(false)
			if c.fallbackEngine != nil {
				c.fallbackEngine.SetFallbackActive(true)
			}
			log.Printf("[WARN] Failed to connect to Controller (%s): %v. Retrying in %v...",
				c.cfg.ServerAddress, err, backoff)

			c.drainIncomingToBuffer(ctx, backoff)

			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			continue
		}

		backoff = 1 * time.Second
		c.conn = conn
		c.client = client
		atomic.StoreInt32(&c.isConnected, 1)
		edgeEngine.SetControllerConnection(true)
		if c.fallbackEngine != nil {
			c.fallbackEngine.SetFallbackActive(false)
		}
		log.Printf("[INFO] gRPC connection established to Controller (%s)", c.cfg.ServerAddress)

		// 1. Drain offline buffered items first (FIFO)
		c.flushOfflineBuffer(ctx, client)

		// 2. Stream live events
		if err := c.streamLive(ctx, client); err != nil {
			atomic.StoreInt32(&c.isConnected, 0)
			edgeEngine.SetControllerConnection(false)
			if c.fallbackEngine != nil {
				c.fallbackEngine.SetFallbackActive(true)
			}
			log.Printf("[WARN] Live gRPC stream disconnected: %v", err)
			c.closeConnection()
		}
	}
}

func (c *ControllerClient) connect(ctx context.Context) (*grpc.ClientConn, copsecproto.CopsecStreamServiceClient, error) {
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()

	keepaliveOpts := grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10 * time.Second, // Ping server every 10s
		Timeout:             3 * time.Second,  // 3s timeout for keepalive response
		PermitWithoutStream: true,
	})

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(c.identity),
		keepaliveOpts,
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(dialCtx, c.cfg.ServerAddress, opts...)
	if err != nil {
		return nil, nil, err
	}

	return conn, copsecproto.NewCopsecStreamServiceClient(conn), nil
}

func (c *ControllerClient) closeConnection() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func sanitizeLogEvent(nodeID string, raw *copsecproto.LogEvent) *copsecproto.LogEvent {
	if raw == nil {
		return nil
	}
	evNodeID := raw.NodeId
	if evNodeID == "" {
		evNodeID = nodeID
	}
	return &copsecproto.LogEvent{
		NodeId:           evNodeID,
		Source:           raw.Source,
		RawLine:          raw.RawLine,
		ClientIp:         raw.ClientIp,
		StatusCode:       raw.StatusCode,
		TimestampMs:      raw.TimestampMs,
		RuleId:           raw.RuleId,
		MitreTechniqueId: raw.MitreTechniqueId,
		ThreatScore:      raw.ThreatScore,
	}
}

// flushOfflineBuffer sends accumulated offline records to the controller.
func (c *ControllerClient) flushOfflineBuffer(ctx context.Context, client copsecproto.CopsecStreamServiceClient) {
	pending := c.buffer.Size()
	if pending == 0 {
		return
	}

	log.Printf("[INFO] Draining %d offline buffered events to Controller...", pending)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		batch, ids, err := c.buffer.DequeueBatch(c.cfg.MaxBatchSize)
		if err != nil || len(batch) == 0 {
			break
		}

		stream, err := client.StreamEvents(ctx)
		if err != nil {
			log.Printf("[WARN] Failed to open stream for buffer flush: %v", err)
			return
		}

		var sentCount int
		for _, rawEvent := range batch {
			cleanEvent := sanitizeLogEvent(c.identity.GetNodeID(), rawEvent)
			if cleanEvent == nil {
				continue
			}
			if err := stream.Send(cleanEvent); err != nil {
				log.Printf("[WARN] Buffer stream interrupted: %v", err)
				return
			}
			sentCount++
		}

		if sentCount == 0 {
			_ = c.buffer.Ack(ids)
			continue
		}

		ack, err := stream.CloseAndRecv()
		if err != nil || (ack != nil && !ack.Success) {
			log.Printf("[WARN] Failed to receive buffer flush Ack: %v", err)
			return
		}

		// Acknowledge and compact local disk buffer
		_ = c.buffer.Ack(ids)
	}

	log.Println("[INFO] Offline buffer successfully drained.")
}

// streamLive pushes live incoming events directly to the Controller.
func (c *ControllerClient) streamLive(ctx context.Context, client copsecproto.CopsecStreamServiceClient) error {
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return nil

		case event := <-c.incomingChan:
			cleanEvent := sanitizeLogEvent(c.identity.GetNodeID(), event)
			if cleanEvent == nil {
				continue
			}
			if err := stream.Send(cleanEvent); err != nil {
				// Failed to send live: store in offline buffer
				_ = c.buffer.Enqueue(cleanEvent)
				return err
			}
		}
	}
}

// drainIncomingToBuffer diverts incoming events to disk buffer while disconnected.
func (c *ControllerClient) drainIncomingToBuffer(ctx context.Context, duration time.Duration) {
	timeout := time.After(duration)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timeout:
			return
		case event := <-c.incomingChan:
			_ = c.buffer.Enqueue(event)
			edgeEngine.InspectRawLine(event.RawLine, event.Source)
			if c.fallbackEngine != nil {
				c.fallbackEngine.InspectOffline(event.RawLine, event.Source)
			}
		}
	}
}

// runHeartbeatLoop transmits periodic node telemetry.
func (c *ControllerClient) runHeartbeatLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(c.cfg.HeartbeatPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&c.isConnected) == 0 || c.client == nil {
				continue
			}

			metrics := CollectSystemMetrics()
			memUsageMB := metrics.RAMUsedMB
			if memUsageMB <= 0 {
				var memStats runtime.MemStats
				runtime.ReadMemStats(&memStats)
				memUsageMB = float64(memStats.Alloc) / 1024.0 / 1024.0
			}

			hb := &copsecproto.Heartbeat{
				NodeId:          c.identity.GetNodeID(),
				UptimeSeconds:   int64(time.Since(c.startTime).Seconds()),
				CpuUsage:        float64(metrics.CPUPercent),
				MemoryUsage:     memUsageMB, // MB
				ActiveBansCount: 0,
			}

			hbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, _ = c.client.SendHeartbeat(hbCtx, hb)
			cancel()
		}
	}
}

// runCommandSyncLoop receives SOAR execution commands from controller and applies actions.
func (c *ControllerClient) runCommandSyncLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if atomic.LoadInt32(&c.isConnected) == 0 || c.client == nil {
			time.Sleep(1 * time.Second)
			continue
		}

		cmdStream, err := c.client.SyncCommands(ctx)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for {
			cmd, err := cmdStream.Recv()
			if err != nil {
				break
			}

			if cmd != nil {
				c.executeSOARCommand(cmd, cmdStream)
			}
		}
	}
}

// executeSOARCommand runs local firewall / containment actions safely.
func (c *ControllerClient) executeSOARCommand(cmd *copsecproto.SOARCommand, stream copsecproto.CopsecStreamService_SyncCommandsClient) {
	log.Printf("[SOAR_COMMAND] Received directive: ID=%s, Action=%s, Target=%s",
		cmd.CommandId, cmd.ActionType, cmd.TargetIp)

	var success bool
	var output string

	targetIP := strings.TrimSpace(cmd.TargetIp)

	switch cmd.ActionType {
	case "BAN_IP":
		success, output = ExecuteSOARBan(targetIP, cmd.DurationSeconds)

	case "UNBAN_IP":
		success, output = ExecuteSOARUnban(targetIP)

	case "WHITELIST_IP":
		if net.ParseIP(targetIP) == nil {
			output = fmt.Sprintf("Rejected: invalid IP address '%s'", targetIP)
			break
		}

		// Remove any iptables ban first
		_ = exec.Command("iptables", "-D", "INPUT", "-s", targetIP, "-j", "DROP").Run()
		_ = exec.Command("copsec-cli", "unban", targetIP).Run()

		// Persist to /etc/copsec/whitelist.json
		wlPath := "/etc/copsec/whitelist.json"
		if _, err := os.Stat("/etc/copsec"); os.IsNotExist(err) {
			_ = os.MkdirAll("/etc/copsec", 0750)
		}
		if _, err := os.Stat(wlPath); os.IsNotExist(err) {
			wlPath = "config/whitelist.json"
		}

		var cfg struct {
			TrustedCIDRs []string `json:"trusted_cidrs"`
		}
		data, _ := os.ReadFile(wlPath)
		_ = json.Unmarshal(data, &cfg)

		exists := false
		for _, c := range cfg.TrustedCIDRs {
			if strings.TrimSpace(c) == targetIP || strings.TrimSpace(c) == targetIP+"/32" {
				exists = true
				break
			}
		}
		if !exists {
			cfg.TrustedCIDRs = append(cfg.TrustedCIDRs, targetIP+"/32")
			outData, _ := json.MarshalIndent(cfg, "", "  ")
			_ = os.WriteFile(wlPath, outData, 0640)
		}

		success = true
		output = fmt.Sprintf("Successfully whitelisted IP %s and cleared iptables rule", targetIP)

	case "FLUSH_BANS":
		out, err := exec.Command("copsec-cli", "flush").CombinedOutput()
		if err == nil {
			success = true
			output = string(out)
		} else {
			output = fmt.Sprintf("Failed to flush bans: %v (%s)", err, string(out))
		}

	default:
		output = "Unknown action type: " + cmd.ActionType
	}

	_ = stream.Send(&copsecproto.CommandAck{
		CommandId:   cmd.CommandId,
		Success:     success,
		Output:      output,
		TimestampMs: time.Now().UnixMilli(),
	})
}
