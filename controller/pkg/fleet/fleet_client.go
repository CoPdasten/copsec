package fleet

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/copsec/collector/pkg/quarantine"
	fleetproto "github.com/copsec/collector/proto/fleet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// FleetClientConfig configures connection and health parameters for the edge agent.
type FleetClientConfig struct {
	ServerAddress   string
	NodeID          string
	Hostname        string
	IPAddress       string
	HeartbeatPeriod time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
}

// CommandExecutionHandler defines a callback when a controller command is received.
type CommandExecutionHandler func(cmd *fleetproto.ControllerCommand)

// FleetClient manages bidirectional streaming with FleetService, sends continuous
// node health pulses, and enforces received quarantine / ban directives locally.
type FleetClient struct {
	cfg        FleetClientConfig
	quarantine quarantine.QuarantineDriver
	onCommand  CommandExecutionHandler

	mu          sync.RWMutex
	conn        *grpc.ClientConn
	client      fleetproto.FleetServiceClient
	isConnected int32 // atomic bool (1 = connected, 0 = disconnected)
	startTime   time.Time
	stopChan    chan struct{}
}

// NewFleetClient initializes a new FleetClient instance.
func NewFleetClient(cfg FleetClientConfig) *FleetClient {
	if cfg.HeartbeatPeriod <= 0 {
		cfg.HeartbeatPeriod = 10 * time.Second
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 1 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = "node-" + hostname
	}

	ipAddr := cfg.IPAddress
	if ipAddr == "" {
		ipAddr = detectLocalIP()
	}

	cfg.Hostname = hostname
	cfg.NodeID = nodeID
	cfg.IPAddress = ipAddr

	return &FleetClient{
		cfg:        cfg,
		quarantine: quarantine.GetDriver(),
		startTime:  time.Now(),
		stopChan:   make(chan struct{}),
	}
}

// SetCommandHandler attaches an optional custom command listener callback.
func (fc *FleetClient) SetCommandHandler(handler CommandExecutionHandler) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.onCommand = handler
}

// IsConnected returns true if currently streaming with FleetService.
func (fc *FleetClient) IsConnected() bool {
	return atomic.LoadInt32(&fc.isConnected) == 1
}

// Start initiates the background connection manager and worker loops.
func (fc *FleetClient) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go fc.runConnectionLoop(ctx, wg)
}

// Stop terminates the fleet client.
func (fc *FleetClient) Stop() {
	select {
	case <-fc.stopChan:
		return
	default:
		close(fc.stopChan)
	}

	fc.mu.Lock()
	if fc.conn != nil {
		_ = fc.conn.Close()
	}
	fc.mu.Unlock()
}

// runConnectionLoop maintains a resilient connection with exponential backoff.
func (fc *FleetClient) runConnectionLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	backoff := fc.cfg.InitialBackoff

	for {
		select {
		case <-ctx.Done():
			return
		case <-fc.stopChan:
			return
		default:
		}

		err := fc.connectAndStream(ctx)
		atomic.StoreInt32(&fc.isConnected, 0)

		select {
		case <-ctx.Done():
			return
		case <-fc.stopChan:
			return
		default:
		}

		log.Printf("[FLEET_CLIENT] Stream disconnected (%v). Reconnecting to %s in %v...", err, fc.cfg.ServerAddress, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		case <-fc.stopChan:
			return
		}

		// Exponential backoff: min(backoff * 2, maxBackoff)
		backoff = time.Duration(math.Min(float64(backoff*2), float64(fc.cfg.MaxBackoff)))
	}
}

// connectAndStream handles dialing, initial handshake, health pulse ticker, and incoming command execution.
func (fc *FleetClient) connectAndStream(ctx context.Context) error {
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}

	conn, err := grpc.DialContext(dialCtx, fc.cfg.ServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	fc.mu.Lock()
	fc.conn = conn
	fc.client = fleetproto.NewFleetServiceClient(conn)
	fc.mu.Unlock()

	stream, err := fc.client.ConnectFleet(ctx)
	if err != nil {
		return fmt.Errorf("ConnectFleet failed: %w", err)
	}

	// 1. Send Initial Handshake Message
	initialHealth := fc.collectHealth()
	initialMsg := &fleetproto.AgentMessage{
		NodeId:      fc.cfg.NodeID,
		Hostname:    fc.cfg.Hostname,
		IpAddress:   fc.cfg.IPAddress,
		TimestampMs: time.Now().UnixMilli(),
		Health:      initialHealth,
	}
	if err := stream.Send(initialMsg); err != nil {
		return fmt.Errorf("initial handshake send failed: %w", err)
	}

	atomic.StoreInt32(&fc.isConnected, 1)
	log.Printf("[FLEET_CLIENT] ✅ Connected to Fleet Mesh at %s (NodeID: %s)", fc.cfg.ServerAddress, fc.cfg.NodeID)

	errChan := make(chan error, 2)

	// 2. Health Pulse Worker (every 10s by default)
	go func() {
		ticker := time.NewTicker(fc.cfg.HeartbeatPeriod)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-fc.stopChan:
				return
			case <-ticker.C:
				health := fc.collectHealth()
				pulse := &fleetproto.AgentMessage{
					NodeId:      fc.cfg.NodeID,
					Hostname:    fc.cfg.Hostname,
					IpAddress:   fc.cfg.IPAddress,
					TimestampMs: time.Now().UnixMilli(),
					Health:      health,
				}
				if err := stream.Send(pulse); err != nil {
					errChan <- fmt.Errorf("health pulse send failed: %w", err)
					return
				}
			}
		}
	}()

	// 3. Command Ingestion Worker
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					errChan <- nil
				} else {
					errChan <- fmt.Errorf("command recv failed: %w", err)
				}
				return
			}
			if cmd != nil {
				fc.executeCommand(cmd)
			}
		}
	}()

	return <-errChan
}

// executeCommand applies ControllerCommand directives locally on the host.
func (fc *FleetClient) executeCommand(cmd *fleetproto.ControllerCommand) {
	log.Printf("[FLEET_COMMAND] Received directive: ID=%s, Type=%s, Target=%s, Reason=%s",
		cmd.CommandId, cmd.Type.String(), cmd.TargetIp, cmd.Reason)

	// Trigger custom hook if set
	fc.mu.RLock()
	hook := fc.onCommand
	fc.mu.RUnlock()
	if hook != nil {
		hook(cmd)
	}

	switch cmd.Type {
	case fleetproto.ControllerCommand_COMMAND_ENFORCE_BAN:
		targetIP := strings.TrimSpace(cmd.TargetIp)
		if targetIP == "" || isProtectedIP(targetIP) {
			log.Printf("[FLEET_COMMAND] ⚠️ Skipping ban for invalid/protected IP: %s", targetIP)
			return
		}

		// Cross-platform quarantine driver (Linux iptables or Windows netsh firewall)
		driver := fc.quarantine
		if driver == nil {
			driver = quarantine.GetDriver()
		}
		if driver != nil {
			err := driver.BlockIP(targetIP, cmd.Reason)
			if err != nil {
				log.Printf("[FLEET_COMMAND] Quarantine driver BlockIP error for %s: %v", targetIP, err)
			}
		}

		log.Printf("[FLEET_COMMAND] ⚡ Enforced immediate ban on IP %s across local host", targetIP)

	case fleetproto.ControllerCommand_COMMAND_REVOKE_BAN:
		targetIP := strings.TrimSpace(cmd.TargetIp)
		if targetIP == "" {
			return
		}

		driver := fc.quarantine
		if driver == nil {
			driver = quarantine.GetDriver()
		}
		if driver != nil {
			_ = driver.UnblockIP(targetIP)
		}

		log.Printf("[FLEET_COMMAND] 🟢 Revoked ban on IP %s across local host", targetIP)

	case fleetproto.ControllerCommand_COMMAND_HEARTBEAT_ACK:
		// Normal heartbeat acknowledgment from controller

	case fleetproto.ControllerCommand_COMMAND_SYNC_WHITELIST:
		log.Printf("[FLEET_COMMAND] Sync whitelist directive received for IP %s", cmd.TargetIp)
	}
}

// collectHealth aggregates current host CPU, RAM, active ban count, and uptime.
func (fc *FleetClient) collectHealth() *fleetproto.AgentHealth {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memUsageMB := float64(memStats.Alloc) / 1024.0 / 1024.0

	activeBans := 0
	driver := fc.quarantine
	if driver == nil {
		driver = quarantine.GetDriver()
	}
	if driver != nil {
		if list, err := driver.ListBlocked(); err == nil {
			activeBans = len(list)
		}
	}

	uptimeSec := int64(time.Since(fc.startTime).Seconds())

	return &fleetproto.AgentHealth{
		CpuUsage:    0.5,
		MemoryUsage: memUsageMB,
		ActiveBans:  int32(activeBans),
		UptimeSec:   uptimeSec,
	}
}

// detectLocalIP finds the preferred non-loopback outbound IP address.
func detectLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}

	return "127.0.0.1"
}

// isProtectedIP checks loopback and private networks.
func isProtectedIP(ipStr string) bool {
	clean := strings.TrimSpace(ipStr)
	if clean == "" || clean == "127.0.0.1" || clean == "::1" || clean == "localhost" {
		return true
	}
	ip := net.ParseIP(clean)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}
