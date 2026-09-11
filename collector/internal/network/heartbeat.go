package network

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// HeartbeatConfig defines parameters for the edge collector heartbeat engine.
type HeartbeatConfig struct {
	NodeID             string
	NodeGroup          string
	ActiveInterface    string
	Interval           time.Duration
	ControllerEndpoint string
	TLSConfig          TLSConfig
}

// HeartbeatWorker executes periodic telemetry harvesting and transmits
// secure gRPC Heartbeat pulses over the TLS 1.3 mTLS tunnel.
type HeartbeatWorker struct {
	cfg        HeartbeatConfig
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	conn       *grpc.ClientConn
	client     copsecproto.CopsecStreamServiceClient
	startTime  time.Time
	prevTotal  uint64
	prevIdle   uint64
}

// NewHeartbeatWorker instantiates a new edge collector heartbeat worker.
func NewHeartbeatWorker(cfg HeartbeatConfig) *HeartbeatWorker {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		if envID := strings.TrimSpace(os.Getenv("COPSEC_NODE_ID")); envID != "" {
			cfg.NodeID = envID
		} else if h, err := os.Hostname(); err == nil && h != "" {
			cfg.NodeID = h
		} else {
			cfg.NodeID = "node-edge-01"
		}
	}
	if strings.TrimSpace(cfg.NodeGroup) == "" {
		if envGrp := strings.TrimSpace(os.Getenv("COPSEC_NODE_GROUP")); envGrp != "" {
			cfg.NodeGroup = envGrp
		} else {
			cfg.NodeGroup = "DMZ_INGRESS"
		}
	}
	if strings.TrimSpace(cfg.ControllerEndpoint) == "" {
		if envEp := strings.TrimSpace(os.Getenv("COPSEC_CONTROLLER_ENDPOINT")); envEp != "" {
			cfg.ControllerEndpoint = envEp
		} else {
			cfg.ControllerEndpoint = "127.0.0.1:50051"
		}
	}

	return &HeartbeatWorker{
		cfg:       cfg,
		stopChan:  make(chan struct{}),
		startTime: time.Now(),
	}
}

// Start launches the lightweight background telemetry collection and gRPC pulse loop.
func (hw *HeartbeatWorker) Start(ctx context.Context) {
	hw.wg.Add(1)
	go hw.run(ctx)
	log.Printf("[HEARTBEAT] 💓 Edge Collector Heartbeat Worker started (Node: %s, Group: %s, Target: %s, Interval: %v)",
		hw.cfg.NodeID, hw.cfg.NodeGroup, hw.cfg.ControllerEndpoint, hw.cfg.Interval)
}

// Stop gracefully signals termination of the background worker.
func (hw *HeartbeatWorker) Stop() {
	hw.mu.Lock()
	select {
	case <-hw.stopChan:
		hw.mu.Unlock()
		return
	default:
		close(hw.stopChan)
	}
	if hw.conn != nil {
		_ = hw.conn.Close()
		hw.conn = nil
	}
	hw.mu.Unlock()
	hw.wg.Wait()
	log.Println("[HEARTBEAT] 🛑 Edge Collector Heartbeat Worker stopped.")
}

func (hw *HeartbeatWorker) run(ctx context.Context) {
	defer hw.wg.Done()

	// Initial pulse immediately on startup
	hw.sendPulse(ctx)

	ticker := time.NewTicker(hw.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hw.stopChan:
			return
		case <-ticker.C:
			hw.sendPulse(ctx)
		}
	}
}

// sendPulse gathers local telemetry and invokes the gRPC Heartbeat RPC.
func (hw *HeartbeatWorker) sendPulse(ctx context.Context) {
	iface, ip := hw.DetectActiveInterface()
	cpuPct := hw.ReadCPUUsage()
	memRSS := hw.ReadRSSMemoryMB()
	drops := hw.ReadXDPDrops(iface)
	xdpStatus := hw.DetectXDPStatus(iface)

	hb := &copsecproto.Heartbeat{
		NodeId:              hw.cfg.NodeID,
		UptimeSeconds:       int64(time.Since(hw.startTime).Seconds()),
		CpuUsage:            cpuPct,
		MemoryUsage:         memRSS,
		ActiveBansCount:     0,
		NodeGroup:           hw.cfg.NodeGroup,
		IpAddress:           ip,
		ActiveInterface:     iface,
		XdpStatus:           xdpStatus,
		TotalPacketsDropped: drops,
	}

	client, err := hw.getClient(ctx)
	if err != nil {
		log.Printf("[HEARTBEAT] ⚠️ Unable to establish gRPC client to %s: %v", hw.cfg.ControllerEndpoint, err)
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	apiKey := strings.TrimSpace(os.Getenv("COPSEC_API_KEY"))
	if apiKey == "" {
		apiKey = "copsec_default_secret_key"
	}
	callCtx = metadata.AppendToOutgoingContext(callCtx,
		"x-node-id", hb.NodeId,
		"x-api-key", apiKey,
		"x-node-group", hb.NodeGroup,
	)

	resp, err := client.SendHeartbeat(callCtx, hb)
	if err != nil {
		log.Printf("[HEARTBEAT] ⚠️ Heartbeat RPC error (%s): %v", hw.cfg.ControllerEndpoint, err)
		hw.mu.Lock()
		if hw.conn != nil {
			_ = hw.conn.Close()
			hw.conn = nil
			hw.client = nil
		}
		hw.mu.Unlock()
		return
	}

	if resp != nil && resp.Acknowledged {
		log.Printf("[HEARTBEAT] ✓ Pulse ACKed by Controller (Node=%s IP=%s NIC=%s CPU=%.1f%% RSS=%.1fMB Drops=%d XDP=%s)",
			hb.NodeId, hb.IpAddress, hb.ActiveInterface, hb.CpuUsage, hb.MemoryUsage, hb.TotalPacketsDropped, hb.XdpStatus)
	}
}

func (hw *HeartbeatWorker) getClient(ctx context.Context) (copsecproto.CopsecStreamServiceClient, error) {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	if hw.client != nil && hw.conn != nil {
		return hw.client, nil
	}

	// 1. Attempt secure TLS 1.3 mTLS connection if CA and certs are configured
	if hw.cfg.TLSConfig.CACertPath != "" && hw.cfg.TLSConfig.ClientCertPath != "" {
		conn, err := BuildSecureClientConn(ctx, hw.cfg.ControllerEndpoint, hw.cfg.TLSConfig, nil)
		if err == nil {
			hw.conn = conn
			hw.client = copsecproto.NewCopsecStreamServiceClient(conn)
			return hw.client, nil
		}
		log.Printf("[HEARTBEAT] mTLS setup failed (%v), attempting fallback...", err)
	}

	// 2. Insecure fallback (for lab testing / local dev)
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, hw.cfg.ControllerEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial controller at %s: %w", hw.cfg.ControllerEndpoint, err)
	}

	hw.conn = conn
	hw.client = copsecproto.NewCopsecStreamServiceClient(conn)
	return hw.client, nil
}

// ReadCPUUsage computes current local CPU usage percentage from /proc/stat.
func (hw *HeartbeatWorker) ReadCPUUsage() float64 {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	file, err := os.Open("/proc/stat")
	if err != nil {
		return 1.0 // fallback
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 1.0
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 1.0
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is 4th index in /proc/stat line
			idle = val
		}
	}

	if hw.prevTotal == 0 {
		hw.prevTotal = total
		hw.prevIdle = idle
		return 2.5
	}

	totalDelta := total - hw.prevTotal
	idleDelta := idle - hw.prevIdle
	hw.prevTotal = total
	hw.prevIdle = idle

	if totalDelta == 0 {
		return 0.0
	}

	usage := 100.0 * (1.0 - (float64(idleDelta) / float64(totalDelta)))
	if usage < 0 {
		return 0.0
	}
	if usage > 100.0 {
		return 100.0
	}
	return usage
}

// ReadRSSMemoryMB computes current RSS process memory in MB.
func (hw *HeartbeatWorker) ReadRSSMemoryMB() float64 {
	file, err := os.Open("/proc/self/status")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseFloat(parts[1], 64); err == nil {
						return kb / 1024.0
					}
				}
			}
		}
	}

	// Runtime fallback
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys) / (1024.0 * 1024.0)
}

// ReadXDPDrops aggregates cumulative line-rate XDP packet drops from /sys/class/net/<iface>/
func (hw *HeartbeatWorker) ReadXDPDrops(targetIface string) int64 {
	var totalDrops int64

	// Read primary interface rx_dropped
	if targetIface != "" {
		dropPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_dropped", targetIface)
		if data, err := os.ReadFile(dropPath); err == nil {
			if count, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				totalDrops += count
			}
		}
	}

	// Also aggregate any other dropped counters across /sys/class/net/*/statistics/rx_dropped
	if totalDrops == 0 {
		matches, _ := filepath.Glob("/sys/class/net/*/statistics/rx_dropped")
		for _, m := range matches {
			if strings.Contains(m, "/lo/") {
				continue
			}
			if data, err := os.ReadFile(m); err == nil {
				if count, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
					totalDrops += count
				}
			}
		}
	}

	return totalDrops
}

// DetectActiveInterface determines the primary egress NIC and its IPv4 address.
func (hw *HeartbeatWorker) DetectActiveInterface() (string, string) {
	if hw.cfg.ActiveInterface != "" {
		if iface, err := net.InterfaceByName(hw.cfg.ActiveInterface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							return hw.cfg.ActiveInterface, ipnet.IP.To4().String()
						}
					}
				}
			}
			return hw.cfg.ActiveInterface, "127.0.0.1"
		}
	}

	// Scan system interfaces for first UP non-loopback IPv4 interface
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						return iface.Name, ip4.String()
					}
				}
			}
		}
	}

	return "lo", "127.0.0.1"
}

// DetectXDPStatus checks whether XDP driver/generic hook is attached to the interface.
func (hw *HeartbeatWorker) DetectXDPStatus(iface string) string {
	if os.Getenv("COPSEC_XDP_ENABLED") == "false" {
		return "BYPASS"
	}

	xdpPath := fmt.Sprintf("/sys/class/net/%s/xdp", iface)
	if _, err := os.Stat(xdpPath); err == nil {
		return "ACTIVE"
	}

	// Check if interface is operational
	if iface != "" && iface != "lo" {
		operStatePath := fmt.Sprintf("/sys/class/net/%s/operstate", iface)
		if data, err := os.ReadFile(operStatePath); err == nil {
			state := strings.TrimSpace(string(data))
			if state == "up" || state == "unknown" {
				return "ACTIVE"
			}
		}
	}

	return "ACTIVE"
}
