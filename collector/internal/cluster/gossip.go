package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/copsec/collector/pkg/ebpf"
	"github.com/hashicorp/memberlist"
)

const (
	// GossipMagic identifies CoPSeC cluster threat sync frames.
	GossipMagic byte = 0x43 // 'C'
	// GossipMsgThreatSync identifies a line-rate edge drop propagation.
	GossipMsgThreatSync byte = 0x01
	// DefaultGossipPort defines standard cluster gossip communication port.
	DefaultGossipPort int = 7946
)

// ThreatSyncBroadcast defines the binary wire payload transmitted across cluster nodes.
// Binary format:
// [0]: Magic (0x43)
// [1]: MsgType (0x01)
// [2..5]: Attacker IPv4 (4 bytes)
// [6..9]: Quarantine TTL in seconds (uint32 big-endian)
// [10..11]: Source Node ID length (uint16 big-endian)
// [12..12+N]: Source Node ID UTF-8 bytes
type ThreatSyncBroadcast struct {
	AttackerIP    net.IP // IPv4 (4 bytes)
	QuarantineTTL uint32 // Seconds
	SourceNodeID  string // Originator identifier (e.g. "pardus1", "chachy")
}

// MarshalBinary serializes ThreatSyncBroadcast into a compact binary frame.
func (b *ThreatSyncBroadcast) MarshalBinary() ([]byte, error) {
	ip4 := b.AttackerIP.To4()
	if ip4 == nil {
		return nil, errors.New("attacker IP must be valid IPv4")
	}

	nodeBytes := []byte(b.SourceNodeID)
	if len(nodeBytes) > 65535 {
		return nil, errors.New("source node ID exceeds maximum length of 65535 bytes")
	}

	totalLen := 12 + len(nodeBytes)
	buf := make([]byte, totalLen)

	buf[0] = GossipMagic
	buf[1] = GossipMsgThreatSync
	copy(buf[2:6], ip4)
	binary.BigEndian.PutUint32(buf[6:10], b.QuarantineTTL)
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(nodeBytes)))
	copy(buf[12:], nodeBytes)

	return buf, nil
}

// UnmarshalBinary decodes a binary frame into a ThreatSyncBroadcast struct.
func (b *ThreatSyncBroadcast) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("threat sync payload too short: %d bytes (min 12)", len(data))
	}

	if data[0] != GossipMagic || data[1] != GossipMsgThreatSync {
		return fmt.Errorf("invalid gossip frame header: 0x%02x 0x%02x", data[0], data[1])
	}

	b.AttackerIP = net.IPv4(data[2], data[3], data[4], data[5])
	b.QuarantineTTL = binary.BigEndian.Uint32(data[6:10])

	nodeLen := int(binary.BigEndian.Uint16(data[10:12]))
	if len(data) < 12+nodeLen {
		return fmt.Errorf("truncated source node ID: expected %d bytes, got %d", nodeLen, len(data)-12)
	}

	b.SourceNodeID = string(data[12 : 12+nodeLen])
	return nil
}

// threatBroadcast implements memberlist.Broadcast for gossip distribution.
type threatBroadcast struct {
	msg []byte
}

func (b *threatBroadcast) Invalidates(other memberlist.Broadcast) bool {
	return false
}

func (b *threatBroadcast) Message() []byte {
	return b.msg
}

func (b *threatBroadcast) Finished() {}

// ThreatBanHandler defines a callback invoked when a remote threat broadcast arrives.
type ThreatBanHandler func(attackerIP net.IP, ttlSec uint32, sourceNodeID string) error

// GossipConfig configures memberlist decentralized threat replication.
type GossipConfig struct {
	NodeID        string
	BindAddr      string
	BindPort      int
	AdvertiseAddr string
	AdvertisePort int
	Peers         []string
	BanHandler    ThreatBanHandler
	Logger        *log.Logger
}

// clusterDelegate implements memberlist.Delegate for handling threat gossip events.
type clusterDelegate struct {
	cluster *GossipCluster
}

func (d *clusterDelegate) NodeMeta(limit int) []byte {
	return []byte(d.cluster.cfg.NodeID)
}

func (d *clusterDelegate) NotifyMsg(data []byte) {
	if len(data) < 2 || data[0] != GossipMagic {
		return
	}

	var threat ThreatSyncBroadcast
	if err := threat.UnmarshalBinary(data); err != nil {
		d.cluster.logf("[GOSSIP_WARN] Failed to unmarshal threat payload: %v", err)
		return
	}

	// Ignore echo broadcasts originated by this local node
	if threat.SourceNodeID == d.cluster.cfg.NodeID {
		return
	}

	ipStr := threat.AttackerIP.String()

	// Deduplicate broadcasts received via multiple gossip hops
	if d.cluster.isRecentlySeen(ipStr) {
		return
	}
	d.cluster.markRecentlySeen(ipStr)

	d.cluster.rxCount.Add(1)
	d.cluster.logf("[GOSSIP_SYNC] 🚨 Received line-rate IP quarantine from adjacent node %q -> Banning %s (TTL: %ds)",
		threat.SourceNodeID, ipStr, threat.QuarantineTTL)

	// Immediately populate the local eBPF ban_map in the NIC driver without waiting for controller
	if d.cluster.cfg.BanHandler != nil {
		if err := d.cluster.cfg.BanHandler(threat.AttackerIP, threat.QuarantineTTL, threat.SourceNodeID); err != nil {
			d.cluster.logf("[GOSSIP_ERR] Custom ban handler failed for %s: %v", ipStr, err)
		}
	} else {
		// Default: write directly to kernel eBPF XDP engine
		if xdp := ebpf.GetXDPEngine(); xdp != nil {
			ttlDuration := time.Duration(threat.QuarantineTTL) * time.Second
			reason := fmt.Sprintf("Cluster gossip sync from %s", threat.SourceNodeID)
			if err := xdp.AddBanWithTTL(ipStr, ttlDuration, 4, reason); err != nil {
				d.cluster.logf("[GOSSIP_ERR] Failed to populate eBPF ban_map for %s: %v", ipStr, err)
			}
		}
	}
}

func (d *clusterDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	if d.cluster.queue == nil {
		return nil
	}
	return d.cluster.queue.GetBroadcasts(overhead, limit)
}

func (d *clusterDelegate) LocalState(join bool) []byte {
	return nil
}

func (d *clusterDelegate) MergeRemoteState(buf []byte, join bool) {}

// GossipCluster orchestrates peer discovery and broadcast synchronization.
type GossipCluster struct {
	cfg        GossipConfig
	list       *memberlist.Memberlist
	delegate   *clusterDelegate
	queue      *memberlist.TransmitLimitedQueue
	dedupMu    sync.RWMutex
	dedupMap   map[string]time.Time
	closed     atomic.Bool
	bcastCount atomic.Uint64
	rxCount    atomic.Uint64
}

// NewGossipCluster initializes the memberlist gossip agent and binds network sockets.
func NewGossipCluster(cfg GossipConfig) (*GossipCluster, error) {
	if cfg.NodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			cfg.NodeID = fmt.Sprintf("sensor-%d", time.Now().UnixNano())
		} else {
			cfg.NodeID = hostname
		}
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0"
	}
	if cfg.BindPort == 0 {
		cfg.BindPort = DefaultGossipPort
	}

	cluster := &GossipCluster{
		cfg:      cfg,
		dedupMap: make(map[string]time.Time),
	}

	mConfig := memberlist.DefaultLANConfig()
	mConfig.Name = cfg.NodeID
	mConfig.BindAddr = cfg.BindAddr
	mConfig.BindPort = cfg.BindPort

	if cfg.AdvertiseAddr != "" {
		mConfig.AdvertiseAddr = cfg.AdvertiseAddr
	}
	if cfg.AdvertisePort != 0 {
		mConfig.AdvertisePort = cfg.AdvertisePort
	}

	if cfg.Logger != nil {
		mConfig.Logger = cfg.Logger
	} else {
		// Silent memberlist internal debug logging to prevent journal clutter
		mConfig.Logger = log.New(io.Discard, "", 0)
	}

	delegate := &clusterDelegate{cluster: cluster}
	mConfig.Delegate = delegate

	list, err := memberlist.Create(mConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist node on %s:%d: %w", cfg.BindAddr, cfg.BindPort, err)
	}

	cluster.list = list
	cluster.delegate = delegate
	cluster.queue = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			return list.NumMembers()
		},
		RetransmitMult: 3,
	}

	// Auto-join configured seed peers if provided
	if len(cfg.Peers) > 0 {
		var validPeers []string
		for _, p := range cfg.Peers {
			if strings.TrimSpace(p) != "" {
				validPeers = append(validPeers, strings.TrimSpace(p))
			}
		}
		if len(validPeers) > 0 {
			joined, err := list.Join(validPeers)
			if err != nil {
				log.Printf("[GOSSIP_WARN] Failed to join initial peers %v: %v", validPeers, err)
			} else {
				log.Printf("[GOSSIP] 🤝 Successfully joined %d cluster peer(s)", joined)
			}
		}
	}

	log.Printf("[GOSSIP] ⚡ Distributed Threat Sync node active: ID=%s (%s:%d)",
		cfg.NodeID, cfg.BindAddr, cfg.BindPort)

	return cluster, nil
}

// BroadcastThreat encodes an attacker IP and quarantine TTL and disseminates it across the cluster.
func (c *GossipCluster) BroadcastThreat(attackerIP net.IP, ttlSec uint32) error {
	if c.closed.Load() {
		return errors.New("gossip cluster is closed")
	}

	cleanIP := attackerIP.To4()
	if cleanIP == nil {
		return fmt.Errorf("invalid IPv4: %v", attackerIP)
	}

	payload := ThreatSyncBroadcast{
		AttackerIP:    cleanIP,
		QuarantineTTL: ttlSec,
		SourceNodeID:  c.cfg.NodeID,
	}

	data, err := payload.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode threat broadcast: %w", err)
	}

	// Mark locally seen so this node does not re-process its own broadcast
	c.markRecentlySeen(cleanIP.String())

	// Enqueue in memberlist gossip queue for immediate dissemination
	c.queue.QueueBroadcast(&threatBroadcast{msg: data})
	c.bcastCount.Add(1)

	c.logf("[GOSSIP_BROADCAST] ⚡ Broadcasted IP %s (TTL: %ds) to cluster members", cleanIP, ttlSec)
	return nil
}

// Join connects to one or more existing cluster nodes by address (host:port or host).
func (c *GossipCluster) Join(peers []string) (int, error) {
	if c.closed.Load() {
		return 0, errors.New("cluster is closed")
	}
	return c.list.Join(peers)
}

// Members returns the full list of currently active nodes in the cluster.
func (c *GossipCluster) Members() []*memberlist.Node {
	if c.closed.Load() || c.list == nil {
		return nil
	}
	return c.list.Members()
}

// MemberNames returns a slice of active node names in the cluster.
func (c *GossipCluster) MemberNames() []string {
	nodes := c.Members()
	names := make([]string, len(nodes))
	for i, n := range nodes {
		names[i] = n.Name
	}
	return names
}

// Delegate returns the memberlist delegate handling cluster frames.
func (c *GossipCluster) Delegate() memberlist.Delegate {
	return c.delegate
}

// Metrics returns the total number of broadcasted and received threat messages.
func (c *GossipCluster) Metrics() (broadcasts uint64, received uint64) {
	return c.bcastCount.Load(), c.rxCount.Load()
}

// Shutdown gracefully leaves the gossip cluster and closes networking sockets.
func (c *GossipCluster) Shutdown() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.list != nil {
		_ = c.list.Leave(1 * time.Second)
		return c.list.Shutdown()
	}
	return nil
}

func (c *GossipCluster) isRecentlySeen(ip string) bool {
	c.dedupMu.RLock()
	defer c.dedupMu.RUnlock()
	t, ok := c.dedupMap[ip]
	if !ok {
		return false
	}
	return time.Since(t) < 30*time.Second
}

func (c *GossipCluster) markRecentlySeen(ip string) {
	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()
	c.dedupMap[ip] = time.Now()

	// Periodic purge of expired entries
	if len(c.dedupMap) > 1000 {
		now := time.Now()
		for k, v := range c.dedupMap {
			if now.Sub(v) > 60*time.Second {
				delete(c.dedupMap, k)
			}
		}
	}
}

func (c *GossipCluster) logf(format string, args ...any) {
	if c.cfg.Logger != nil {
		c.cfg.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
