package p2p

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MeshConfig defines cluster parameters and networking bindings.
type MeshConfig struct {
	NodeID         string
	BindAddr       string // e.g. ":7946" or "0.0.0.0:7946"
	BootstrapPeers []string
	ClusterSecret  string
	GossipInterval time.Duration
}

// PeerInfo records the health and telemetry of a swarm peer.
type PeerInfo struct {
	NodeID          string        `json:"node_id"`
	Addr            string        `json:"addr"`
	LastSeenMs      int64         `json:"last_seen_ms"`
	RTTMs           int64         `json:"rtt_ms"`
	Status          string        `json:"status"` // ALIVE, SUSPECT, DEAD
	PreemptiveDrops uint64        `json:"preemptive_drops"`
	ActiveBansCount int           `json:"active_bans_count"`
}

// GossipMessage wraps serialized peer-to-peer data packets.
type GossipMessage struct {
	Type        string `json:"type"` // PING, PONG, THREAT_BROADCAST, CRDT_SYNC
	SenderID    string `json:"sender_id"`
	SenderAddr  string `json:"sender_addr"`
	Sequence    uint64 `json:"sequence"`
	TimestampMs int64  `json:"timestamp_ms"`
	Signature   string `json:"signature"`
	Payload     []byte `json:"payload"`
}

// ThreatBroadcast is gossiped when an edge node detects a malicious attack.
type ThreatBroadcast struct {
	TargetIP     string `json:"target_ip"`
	Subnet       string `json:"subnet"`
	ThreatScore  int    `json:"threat_score"`
	RuleID       string `json:"rule_id"`
	MitreID      string `json:"mitre_id"`
	CountryCode  string `json:"country_code"`
	AttackerASN  string `json:"attacker_asn"`
	TTLSeconds   int64  `json:"ttl_seconds"`
	Reason       string `json:"reason"`
	OriginNodeID string `json:"origin_node_id"`
}

// SwarmEventLog represents an audit log entry for the Web SOC Swarm Stream.
type SwarmEventLog struct {
	TimestampMs int64  `json:"timestamp_ms"`
	OriginNode  string `json:"origin_node"`
	TargetIP    string `json:"target_ip"`
	ThreatScore int    `json:"threat_score"`
	RuleID      string `json:"rule_id"`
	Action      string `json:"action"`
	Message     string `json:"message"`
}

// GossipMesh manages decentralized threat intelligence dissemination and CRDT sync.
type GossipMesh struct {
	cfg          MeshConfig
	crdtJail     *CRDTSwarmJail
	conn         *net.UDPConn
	peers        map[string]*PeerInfo
	peersMu      sync.RWMutex
	seqCounter   uint64
	msgRate      uint64
	eventLogs    []SwarmEventLog
	logsMu       sync.RWMutex
	onThreatRecv func(tb ThreatBroadcast)
	stopChan     chan struct{}
}

// NewGossipMesh initializes the P2P swarm node.
func NewGossipMesh(cfg MeshConfig, onThreatRecv func(tb ThreatBroadcast), onLocalBan func(entry CRDTBanEntry)) *GossipMesh {
	if cfg.BindAddr == "" {
		cfg.BindAddr = ":7946"
	}
	if cfg.GossipInterval == 0 {
		cfg.GossipInterval = 1500 * time.Millisecond
	}
	if cfg.ClusterSecret == "" {
		cfg.ClusterSecret = "copsec-zero-trust-default-mesh-key"
	}

	mesh := &GossipMesh{
		cfg:          cfg,
		peers:        make(map[string]*PeerInfo),
		onThreatRecv: onThreatRecv,
		stopChan:     make(chan struct{}),
	}

	mesh.crdtJail = NewCRDTSwarmJail(cfg.NodeID, func(entry CRDTBanEntry) {
		if onLocalBan != nil {
			onLocalBan(entry)
		}
	})

	return mesh
}

// Start opens the UDP gossip listener and joins bootstrap peers.
func (m *GossipMesh) Start(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", m.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve bind address %s: %w", m.cfg.BindAddr, err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", m.cfg.BindAddr, err)
	}
	m.conn = conn

	log.Printf("[P2P_MESH] 🌐 Zero-Trust Gossip Defense Mesh listening on %s (NodeID: %s)", m.cfg.BindAddr, m.cfg.NodeID)

	// Ingest bootstrap peers
	for _, p := range m.cfg.BootstrapPeers {
		p = strings.TrimSpace(p)
		if p != "" && p != m.cfg.BindAddr {
			m.AddPeer("bootstrap-"+p, p)
		}
	}

	go m.listenLoop()
	go m.gossipLoop(ctx)
	go m.antiEntropySyncLoop(ctx)

	return nil
}

// AddPeer registers or updates a peer in the routing table.
func (m *GossipMesh) AddPeer(nodeID, addr string) {
	if addr == "" {
		return
	}
	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	if p, exists := m.peers[addr]; exists {
		p.LastSeenMs = time.Now().UnixMilli()
		p.Status = "ALIVE"
		if nodeID != "" {
			p.NodeID = nodeID
		}
	} else {
		m.peers[addr] = &PeerInfo{
			NodeID:     nodeID,
			Addr:       addr,
			LastSeenMs: time.Now().UnixMilli(),
			RTTMs:      2,
			Status:     "ALIVE",
		}
		log.Printf("[P2P_MESH] 🤝 Discovered new Swarm peer: %s (%s)", nodeID, addr)
	}
}

// BroadcastThreat pushes a new attack signature to the peer mesh for instant cross-fleet quarantine.
func (m *GossipMesh) BroadcastThreat(tb ThreatBroadcast) {
	if tb.OriginNodeID == "" {
		tb.OriginNodeID = m.cfg.NodeID
	}

	// 1. Record in local CRDT jail
	m.crdtJail.Add(CRDTBanEntry{
		TargetIP:         tb.TargetIP,
		Subnet:           tb.Subnet,
		AttackerASN:      tb.AttackerASN,
		CountryCode:      tb.CountryCode,
		ThreatScore:      tb.ThreatScore,
		OriginNodeID:     tb.OriginNodeID,
		TimestampMs:      time.Now().UnixMilli(),
		TTLSeconds:       tb.TTLSeconds,
		MitigationReason: tb.Reason,
		Preemptive:       false,
	})

	payloadBytes, _ := json.Marshal(tb)
	msg := m.buildSignedMessage("THREAT_BROADCAST", payloadBytes)

	m.addEventLog(tb.OriginNodeID, tb.TargetIP, tb.ThreatScore, tb.RuleID, "LOCAL_DETECT",
		fmt.Sprintf("Origin node detected %s from %s (Score: %d). Gossiping to mesh.", tb.RuleID, tb.TargetIP, tb.ThreatScore))

	// Gossip to random sample of peers
	m.gossipToPeers(msg, 3)
}

// CRDTSyncMessage carries CRDT sets for anti-entropy reconciliation.
type CRDTSyncMessage struct {
	AddSet    map[string]CRDTBanEntry    `json:"add_set"`
	RemoveSet map[string]CRDTRemoveEntry `json:"remove_set"`
}

func (m *GossipMesh) listenLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		n, remoteAddr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		atomic.AddUint64(&m.msgRate, 1)

		var msg GossipMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		// Verify signature
		if !m.verifySignature(msg) {
			continue
		}

		m.AddPeer(msg.SenderID, remoteAddr.String())

		m.handleIncomingMessage(msg, remoteAddr)
	}
}

func (m *GossipMesh) handleIncomingMessage(msg GossipMessage, remoteAddr *net.UDPAddr) {
	switch msg.Type {
	case "PING":
		pong := m.buildSignedMessage("PONG", nil)
		data, _ := json.Marshal(pong)
		_, _ = m.conn.WriteToUDP(data, remoteAddr)

	case "PONG":
		rtt := time.Now().UnixMilli() - msg.TimestampMs
		if rtt < 0 {
			rtt = 1
		}
		m.peersMu.Lock()
		if p, ok := m.peers[remoteAddr.String()]; ok {
			p.RTTMs = rtt
			p.LastSeenMs = time.Now().UnixMilli()
			p.Status = "ALIVE"
		}
		m.peersMu.Unlock()

	case "THREAT_BROADCAST":
		var tb ThreatBroadcast
		if err := json.Unmarshal(msg.Payload, &tb); err != nil {
			return
		}

		// Preemptive local mitigation
		enforced := m.crdtJail.Add(CRDTBanEntry{
			TargetIP:         tb.TargetIP,
			Subnet:           tb.Subnet,
			AttackerASN:      tb.AttackerASN,
			CountryCode:      tb.CountryCode,
			ThreatScore:      tb.ThreatScore,
			OriginNodeID:     tb.OriginNodeID,
			TimestampMs:      msg.TimestampMs,
			TTLSeconds:       tb.TTLSeconds,
			MitigationReason: tb.Reason,
			Preemptive:       true,
		})

		if enforced {
			log.Printf("[P2P_MESH] ⚡ Preemptively Quarantined Attacker IP %s (Received from Peer %s, Score: %d)",
				tb.TargetIP, tb.OriginNodeID, tb.ThreatScore)

			m.addEventLog(tb.OriginNodeID, tb.TargetIP, tb.ThreatScore, tb.RuleID, "PREEMPTIVE_BAN",
				fmt.Sprintf("Preemptively enforced kernel drop for %s received from Swarm Peer %s", tb.TargetIP, tb.OriginNodeID))

			if m.onThreatRecv != nil {
				m.onThreatRecv(tb)
			}
		}

	case "CRDT_SYNC":
		var syncMsg CRDTSyncMessage
		if err := json.Unmarshal(msg.Payload, &syncMsg); err != nil {
			return
		}
		newBans := m.crdtJail.Merge(syncMsg.AddSet, syncMsg.RemoveSet)
		for _, nb := range newBans {
			log.Printf("[P2P_CRDT] 🔄 Reconciled Swarm Ban: %s (Origin: %s, TTL: %ds)", nb.TargetIP, nb.OriginNodeID, nb.TTLSeconds)
		}
	}
}

func (m *GossipMesh) gossipLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Send PING heartbeats to known peers
			ping := m.buildSignedMessage("PING", nil)
			m.gossipToPeers(ping, 2)
		}
	}
}

func (m *GossipMesh) antiEntropySyncLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Exchange CRDT delta with peers
			addSet, remSet := m.crdtJail.ExportState()
			syncPayload, _ := json.Marshal(CRDTSyncMessage{
				AddSet:    addSet,
				RemoveSet: remSet,
			})
			msg := m.buildSignedMessage("CRDT_SYNC", syncPayload)
			m.gossipToPeers(msg, 2)
		}
	}
}

func (m *GossipMesh) gossipToPeers(msg GossipMessage, fanout int) {
	data, err := json.Marshal(msg)
	if err != nil || m.conn == nil {
		return
	}

	m.peersMu.RLock()
	var addrs []string
	for addr := range m.peers {
		addrs = append(addrs, addr)
	}
	m.peersMu.RUnlock()

	if len(addrs) == 0 {
		return
	}

	// Shuffle
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	if len(addrs) > fanout {
		addrs = addrs[:fanout]
	}

	for _, addrStr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
		if err == nil {
			_, _ = m.conn.WriteToUDP(data, udpAddr)
		}
	}
}

func (m *GossipMesh) buildSignedMessage(msgType string, payload []byte) GossipMessage {
	seq := atomic.AddUint64(&m.seqCounter, 1)
	now := time.Now().UnixMilli()

	msg := GossipMessage{
		Type:        msgType,
		SenderID:    m.cfg.NodeID,
		SenderAddr:  m.cfg.BindAddr,
		Sequence:    seq,
		TimestampMs: now,
		Payload:     payload,
	}

	mac := hmac.New(sha256.New, []byte(m.cfg.ClusterSecret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d:%d:%s", msgType, m.cfg.NodeID, seq, now, string(payload))))
	msg.Signature = hex.EncodeToString(mac.Sum(nil))

	return msg
}

func (m *GossipMesh) verifySignature(msg GossipMessage) bool {
	mac := hmac.New(sha256.New, []byte(m.cfg.ClusterSecret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d:%d:%s", msg.Type, msg.SenderID, msg.Sequence, msg.TimestampMs, string(msg.Payload))))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(msg.Signature), []byte(expected))
}

func (m *GossipMesh) addEventLog(origin, target string, score int, rule, action, msg string) {
	m.logsMu.Lock()
	defer m.logsMu.Unlock()

	m.eventLogs = append(m.eventLogs, SwarmEventLog{
		TimestampMs: time.Now().UnixMilli(),
		OriginNode:  origin,
		TargetIP:    target,
		ThreatScore: score,
		RuleID:      rule,
		Action:      action,
		Message:     msg,
	})

	if len(m.eventLogs) > 100 {
		m.eventLogs = m.eventLogs[1:]
	}
}

// GetPeers returns the list of known mesh peers.
func (m *GossipMesh) GetPeers() []PeerInfo {
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()

	now := time.Now().UnixMilli()
	var list []PeerInfo
	for _, p := range m.peers {
		info := *p
		if now-info.LastSeenMs > 10000 {
			info.Status = "SUSPECT"
		}
		if now-info.LastSeenMs > 30000 {
			info.Status = "DEAD"
		}
		list = append(list, info)
	}
	return list
}

// GetEventLogs returns the recent swarm event stream for Web SOC inspection.
func (m *GossipMesh) GetEventLogs() []SwarmEventLog {
	m.logsMu.RLock()
	defer m.logsMu.RUnlock()

	res := make([]SwarmEventLog, len(m.eventLogs))
	copy(res, m.eventLogs)
	return res
}

// GetCRDTJail returns the active CRDT quarantine engine.
func (m *GossipMesh) GetCRDTJail() *CRDTSwarmJail {
	return m.crdtJail
}

// GetTopology returns real-time swarm topology statistics.
func (m *GossipMesh) GetTopology() map[string]interface{} {
	peers := m.GetPeers()
	activePeers := 0
	var totalRTT int64 = 0

	for _, p := range peers {
		if p.Status == "ALIVE" {
			activePeers++
			totalRTT += p.RTTMs
		}
	}

	avgRTT := float64(0)
	if activePeers > 0 {
		avgRTT = float64(totalRTT) / float64(activePeers)
	}

	return map[string]interface{}{
		"local_node_id":   m.cfg.NodeID,
		"bind_addr":       m.cfg.BindAddr,
		"total_peers":     len(peers),
		"active_peers":    activePeers,
		"average_rtt_ms":  avgRTT,
		"gossip_msg_rate": atomic.LoadUint64(&m.msgRate),
		"crdt_bans_count": m.crdtJail.Count(),
		"peers":           peers,
	}
}

// Close gracefully terminates the gossip listener.
func (m *GossipMesh) Close() error {
	close(m.stopChan)
	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}
