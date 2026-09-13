package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BGP Protocol Constants (RFC 4271 & RFC 7999)
const (
	HeaderLength = 19
	MarkerOctet  = 0xFF
	BGPVersion   = 4

	// Message Types
	TypeOpen         byte = 1
	TypeUpdate       byte = 2
	TypeNotification byte = 3
	TypeKeepalive    byte = 4

	// Path Attribute Types
	AttrOrigin      byte = 1
	AttrASPath      byte = 2
	AttrNextHop     byte = 3
	AttrCommunities byte = 8

	// Attribute Flags
	FlagWellKnownTransitive byte = 0x40
	FlagOptionalTransitive  byte = 0xC0

	// RFC 7999 Well-Known Blackhole Community: 65535:666 (0xFFFF029A)
	BlackholeCommunity uint32 = 0xFFFF029A

	// Default RTBH Next-Hop (RFC 5735 TEST-NET-1)
	DefaultBlackholeNextHop = "192.0.2.1"
)

// State represents the RFC 4271 BGP Finite State Machine state.
type State string

const (
	StateIdle        State = "IDLE"
	StateConnect     State = "CONNECT"
	StateOpenSent    State = "OPEN_SENT"
	StateOpenConfirm State = "OPEN_CONFIRM"
	StateEstablished State = "ESTABLISHED"
	StateClosed      State = "CLOSED"
)

// Config defines the configuration parameters for the BGP peering speaker.
type Config struct {
	Enabled          bool          `json:"enabled"`
	LocalAS          uint32        `json:"local_as"`
	PeerAS           uint32        `json:"peer_as"`
	RouterID         string        `json:"router_id"`
	PeerAddress      string        `json:"peer_address"` // e.g. "192.168.1.1" or "192.168.1.1:179"
	PeerPort         int           `json:"peer_port"`    // default 179
	HoldTime         time.Duration `json:"hold_time"`    // default 90s
	RTBHThresholdPPS uint64        `json:"rtbh_threshold_pps"` // volumetric flood threshold (default: 200,000 PPS)
	RecoveryDuration time.Duration `json:"recovery_duration"`   // quiet duration before withdrawal (default: 60s)
	BlackholeNextHop string        `json:"blackhole_next_hop"` // next-hop IP for RTBH route (default: "192.0.2.1")
}

// BlackholeRoute represents an actively advertised RTBH prefix.
type BlackholeRoute struct {
	Prefix         string    `json:"prefix"`
	IP             net.IP    `json:"ip"`
	AdvertisedAt   time.Time `json:"advertised_at"`
	LastAttackTime time.Time `json:"last_attack_time"`
	CurrentPPS     uint64    `json:"current_pps"`
	Active         bool      `json:"active"`
}

// Speaker manages BGP-4 peering sessions and autonomous RTBH signaling.
type Speaker struct {
	mu               sync.RWMutex
	cfg              Config
	state            State
	conn             net.Conn
	customDialer     func(ctx context.Context) (net.Conn, error)
	blackholedRoutes map[string]*BlackholeRoute
	advertisedCount  uint64
	withdrawnCount   uint64
	ctx              context.Context
	cancel           context.CancelFunc
	running          bool
	closeOnce        sync.Once
}

// NewSpeaker creates a new BGP speaker instance with provided config.
func NewSpeaker(cfg Config) *Speaker {
	if cfg.PeerPort <= 0 {
		cfg.PeerPort = 179
	}
	if cfg.HoldTime <= 0 {
		cfg.HoldTime = 90 * time.Second
	}
	if cfg.RecoveryDuration <= 0 {
		cfg.RecoveryDuration = 60 * time.Second
	}
	if cfg.RTBHThresholdPPS == 0 {
		cfg.RTBHThresholdPPS = 200000
	}
	if cfg.BlackholeNextHop == "" {
		cfg.BlackholeNextHop = DefaultBlackholeNextHop
	}
	if cfg.RouterID == "" {
		cfg.RouterID = "127.0.0.1"
	}

	return &Speaker{
		cfg:              cfg,
		state:            StateIdle,
		blackholedRoutes: make(map[string]*BlackholeRoute),
	}
}

// SetCustomDialer allows injecting a custom connection (e.g. for testing with net.Pipe).
func (s *Speaker) SetCustomDialer(dialer func(ctx context.Context) (net.Conn, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customDialer = dialer
}

// Start initiates the BGP peering lifecycle in a background goroutine.
func (s *Speaker) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("bgp speaker already running")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	s.state = StateConnect
	s.mu.Unlock()

	go s.sessionLoop()
	go s.recoveryMonitorLoop()

	return nil
}

// Stop gracefully shuts down the BGP peering session.
func (s *Speaker) Stop() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.cancel != nil {
			s.cancel()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.state = StateClosed
		s.running = false
		s.mu.Unlock()
	})
}

// GetState returns the current BGP FSM state.
func (s *Speaker) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// GetBlackholedRoutes returns a snapshot list of currently tracked RTBH routes.
func (s *Speaker) GetBlackholedRoutes() []BlackholeRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()
	routes := make([]BlackholeRoute, 0, len(s.blackholedRoutes))
	for _, r := range s.blackholedRoutes {
		routes = append(routes, *r)
	}
	return routes
}

// Stats returns counters for BGP operational visibility.
func (s *Speaker) Stats() (advertised uint64, withdrawn uint64, active int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	activeCount := 0
	for _, r := range s.blackholedRoutes {
		if r.Active {
			activeCount++
		}
	}
	return atomic.LoadUint64(&s.advertisedCount), atomic.LoadUint64(&s.withdrawnCount), activeCount
}

// RecordIngressMetrics evaluates live traffic rate for a source IP.
// If the ingress rate exceeds the configured RTBH threshold, a Blackhole route is automatically signaled.
func (s *Speaker) RecordIngressMetrics(ipStr string, pps uint64) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := ip.String()
	route, exists := s.blackholedRoutes[key]

	if pps >= s.cfg.RTBHThresholdPPS {
		now := time.Now()
		if !exists || !route.Active {
			// Trigger autonomous RTBH advertisement
			err := s.sendUpdate(ip, true)
			if err != nil {
				log.Printf("[BGP] Failed to advertise RTBH for %s: %v", key, err)
			} else {
				log.Printf("[BGP-RTBH] 🚨 THRESHOLD EXCEEDED (%d PPS >= %d PPS) -> ADVERTISED RTBH for %s (Community 65535:666, Next-Hop: %s)",
					pps, s.cfg.RTBHThresholdPPS, key, s.cfg.BlackholeNextHop)
				atomic.AddUint64(&s.advertisedCount, 1)
			}

			s.blackholedRoutes[key] = &BlackholeRoute{
				Prefix:         key + "/32",
				IP:             ip,
				AdvertisedAt:   now,
				LastAttackTime: now,
				CurrentPPS:     pps,
				Active:         true,
			}
		} else {
			// Refresh last seen attack time
			route.LastAttackTime = now
			route.CurrentPPS = pps
		}
	} else if exists && route.Active {
		// Traffic below threshold; update current PPS but maintain route until quiet recovery period
		route.CurrentPPS = pps
	}
}

// AdvertiseBlackhole forces an immediate manual RTBH route advertisement for an IP.
func (s *Speaker) AdvertiseBlackhole(ipStr string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	key := ip.String()

	err := s.sendUpdate(ip, true)
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.advertisedCount, 1)
	s.blackholedRoutes[key] = &BlackholeRoute{
		Prefix:         key + "/32",
		IP:             ip,
		AdvertisedAt:   now,
		LastAttackTime: now,
		CurrentPPS:     s.cfg.RTBHThresholdPPS,
		Active:         true,
	}
	log.Printf("[BGP-RTBH] Manual RTBH injection succeeded for %s", key)
	return nil
}

// WithdrawBlackhole forces an immediate withdrawal of an RTBH route.
func (s *Speaker) WithdrawBlackhole(ipStr string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := ip.String()
	route, exists := s.blackholedRoutes[key]
	if !exists || !route.Active {
		return nil
	}

	err := s.sendUpdate(ip, false)
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.withdrawnCount, 1)
	route.Active = false
	log.Printf("[BGP-RTBH] Route withdrawal sent for %s", key)
	return nil
}

// recoveryMonitorLoop runs periodically to withdraw routes that have been quiet for > RecoveryDuration.
func (s *Speaker) recoveryMonitorLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkRecovery()
		}
	}
}

func (s *Speaker) checkRecovery() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, route := range s.blackholedRoutes {
		if !route.Active {
			continue
		}

		if now.Sub(route.LastAttackTime) >= s.cfg.RecoveryDuration {
			// Attack traffic has subsided; withdraw the RTBH prefix
			err := s.sendUpdate(route.IP, false)
			if err != nil {
				log.Printf("[BGP] Error withdrawing recovered route %s: %v", key, err)
			} else {
				log.Printf("[BGP-RTBH] ✅ QUIET RECOVERY COMPLETED (%s quiet for > %v) -> WITHDRAWN RTBH route",
					key, s.cfg.RecoveryDuration)
				atomic.AddUint64(&s.withdrawnCount, 1)
				route.Active = false
			}
		}
	}
}

// sessionLoop manages the connection and message interchange.
func (s *Speaker) sessionLoop() {
	backoff := 1 * time.Second

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.dial()
		if err != nil {
			s.mu.Lock()
			if s.state != StateClosed {
				s.state = StateConnect
			}
			s.mu.Unlock()
			time.Sleep(backoff)
			if backoff < 15*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = 1 * time.Second
		s.handleSession(conn)
	}
}

func (s *Speaker) dial() (net.Conn, error) {
	s.mu.RLock()
	dialer := s.customDialer
	s.mu.RUnlock()

	if dialer != nil {
		return dialer(s.ctx)
	}

	addr := s.cfg.PeerAddress
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, s.cfg.PeerPort)
	}

	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(s.ctx, "tcp", addr)
}

func (s *Speaker) handleSession(conn net.Conn) {
	s.mu.Lock()
	s.conn = conn
	s.state = StateOpenSent
	s.mu.Unlock()

	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		s.conn = nil
		if s.state != StateClosed {
			s.state = StateConnect
		}
		s.mu.Unlock()
	}()

	// Send OPEN message
	openMsg := s.EncodeOpenMessage()
	if _, err := conn.Write(openMsg); err != nil {
		log.Printf("[BGP] Failed to send OPEN: %v", err)
		return
	}

	keepaliveInterval := s.cfg.HoldTime / 3
	if keepaliveInterval < time.Second {
		keepaliveInterval = time.Second
	}
	keepaliveTicker := time.NewTicker(keepaliveInterval)
	defer keepaliveTicker.Stop()

	msgChan := make(chan []byte, 16)
	errChan := make(chan error, 1)

	go func() {
		for {
			msg, err := ReadBGPMessage(conn)
			if err != nil {
				errChan <- err
				return
			}
			msgChan <- msg
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-keepaliveTicker.C:
			s.mu.RLock()
			st := s.state
			s.mu.RUnlock()
			if st == StateEstablished {
				ka := EncodeKeepaliveMessage()
				if _, err := conn.Write(ka); err != nil {
					log.Printf("[BGP] Error sending KEEPALIVE: %v", err)
					return
				}
			}
		case err := <-errChan:
			if !errors.Is(err, io.EOF) && s.GetState() != StateClosed {
				log.Printf("[BGP] Session read error: %v", err)
			}
			return
		case msg := <-msgChan:
			if len(msg) < HeaderLength {
				continue
			}
			msgType := msg[18]
			switch msgType {
			case TypeOpen:
				s.mu.Lock()
				s.state = StateOpenConfirm
				s.mu.Unlock()
				// Send KEEPALIVE in response to OPEN
				ka := EncodeKeepaliveMessage()
				if _, err := conn.Write(ka); err != nil {
					return
				}
			case TypeKeepalive:
				s.mu.Lock()
				if s.state == StateOpenConfirm || s.state == StateOpenSent {
					s.state = StateEstablished
					log.Printf("[BGP] BGP Session ESTABLISHED with peer AS%d (%s)", s.cfg.PeerAS, s.cfg.PeerAddress)
				}
				s.mu.Unlock()
			case TypeNotification:
				log.Printf("[BGP] Received NOTIFICATION from peer, resetting session")
				return
			case TypeUpdate:
				// Route updates from peer - accepted in Established state
			}
		}
	}
}

// sendUpdate writes an UPDATE message to the active connection.
func (s *Speaker) sendUpdate(ip net.IP, advertise bool) error {
	var msg []byte
	var err error

	if advertise {
		msg, err = s.EncodeRTBHUpdateMessage(ip)
	} else {
		msg, err = s.EncodeWithdrawalMessage(ip)
	}
	if err != nil {
		return err
	}

	if s.conn != nil {
		_, err = s.conn.Write(msg)
		return err
	}
	return nil
}

// ============================================
// RFC 4271 BINARY MESSAGE ENCODERS
// ============================================

// EncodeHeader builds the 19-byte standard BGP marker header.
func EncodeHeader(length uint16, msgType byte) []byte {
	buf := make([]byte, HeaderLength)
	for i := 0; i < 16; i++ {
		buf[i] = MarkerOctet
	}
	binary.BigEndian.PutUint16(buf[16:18], length)
	buf[18] = msgType
	return buf
}

// EncodeOpenMessage creates an RFC 4271 OPEN message.
func (s *Speaker) EncodeOpenMessage() []byte {
	const openPayloadLen = 10 // Version(1) + AS(2) + HoldTime(2) + BGP_ID(4) + OptLen(1)
	totalLen := uint16(HeaderLength + openPayloadLen)

	hdr := EncodeHeader(totalLen, TypeOpen)
	payload := make([]byte, openPayloadLen)

	payload[0] = BGPVersion

	// 2-byte ASN handling (use 23456 AS_TRANS if 4-byte ASN)
	asn := uint16(s.cfg.LocalAS)
	if s.cfg.LocalAS > 65535 {
		asn = 23456
	}
	binary.BigEndian.PutUint16(payload[1:3], asn)
	binary.BigEndian.PutUint16(payload[3:5], uint16(s.cfg.HoldTime.Seconds()))

	// Router ID (IPv4)
	rid := net.ParseIP(s.cfg.RouterID).To4()
	if rid == nil {
		rid = net.IPv4(127, 0, 0, 1)
	}
	copy(payload[5:9], rid)
	payload[9] = 0 // Optional parameter length

	return append(hdr, payload...)
}

// EncodeKeepaliveMessage creates a 19-byte RFC 4271 KEEPALIVE message.
func EncodeKeepaliveMessage() []byte {
	return EncodeHeader(HeaderLength, TypeKeepalive)
}

// EncodeRTBHUpdateMessage creates an RFC 4271 UPDATE message advertising an IP with RFC 7999 Blackhole Community.
func (s *Speaker) EncodeRTBHUpdateMessage(ip net.IP) ([]byte, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 RTBH currently supported, got %v", ip)
	}

	nhIP := net.ParseIP(s.cfg.BlackholeNextHop).To4()
	if nhIP == nil {
		nhIP = net.IPv4(192, 0, 2, 1)
	}

	// 1. Path Attributes
	var attrs []byte

	// ORIGIN: Type 1, Len 1, Value 0 (IGP)
	attrs = append(attrs, FlagWellKnownTransitive, AttrOrigin, 1, 0)

	// AS_PATH: Type 2, Len 4 (Type 2 AS_SEQUENCE, 1 AS)
	asSeq := uint16(s.cfg.LocalAS)
	if s.cfg.LocalAS > 65535 {
		asSeq = 23456
	}
	attrs = append(attrs, FlagWellKnownTransitive, AttrASPath, 4, 2, 1, byte(asSeq>>8), byte(asSeq))

	// NEXT_HOP: Type 3, Len 4, IP
	attrs = append(attrs, FlagWellKnownTransitive, AttrNextHop, 4)
	attrs = append(attrs, nhIP...)

	// COMMUNITIES: Type 8, Len 4, Value 0xFFFF029A (RFC 7999 BLACKHOLE 65535:666)
	attrs = append(attrs, FlagOptionalTransitive, AttrCommunities, 4)
	commBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(commBytes, BlackholeCommunity)
	attrs = append(attrs, commBytes...)

	// 2. NLRI (IPv4 /32 host route: 1 byte prefix length + 4 bytes IP)
	nlri := make([]byte, 5)
	nlri[0] = 32
	copy(nlri[1:5], ipv4)

	// 3. Assemble UPDATE
	// Unfeasible Routes Length: 2 bytes (0)
	// Path Attribute Length: 2 bytes
	// Attributes
	// NLRI
	attrLen := uint16(len(attrs))
	payloadLen := 2 + 2 + len(attrs) + len(nlri)
	totalLen := uint16(HeaderLength + payloadLen)

	hdr := EncodeHeader(totalLen, TypeUpdate)
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], 0) // No withdrawn routes
	binary.BigEndian.PutUint16(payload[2:4], attrLen)

	result := append(hdr, payload...)
	result = append(result, attrs...)
	result = append(result, nlri...)

	return result, nil
}

// EncodeWithdrawalMessage creates an RFC 4271 UPDATE message with Withdrawn Routes.
func (s *Speaker) EncodeWithdrawalMessage(ip net.IP) ([]byte, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 withdrawal supported, got %v", ip)
	}

	// Withdrawn route: 1 byte prefix length (32) + 4 bytes IP
	withdrawnLen := uint16(5)
	withdrawn := make([]byte, 5)
	withdrawn[0] = 32
	copy(withdrawn[1:5], ipv4)

	// Total length: Header(19) + WithdrawnLen(2) + Withdrawn(5) + PathAttrLen(2)
	totalLen := uint16(HeaderLength + 2 + 5 + 2)
	hdr := EncodeHeader(totalLen, TypeUpdate)

	payload := make([]byte, 2+5+2)
	binary.BigEndian.PutUint16(payload[0:2], withdrawnLen)
	copy(payload[2:7], withdrawn)
	binary.BigEndian.PutUint16(payload[7:9], 0) // Path attribute length = 0

	return append(hdr, payload...), nil
}

// ReadBGPMessage reads a single complete BGP message from a stream.
func ReadBGPMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}

	// Verify 16-byte marker
	for i := 0; i < 16; i++ {
		if hdr[i] != MarkerOctet {
			return nil, fmt.Errorf("invalid BGP marker at index %d: 0x%02x", i, hdr[i])
		}
	}

	msgLen := binary.BigEndian.Uint16(hdr[16:18])
	if msgLen < HeaderLength || msgLen > 4096 {
		return nil, fmt.Errorf("invalid BGP message length: %d", msgLen)
	}

	payloadLen := int(msgLen) - HeaderLength
	if payloadLen == 0 {
		return hdr, nil
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return append(hdr, payload...), nil
}
