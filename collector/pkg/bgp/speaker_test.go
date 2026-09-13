package bgp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEncodeHeaderAndKeepalive(t *testing.T) {
	ka := EncodeKeepaliveMessage()
	if len(ka) != HeaderLength {
		t.Fatalf("expected keepalive length %d, got %d", HeaderLength, len(ka))
	}

	for i := 0; i < 16; i++ {
		if ka[i] != MarkerOctet {
			t.Errorf("marker byte %d != 0xFF", i)
		}
	}

	msgLen := binary.BigEndian.Uint16(ka[16:18])
	if msgLen != HeaderLength {
		t.Errorf("length field != %d, got %d", HeaderLength, msgLen)
	}

	if ka[18] != TypeKeepalive {
		t.Errorf("type field != %d, got %d", TypeKeepalive, ka[18])
	}
}

func TestEncodeOpenMessage(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		HoldTime: 90 * time.Second,
		RouterID: "192.168.1.8",
	}
	s := NewSpeaker(cfg)
	open := s.EncodeOpenMessage()

	if len(open) != HeaderLength+10 {
		t.Fatalf("expected open message length %d, got %d", HeaderLength+10, len(open))
	}

	if open[18] != TypeOpen {
		t.Errorf("expected msg type %d, got %d", TypeOpen, open[18])
	}

	payload := open[HeaderLength:]
	if payload[0] != BGPVersion {
		t.Errorf("expected BGP version %d, got %d", BGPVersion, payload[0])
	}

	as := binary.BigEndian.Uint16(payload[1:3])
	if as != 65001 {
		t.Errorf("expected ASN 65001, got %d", as)
	}

	holdTime := binary.BigEndian.Uint16(payload[3:5])
	if holdTime != 90 {
		t.Errorf("expected hold time 90s, got %d", holdTime)
	}

	rid := net.IP(payload[5:9]).String()
	if rid != "192.168.1.8" {
		t.Errorf("expected router ID 192.168.1.8, got %s", rid)
	}
}

func TestEncodeRTBHUpdateMessage(t *testing.T) {
	cfg := Config{
		LocalAS:          65001,
		BlackholeNextHop: "192.0.2.1",
	}
	s := NewSpeaker(cfg)

	targetIP := net.ParseIP("192.168.1.12")
	msg, err := s.EncodeRTBHUpdateMessage(targetIP)
	if err != nil {
		t.Fatalf("EncodeRTBHUpdateMessage failed: %v", err)
	}

	if len(msg) < HeaderLength+4 {
		t.Fatalf("message too short: %d", len(msg))
	}

	if msg[18] != TypeUpdate {
		t.Errorf("expected msg type UPDATE (2), got %d", msg[18])
	}

	// Verify communities attribute (RFC 7999 65535:666 = 0xFFFF029A)
	foundBlackholeComm := false
	for i := 0; i < len(msg)-4; i++ {
		val := binary.BigEndian.Uint32(msg[i : i+4])
		if val == BlackholeCommunity {
			foundBlackholeComm = true
			break
		}
	}
	if !foundBlackholeComm {
		t.Errorf("RFC 7999 Blackhole community 65535:666 (0xFFFF029A) not found in UPDATE message")
	}

	// Verify next-hop 192.0.2.1
	foundNextHop := false
	for i := 0; i < len(msg)-4; i++ {
		if msg[i] == 192 && msg[i+1] == 0 && msg[i+2] == 2 && msg[i+3] == 1 {
			foundNextHop = true
			break
		}
	}
	if !foundNextHop {
		t.Errorf("Blackhole next-hop 192.0.2.1 not found in UPDATE message")
	}

	// Verify NLRI: ends with prefix /32 (32) and target IP
	nlriLen := len(msg)
	if msg[nlriLen-5] != 32 {
		t.Errorf("expected NLRI prefix length 32, got %d", msg[nlriLen-5])
	}
	ipInNLRI := net.IP(msg[nlriLen-4:]).String()
	if ipInNLRI != "192.168.1.12" {
		t.Errorf("expected NLRI target IP 192.168.1.12, got %s", ipInNLRI)
	}
}

func TestEncodeWithdrawalMessage(t *testing.T) {
	s := NewSpeaker(Config{LocalAS: 65001})
	targetIP := net.ParseIP("192.168.1.12")

	msg, err := s.EncodeWithdrawalMessage(targetIP)
	if err != nil {
		t.Fatalf("EncodeWithdrawalMessage failed: %v", err)
	}

	if msg[18] != TypeUpdate {
		t.Errorf("expected msg type UPDATE (2), got %d", msg[18])
	}

	payload := msg[HeaderLength:]
	withdrawnLen := binary.BigEndian.Uint16(payload[0:2])
	if withdrawnLen != 5 {
		t.Errorf("expected withdrawn length 5, got %d", withdrawnLen)
	}

	if payload[2] != 32 {
		t.Errorf("expected withdrawn prefix length 32, got %d", payload[2])
	}

	withdrawnIP := net.IP(payload[3:7]).String()
	if withdrawnIP != "192.168.1.12" {
		t.Errorf("expected withdrawn IP 192.168.1.12, got %s", withdrawnIP)
	}
}

func TestAutonomousRTBHTriggerAndRecovery(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		LocalAS:          65001,
		PeerAS:           65001,
		RouterID:         "192.168.1.8",
		PeerAddress:      "127.0.0.1:179",
		RTBHThresholdPPS: 200000,
		RecoveryDuration: 50 * time.Millisecond,
		BlackholeNextHop: "192.0.2.1",
	}

	s := NewSpeaker(cfg)

	// Ingress rate below threshold -> no RTBH
	s.RecordIngressMetrics("192.168.1.50", 150000)
	routes := s.GetBlackholedRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 RTBH routes below threshold, got %d", len(routes))
	}

	// Ingress rate >= 200,000 PPS -> triggers autonomous RTBH
	s.RecordIngressMetrics("192.168.1.50", 250000)
	routes = s.GetBlackholedRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 RTBH route, got %d", len(routes))
	}
	if !routes[0].Active {
		t.Errorf("expected route to be active")
	}
	if routes[0].Prefix != "192.168.1.50/32" {
		t.Errorf("expected prefix 192.168.1.50/32, got %s", routes[0].Prefix)
	}

	advCount, withCount, active := s.Stats()
	if advCount != 1 || active != 1 {
		t.Errorf("expected 1 advertised route, got adv=%d, active=%d", advCount, active)
	}

	// Quiet period: sleep beyond RecoveryDuration (50ms)
	time.Sleep(70 * time.Millisecond)
	s.checkRecovery()

	routes = s.GetBlackholedRoutes()
	if len(routes) != 1 || routes[0].Active {
		t.Errorf("expected route to be marked inactive after quiet recovery")
	}

	advCount, withCount, active = s.Stats()
	if withCount != 1 || active != 0 {
		t.Errorf("expected withCount=1 and active=0, got with=%d active=%d", withCount, active)
	}
}

func TestSpeakerFSMWithNetPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cfg := Config{
		Enabled:     true,
		LocalAS:     65001,
		PeerAS:      65001,
		RouterID:    "192.168.1.8",
		PeerAddress: "127.0.0.1:179",
		HoldTime:    3 * time.Second,
	}

	s := NewSpeaker(cfg)
	s.SetCustomDialer(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer s.Stop()

	// Server side emulation:
	// 1. Read client OPEN
	clientOpen, err := ReadBGPMessage(serverConn)
	if err != nil {
		t.Fatalf("failed reading client OPEN: %v", err)
	}
	if clientOpen[18] != TypeOpen {
		t.Fatalf("expected TypeOpen, got %d", clientOpen[18])
	}

	// 2. Send server OPEN
	serverOpen := s.EncodeOpenMessage()
	if _, err := serverConn.Write(serverOpen); err != nil {
		t.Fatalf("failed sending server OPEN: %v", err)
	}

	// 3. Client should send KEEPALIVE in response to server OPEN
	clientKA, err := ReadBGPMessage(serverConn)
	if err != nil {
		t.Fatalf("failed reading client KEEPALIVE: %v", err)
	}
	if clientKA[18] != TypeKeepalive {
		t.Fatalf("expected client KEEPALIVE, got %d", clientKA[18])
	}

	// 4. Send server KEEPALIVE to transition client to ESTABLISHED
	serverKA := EncodeKeepaliveMessage()
	if _, err := serverConn.Write(serverKA); err != nil {
		t.Fatalf("failed sending server KEEPALIVE: %v", err)
	}

	// Wait for client to process and establish
	time.Sleep(50 * time.Millisecond)
	if s.GetState() != StateEstablished {
		t.Errorf("expected client state ESTABLISHED, got %s", s.GetState())
	}
}
