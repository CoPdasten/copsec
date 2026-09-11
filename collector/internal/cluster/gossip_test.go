package cluster

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/copsec/collector/pkg/ebpf"
)

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestThreatSyncBroadcastSerialization(t *testing.T) {
	orig := ThreatSyncBroadcast{
		AttackerIP:    net.ParseIP("198.51.100.77").To4(),
		QuarantineTTL: 3600,
		SourceNodeID:  "pardus1",
	}

	data, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Header verification
	if data[0] != GossipMagic || data[1] != GossipMsgThreatSync {
		t.Fatalf("Magic or type mismatch: 0x%02x 0x%02x", data[0], data[1])
	}

	var decoded ThreatSyncBroadcast
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if !decoded.AttackerIP.Equal(orig.AttackerIP) {
		t.Errorf("Expected IP %v, got %v", orig.AttackerIP, decoded.AttackerIP)
	}
	if decoded.QuarantineTTL != orig.QuarantineTTL {
		t.Errorf("Expected TTL %d, got %d", orig.QuarantineTTL, decoded.QuarantineTTL)
	}
	if decoded.SourceNodeID != orig.SourceNodeID {
		t.Errorf("Expected node ID %s, got %s", orig.SourceNodeID, decoded.SourceNodeID)
	}

	// Truncated data test
	shortData := data[:8]
	if err := decoded.UnmarshalBinary(shortData); err == nil {
		t.Error("Expected error unmarshaling truncated data")
	}

	// Invalid magic test
	corruptData := make([]byte, len(data))
	copy(corruptData, data)
	corruptData[0] = 0xFF
	if err := decoded.UnmarshalBinary(corruptData); err == nil {
		t.Error("Expected error unmarshaling invalid magic")
	}
}

func TestDistributedThreatSynchronizationAcrossNodes(t *testing.T) {
	port1, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	port2, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}

	var node2Received sync.WaitGroup
	node2Received.Add(1)

	var receivedIP string
	var receivedTTL uint32
	var receivedNode string
	var mu sync.Mutex

	// 1. Initialize Node 1 ("pardus1")
	cfg1 := GossipConfig{
		NodeID:   "pardus1",
		BindAddr: "127.0.0.1",
		BindPort: port1,
	}
	node1, err := NewGossipCluster(cfg1)
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	defer node1.Shutdown()

	// 2. Initialize Node 2 ("chachy") with ban callback
	cfg2 := GossipConfig{
		NodeID:   "chachy",
		BindAddr: "127.0.0.1",
		BindPort: port2,
		Peers:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
		BanHandler: func(ip net.IP, ttl uint32, srcNode string) error {
			mu.Lock()
			receivedIP = ip.String()
			receivedTTL = ttl
			receivedNode = srcNode
			mu.Unlock()
			node2Received.Done()
			return nil
		},
	}
	node2, err := NewGossipCluster(cfg2)
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	defer node2.Shutdown()

	// Wait for peer discovery
	time.Sleep(300 * time.Millisecond)

	// Node 1 detects an attack at line rate and broadcasts it
	attackerIP := net.ParseIP("203.0.113.99").To4()
	quarantineDuration := uint32(900) // 15 mins

	if err := node1.BroadcastThreat(attackerIP, quarantineDuration); err != nil {
		t.Fatalf("BroadcastThreat failed: %v", err)
	}

	// Await propagation to Node 2
	done := make(chan struct{})
	go func() {
		node2Received.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for gossip threat synchronization on Node 2")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedIP != "203.0.113.99" {
		t.Errorf("Expected received IP 203.0.113.99, got %s", receivedIP)
	}
	if receivedTTL != 900 {
		t.Errorf("Expected received TTL 900, got %d", receivedTTL)
	}
	if receivedNode != "pardus1" {
		t.Errorf("Expected received source node pardus1, got %s", receivedNode)
	}

	bcast1, _ := node1.Metrics()
	if bcast1 != 1 {
		t.Errorf("Expected node1 broadcast count 1, got %d", bcast1)
	}
	_, rx2 := node2.Metrics()
	if rx2 != 1 {
		t.Errorf("Expected node2 rx count 1, got %d", rx2)
	}
}

func TestGossipClusterDefaultEBPFBanMapPopulator(t *testing.T) {
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}

	xdp := ebpf.GetXDPEngine()
	if xdp == nil {
		t.Fatal("eBPF XDP engine must not be nil")
	}

	cfg := GossipConfig{
		NodeID:   "chachy-edge",
		BindAddr: "127.0.0.1",
		BindPort: port,
		// No custom BanHandler: test default ebpf ban map population
	}
	cluster, err := NewGossipCluster(cfg)
	if err != nil {
		t.Fatalf("Failed to start cluster: %v", err)
	}
	defer cluster.Shutdown()

	// Simulate inbound frame from remote sensor "pardus1"
	testPayload := ThreatSyncBroadcast{
		AttackerIP:    net.ParseIP("198.51.100.123").To4(),
		QuarantineTTL: 1800,
		SourceNodeID:  "pardus1",
	}
	frame, err := testPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	// Trigger NotifyMsg on delegate directly to simulate gossip arrival
	delegate := cluster.Delegate()
	delegate.NotifyMsg(frame)

	// Verify the IP is now banned in local eBPF engine
	if !xdp.IsBanned("198.51.100.123") {
		t.Errorf("Expected 198.51.100.123 to be banned in eBPF engine after gossip sync")
	}

	// Cleanup
	_ = xdp.RemoveBan("198.51.100.123")
}
