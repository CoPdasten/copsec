package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/copsec/collector/pkg/honeypot"
	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
)

func TestOffsetManager(t *testing.T) {
	tmpDir := t.TempDir()
	offsetFile := filepath.Join(tmpDir, "offsets.json")

	om1 := NewOffsetManager(offsetFile)
	om1.SetOffset("/var/log/nginx/access.log", 1024)
	om1.SetOffset("/var/log/auth.log", 2048)
	if err := om1.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	om2 := NewOffsetManager(offsetFile)
	if off := om2.GetOffset("/var/log/nginx/access.log"); off != 1024 {
		t.Errorf("Expected 1024, got %d", off)
	}
	if off := om2.GetOffset("/var/log/auth.log"); off != 2048 {
		t.Errorf("Expected 2048, got %d", off)
	}
}

func TestIdentityEnrollment(t *testing.T) {
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "node.json")

	idMgr, err := LoadOrCreateIdentity(identityFile)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	nodeID := idMgr.GetNodeID()
	apiKey := idMgr.GetAPIKey()

	if nodeID == "" || apiKey == "" {
		t.Errorf("Empty nodeID or apiKey: ID=%s, Key=%s", nodeID, apiKey)
	}

	info, err := os.Stat(identityFile)
	if err != nil {
		t.Fatalf("Stat identity file failed: %v", err)
	}
	// Check 0600 mode
	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Verify gRPC metadata headers
	md, err := idMgr.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRequestMetadata failed: %v", err)
	}
	if md["x-node-id"] != nodeID || md["x-api-key"] != apiKey || md["x-node-group"] == "" {
		t.Errorf("Metadata mismatch: %v", md)
	}

	// Re-load and verify persistence
	idMgr2, err := LoadOrCreateIdentity(identityFile)
	if err != nil {
		t.Fatalf("Re-load identity failed: %v", err)
	}
	if idMgr2.GetNodeID() != nodeID || idMgr2.GetAPIKey() != apiKey {
		t.Errorf("Identity persistence mismatch: %s != %s", idMgr2.GetNodeID(), nodeID)
	}
}

func TestOfflineBufferFIFO(t *testing.T) {
	tmpDir := t.TempDir()
	bufPath := filepath.Join(tmpDir, "buffer.db")

	buf, err := NewOfflineBuffer(bufPath)
	if err != nil {
		t.Fatalf("NewOfflineBuffer failed: %v", err)
	}
	defer buf.Close()

	// Enqueue 3 events
	for i := 1; i <= 3; i++ {
		ev := &copsecproto.LogEvent{
			NodeId:     "test-node",
			Source:     "nginx",
			RawLine:    fmt.Sprintf("event-%d", i),
			ClientIp:   "198.51.100.1",
			StatusCode: 404,
		}
		if err := buf.Enqueue(ev); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}
	}

	if buf.Size() != 3 {
		t.Errorf("Expected buffer size 3, got %d", buf.Size())
	}

	// Dequeue batch
	events, ids, err := buf.DequeueBatch(2)
	if err != nil {
		t.Fatalf("DequeueBatch failed: %v", err)
	}
	if len(events) != 2 || len(ids) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
	if events[0].RawLine != "event-1" || events[1].RawLine != "event-2" {
		t.Errorf("FIFO order mismatch: %s, %s", events[0].RawLine, events[1].RawLine)
	}

	// Acknowledge first 2 items
	if err := buf.Ack(ids); err != nil {
		t.Fatalf("Ack failed: %v", err)
	}
	if buf.Size() != 1 {
		t.Errorf("Expected remaining size 1, got %d", buf.Size())
	}

	// Dequeue remaining
	remainingEvents, remainingIDs, err := buf.DequeueBatch(10)
	if err != nil {
		t.Fatalf("DequeueBatch remaining failed: %v", err)
	}
	if len(remainingEvents) != 1 || remainingEvents[0].RawLine != "event-3" {
		t.Errorf("Expected event-3 remaining, got %v", remainingEvents)
	}
	_ = buf.Ack(remainingIDs)
	if buf.Size() != 0 {
		t.Errorf("Expected empty buffer, got %d", buf.Size())
	}
}

// Mock gRPC Server implementation for integration testing
type mockCopsecServer struct {
	copsecproto.UnimplementedCopsecStreamServiceServer
	mu           sync.Mutex
	receivedLogs []*copsecproto.LogEvent
}

func (s *mockCopsecServer) StreamEvents(stream grpc.ClientStreamingServer[copsecproto.LogEvent, copsecproto.StreamAck]) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			s.mu.Lock()
			count := uint64(len(s.receivedLogs))
			s.mu.Unlock()
			return stream.SendAndClose(&copsecproto.StreamAck{
				Success:        true,
				ProcessedCount: count,
				Message:        "OK",
			})
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.receivedLogs = append(s.receivedLogs, event)
		s.mu.Unlock()
	}
}

func (s *mockCopsecServer) SendHeartbeat(ctx context.Context, in *copsecproto.Heartbeat) (*copsecproto.HeartbeatResponse, error) {
	return &copsecproto.HeartbeatResponse{Acknowledged: true, SyncIntervalSeconds: 15}, nil
}

func (s *mockCopsecServer) SyncCommands(stream grpc.BidiStreamingServer[copsecproto.CommandAck, copsecproto.SOARCommand]) error {
	return nil
}

func TestGrpcClientFlushOfflineBufferLive(t *testing.T) {
	// Start Mock gRPC Server on random port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	mockSrv := &mockCopsecServer{}
	copsecproto.RegisterCopsecStreamServiceServer(grpcServer, mockSrv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	tmpDir := t.TempDir()
	bufPath := filepath.Join(tmpDir, "buffer.db")
	idPath := filepath.Join(tmpDir, "node.json")

	idMgr, _ := LoadOrCreateIdentity(idPath)
	buf, _ := NewOfflineBuffer(bufPath)
	defer buf.Close()

	// Enqueue test events to disk buffer
	for i := 1; i <= 5; i++ {
		ev := &copsecproto.LogEvent{
			Source:      "nginx",
			RawLine:     fmt.Sprintf("GET /admin-%d HTTP/1.1 404", i),
			ClientIp:    "198.51.100.1",
			StatusCode:  404,
			TimestampMs: time.Now().UnixMilli(),
		}
		_ = buf.Enqueue(ev)
	}

	client := NewControllerClient(GrpcClientConfig{
		ServerAddress: lis.Addr().String(),
		MaxBatchSize:  10,
	}, idMgr, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, streamClient, err := client.connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to mock gRPC server: %v", err)
	}
	defer conn.Close()

	// Flush buffer to server (tests serialization and avoids opaqueInitHook segfault)
	client.flushOfflineBuffer(ctx, streamClient)

	if buf.Size() != 0 {
		t.Errorf("Expected buffer to be fully drained, remaining: %d", buf.Size())
	}

	mockSrv.mu.Lock()
	receivedCount := len(mockSrv.receivedLogs)
	mockSrv.mu.Unlock()

	if receivedCount != 5 {
		t.Errorf("Expected 5 received logs on server, got %d", receivedCount)
	}
}

func TestFallbackEngineAutonomousInspection(t *testing.T) {
	fallback := NewFallbackEngine("node-vps-test")
	fallback.SetFallbackActive(true)

	if !fallback.IsActive() {
		t.Fatalf("Expected fallback engine to be active")
	}

	// 1. Test Static Critical Detection (SQLi)
	critLog := "198.51.100.77 - - [22/Aug/2026:16:00:00 +0000] \"GET /search?q=1' UNION SELECT 1,2-- HTTP/1.1\" 200 45"
	fallback.InspectOffline(critLog, "nginx")

	fallback.mu.Lock()
	_, banned := fallback.bannedIPs["198.51.100.77"]
	fallback.mu.Unlock()

	if !banned {
		t.Fatalf("Expected IP 198.51.100.77 to be autonomously banned by fallback engine")
	}

	// 2. Test Correlational Spike Detection (3x SSH Failed Password)
	spikeIP := "198.51.100.66"
	sshLog := fmt.Sprintf("Aug 22 16:00:01 server sshd[1234]: Failed password for root from %s port 2222 ssh2", spikeIP)

	// Event 1 & 2
	fallback.InspectOffline(sshLog, "ssh")
	fallback.InspectOffline(sshLog, "ssh")

	fallback.mu.Lock()
	_, spikeBanned := fallback.bannedIPs[spikeIP]
	fallback.mu.Unlock()
	if spikeBanned {
		t.Fatalf("IP %s should not be banned after only 2 attempts", spikeIP)
	}

	// Event 3 (triggers correlation)
	fallback.InspectOffline(sshLog, "ssh")
	fallback.mu.Lock()
	_, spikeBanned = fallback.bannedIPs[spikeIP]
	fallback.mu.Unlock()
	if !spikeBanned {
		t.Fatalf("Expected IP %s to be autonomously banned after 3 attempts", spikeIP)
	}
}

func TestSuricataAndAuthParsers(t *testing.T) {
	// 1. Suricata Alert test (SQLi / Web Exploit -> T1190)
	suriAlertLine := `{"timestamp":"2026-08-23T12:34:56.789000+0000","event_type":"alert","src_ip":"198.51.100.222","src_port":44321,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":1,"signature":"ET WEB_SERVER Possible SQL Injection Attempt","category":"Web Application Attack","severity":1}}`
	suriEv, ok := parseSuricataLine(suriAlertLine)
	if !ok {
		t.Fatalf("Expected parseSuricataLine to succeed on JSON")
	}
	if suriEv.Source != "suricata" || suriEv.ClientIp != "198.51.100.222" || suriEv.ThreatScore != 85 || suriEv.MitreTechniqueId != "T1190" {
		t.Errorf("Unexpected suricata alert event: %+v", suriEv)
	}

	// 2. Suricata Flow/DNS test
	suriFlowLine := `{"timestamp":"2026-08-23T12:34:56.789000+0000","event_type":"flow","src_ip":"192.168.1.50","dest_ip":"1.1.1.1","proto":"UDP"}`
	suriFlowEv, ok := parseSuricataLine(suriFlowLine)
	if !ok {
		t.Fatalf("Expected parseSuricataLine to succeed on flow JSON")
	}
	if suriFlowEv.ThreatScore != 0 || suriFlowEv.ClientIp != "192.168.1.50" || suriFlowEv.MitreTechniqueId != "" {
		t.Errorf("Unexpected suricata flow event: %+v", suriFlowEv)
	}

	// 2b. Suricata DNS Query to 8.8.8.8
	suriDNSLine := `{"timestamp":"2026-08-23T12:34:56.789000+0000","event_type":"dns","src_ip":"8.8.8.8","dest_ip":"10.0.0.5","proto":"UDP","dns":{"type":"query","rrname":"example.com"}}`
	suriDNSEv, ok := parseSuricataLine(suriDNSLine)
	if !ok {
		t.Fatalf("Expected parseSuricataLine to succeed on dns JSON")
	}
	if suriDNSEv.ThreatScore != 0 || suriDNSEv.MitreTechniqueId != "" {
		t.Errorf("Expected 8.8.8.8 DNS query to have ThreatScore 0 and empty MITRE, got: %+v", suriDNSEv)
	}

	// 3. Auth Failed Password test
	authFailLine := `Aug 23 12:00:00 vps sshd[5678]: Failed password for root from 203.0.113.88 port 54321 ssh2`
	authFailEv, ok := parseAuthLine(authFailLine)
	if !ok {
		t.Fatalf("Expected parseAuthLine to succeed")
	}
	if authFailEv.Source != "auth" || authFailEv.ClientIp != "203.0.113.88" || authFailEv.ThreatScore != 70 || authFailEv.MitreTechniqueId != "T1110.001" {
		t.Errorf("Unexpected auth fail event: %+v", authFailEv)
	}

	// 4. Auth Sudo test
	authSudoLine := `Aug 23 12:00:00 vps sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash`
	authSudoEv, ok := parseAuthLine(authSudoLine)
	if !ok {
		t.Fatalf("Expected parseAuthLine to succeed on sudo")
	}
	if authSudoEv.ThreatScore != 20 || authSudoEv.RuleId != "sudo_execution" {
		t.Errorf("Unexpected auth sudo event: %+v", authSudoEv)
	}

	// 5. ParseLogSourceLine Dispatcher test
	dispatched := ParseLogSourceLine("suricata", suriAlertLine, time.Now().UnixMilli())
	if dispatched.ThreatScore != 85 || dispatched.ClientIp != "198.51.100.222" {
		t.Errorf("ParseLogSourceLine dispatcher failed for suricata: %+v", dispatched)
	}
}

func TestShadowHoneypotRedirection(t *testing.T) {
	hp := honeypot.NewShadowHoneypot("127.0.0.1:12224", "127.0.0.1:18088", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := hp.Start(ctx); err != nil {
		t.Logf("Honeypot start notice: %v", err)
	}
	defer hp.Close()

	targetIP := "198.51.100.88"
	_ = hp.RedirectAttackerToHoneypot(targetIP, "ALL")
	_ = hp.RemoveRedirection(targetIP)

	stats := hp.GetStats()
	if stats["ssh_bind_port"].(int) != 2222 {
		t.Errorf("Unexpected stats: %+v", stats)
	}
}
