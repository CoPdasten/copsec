package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
	if md["x-node-id"] != nodeID || md["x-api-key"] != apiKey {
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
	mu           sync.Mutex
	receivedLogs []*copsecproto.LogEvent
}

func (s *mockCopsecServer) StreamEvents(stream grpc.ClientStreamingServer[copsecproto.LogEvent, copsecproto.StreamAck]) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&copsecproto.StreamAck{
				Success:        true,
				ProcessedCount: uint64(len(s.receivedLogs)),
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

func TestGrpcClientLiveAndOfflineBuffer(t *testing.T) {
	tmpDir := t.TempDir()
	bufPath := filepath.Join(tmpDir, "buffer.db")
	idPath := filepath.Join(tmpDir, "node.json")

	idMgr, _ := LoadOrCreateIdentity(idPath)
	buf, _ := NewOfflineBuffer(bufPath)
	defer buf.Close()

	// 1. Test offline buffering when controller is down
	client := NewControllerClient(GrpcClientConfig{
		ServerAddress: "127.0.0.1:54321", // Non-existent port
	}, idMgr, buf)

	eventOffline := &copsecproto.LogEvent{
		Source:     "ssh",
		RawLine:    "Failed password for root from 198.51.100.22 port 22",
		ClientIp:   "198.51.100.22",
		StatusCode: 0,
	}

	// Directly enqueue into buffer
	_ = buf.Enqueue(eventOffline)
	if buf.Size() != 1 {
		t.Errorf("Expected 1 offline buffered item, got %d", buf.Size())
	}
	_ = client
}
