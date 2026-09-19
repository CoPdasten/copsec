package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGRPCControlPlaneAuthentication(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_grpc_auth.db")

	store, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize StorageEngine: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	server.SetFleetKey("fleet-secret-key-12345678")

	// 1. Missing metadata
	_, err = server.authenticate(context.Background())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected codes.Unauthenticated for missing metadata, got: %v", err)
	}

	// 2. Missing credentials in metadata
	ctxEmptyMD := metadata.NewIncomingContext(context.Background(), metadata.Pairs("foo", "bar"))
	_, err = server.authenticate(ctxEmptyMD)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected codes.Unauthenticated for missing node credentials, got: %v", err)
	}

	// 3. New node enrollment without valid fleet key -> REJECTED
	ctxNewNodeNoFleet := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-node-id", "node-rogue-01",
		"x-api-key", "random-invalid-key-9999",
	))
	_, err = server.authenticate(ctxNewNodeNoFleet)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected codes.Unauthenticated for rogue node enrollment without fleet key, got: %v", err)
	}

	// 4. New node enrollment WITH valid fleet key -> ACCEPTED
	ctxNewNodeWithFleet := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-node-id", "node-legit-01",
		"x-api-key", "legit-agent-key-12345",
		"x-fleet-key", "fleet-secret-key-12345678",
	))
	nodeID, err := server.authenticate(ctxNewNodeWithFleet)
	if err != nil {
		t.Fatalf("Expected successful enrollment with valid fleet key, got error: %v", err)
	}
	if nodeID != "node-legit-01" {
		t.Fatalf("Expected nodeID node-legit-01, got %s", nodeID)
	}

	// 5. Subsequent connection to existing node with WRONG api key -> REJECTED
	ctxExistingNodeWrongKey := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-node-id", "node-legit-01",
		"x-api-key", "wrong-impersonator-key-9999",
	))
	_, err = server.authenticate(ctxExistingNodeWrongKey)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected codes.Unauthenticated for node key mismatch, got: %v", err)
	}

	// 6. Subsequent connection to existing node with VALID api key -> ACCEPTED
	ctxExistingNodeValidKey := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-node-id", "node-legit-01",
		"x-api-key", "legit-agent-key-12345",
	))
	nodeID, err = server.authenticate(ctxExistingNodeValidKey)
	if err != nil {
		t.Fatalf("Expected successful authentication for registered node with matching key, got error: %v", err)
	}
	if nodeID != "node-legit-01" {
		t.Fatalf("Expected nodeID node-legit-01, got %s", nodeID)
	}
}

func TestGRPCServerInterceptors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_grpc_interceptor.db")

	store, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize StorageEngine: %v", err)
	}
	defer store.Close()

	analyzer := NewRuleEngine("")
	server := NewCentralServer(store, analyzer)
	server.SetFleetKey("fleet-secret-test-key-999")

	// Start gRPC server on random loopback port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	grpcServer, err := StartGRPCServer(addr, server)
	if err != nil {
		t.Fatalf("StartGRPCServer failed: %v", err)
	}
	defer grpcServer.Stop()

	// Dial gRPC server using in-process loopback
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatalf("Failed to dial test gRPC server: %v", err)
	}
	defer conn.Close()

	client := copsecproto.NewCopsecStreamServiceClient(conn)

	// Call SendHeartbeat without metadata -> must be rejected by UnaryAuthInterceptor
	_, err = client.SendHeartbeat(context.Background(), &copsecproto.Heartbeat{
		NodeId: "test-node",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected Unauthenticated from interceptor without metadata, got: %v", err)
	}

	// Call SendHeartbeat with valid fleet key metadata -> must succeed through interceptor
	ctxValid := metadata.AppendToOutgoingContext(context.Background(),
		"x-node-id", "test-node-interceptor",
		"x-api-key", "test-agent-key-interceptor-1",
		"x-fleet-key", "fleet-secret-test-key-999",
	)
	resp, err := client.SendHeartbeat(ctxValid, &copsecproto.Heartbeat{
		NodeId: "test-node-interceptor",
	})
	if err != nil {
		t.Fatalf("Expected successful SendHeartbeat with valid fleet credentials, got: %v", err)
	}
	if resp == nil || !resp.Acknowledged {
		t.Fatalf("Expected Heartbeat ACK, got: %v", resp)
	}
}
