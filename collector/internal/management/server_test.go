package management

import (
	"context"
	"testing"
	"time"

	managementproto "github.com/copsec/collector/proto/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestIsLoopbackAddress(t *testing.T) {
	cases := []struct {
		addr     string
		expected bool
	}{
		{"127.0.0.1:50052", true},
		{"127.0.0.2:8080", true},
		{"localhost:50052", true},
		{"unix:///var/run/copsec/mgmt.sock", true},
		{"/var/run/copsec/mgmt.sock", true},
		{"0.0.0.0:50052", false},
		{"192.168.1.10:50052", false},
		{"10.0.0.1:50052", false},
		{"", false},
	}

	for _, c := range cases {
		got := IsLoopbackAddress(c.addr)
		if got != c.expected {
			t.Errorf("IsLoopbackAddress(%q) = %v; want %v", c.addr, got, c.expected)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	// 1. Wildcard / non-loopback rejected by default
	cfgWildcard := &Config{
		ListenAddr:       "0.0.0.0:50052",
		EnableRemoteMgmt: false,
		AuthSecret:       "test-secret",
	}
	if err := ValidateConfig(cfgWildcard); err == nil {
		t.Errorf("expected error when binding to 0.0.0.0 without EnableRemoteMgmt, got nil")
	}

	cfgRemoteWithoutTLS := &Config{
		ListenAddr:       "192.168.1.50:50052",
		EnableRemoteMgmt: true,
		AuthSecret:       "test-secret",
	}
	if err := ValidateConfig(cfgRemoteWithoutTLS); err == nil {
		t.Errorf("expected error when EnableRemoteMgmt is true but TLS certs missing, got nil")
	}

	// 2. Loopback allowed without remote mgmt flag
	cfgLoopback := &Config{
		ListenAddr:       "127.0.0.1:50052",
		EnableRemoteMgmt: false,
		AuthSecret:       "test-secret",
	}
	if err := ValidateConfig(cfgLoopback); err != nil {
		t.Errorf("unexpected error for loopback config: %v", err)
	}

	// 3. Unix socket allowed without remote mgmt flag
	cfgUDS := &Config{
		ListenAddr:       "unix:///tmp/test_copsec_mgmt.sock",
		EnableRemoteMgmt: false,
		AuthSecret:       "test-secret",
	}
	if err := ValidateConfig(cfgUDS); err != nil {
		t.Errorf("unexpected error for UDS config: %v", err)
	}
}

func TestAuthInterceptor(t *testing.T) {
	secret := "authoritative-secret-key-12345"
	unaryInterceptor, _ := NewAuthInterceptor(secret)

	mockHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	}

	// Case 1: Missing metadata
	_, err := unaryInterceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, mockHandler)
	if err == nil || status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected codes.Unauthenticated for missing metadata, got: %v", err)
	}

	// Case 2: Invalid Bearer token
	ctxBad := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token"))
	_, err = unaryInterceptor(ctxBad, "req", &grpc.UnaryServerInfo{}, mockHandler)
	if err == nil || status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected codes.Unauthenticated for invalid Bearer token, got: %v", err)
	}

	// Case 3: Valid Bearer token
	ctxGood := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer authoritative-secret-key-12345"))
	resp, err := unaryInterceptor(ctxGood, "req", &grpc.UnaryServerInfo{}, mockHandler)
	if err != nil {
		t.Errorf("unexpected error for valid Bearer token: %v", err)
	}
	if resp != "success" {
		t.Errorf("expected handler response 'success', got: %v", resp)
	}

	// Case 4: Valid x-mgmt-token
	ctxXToken := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-mgmt-token", "authoritative-secret-key-12345"))
	resp, err = unaryInterceptor(ctxXToken, "req", &grpc.UnaryServerInfo{}, mockHandler)
	if err != nil {
		t.Errorf("unexpected error for valid x-mgmt-token: %v", err)
	}
	if resp != "success" {
		t.Errorf("expected handler response 'success', got: %v", resp)
	}
}

type mockManagementServer struct {
	managementproto.UnimplementedSensorManagementServiceServer
}

func (m *mockManagementServer) GetEngineStatus(ctx context.Context, req *managementproto.EngineStatusRequest) (*managementproto.EngineStatusResponse, error) {
	return &managementproto.EngineStatusResponse{
		ActiveRulesCount: 42,
		EngineVersion:    2,
	}, nil
}

func TestManagementServerE2E(t *testing.T) {
	secret := "cluster-preshared-secret-key-999"
	cfg := &Config{
		ListenAddr:       "127.0.0.1:0",
		EnableRemoteMgmt: false,
		AuthSecret:       secret,
	}

	mockSrv := &mockManagementServer{}
	server, err := NewServer(cfg, mockSrv)
	if err != nil {
		t.Fatalf("failed to create management server: %v", err)
	}
	server.Start()
	defer server.Stop()

	// Connect with client
	conn, err := grpc.NewClient(server.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect to management server: %v", err)
	}
	defer conn.Close()

	client := managementproto.NewSensorManagementServiceClient(conn)

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Unauthenticated call must fail with codes.Unauthenticated
	_, err = client.GetEngineStatus(ctxTimeout, &managementproto.EngineStatusRequest{RequesterId: "auditor"})
	if err == nil {
		t.Fatalf("expected unauthenticated call to fail, got nil error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected codes.Unauthenticated, got: %v", status.Code(err))
	}

	// 2. Authenticated call with Bearer token must succeed
	ctxAuth := metadata.NewOutgoingContext(ctxTimeout, metadata.Pairs("authorization", "Bearer "+secret))
	statusResp, err := client.GetEngineStatus(ctxAuth, &managementproto.EngineStatusRequest{RequesterId: "auditor"})
	if err != nil {
		t.Fatalf("authenticated call failed: %v", err)
	}
	if statusResp.ActiveRulesCount != 42 {
		t.Errorf("expected ActiveRulesCount=42, got %d", statusResp.ActiveRulesCount)
	}
}
