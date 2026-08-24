package tarpit

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTarpitEngineTrapSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var trappedSession TarpitSession
	engine := NewTarpitEngine("127.0.0.1:12223", func(s TarpitSession) {
		trappedSession = s
	})
	_ = trappedSession

	err := engine.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start tarpit: %v", err)
	}
	defer engine.Close()

	// Connect mock scanner
	conn, err := net.DialTimeout("tcp", "127.0.0.1:12223", 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial tarpit: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	sessions := engine.GetActiveSessions()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 active trapped session, got %d", len(sessions))
	}

	if sessions[0].RemoteIP != "127.0.0.1" {
		t.Errorf("Expected remote IP 127.0.0.1, got %s", sessions[0].RemoteIP)
	}

	stats := engine.GetStats()
	if stats["total_connections_held"].(uint64) != 1 {
		t.Errorf("Expected 1 total connection held, got %v", stats["total_connections_held"])
	}
}
