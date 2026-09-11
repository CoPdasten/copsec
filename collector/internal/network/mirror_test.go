package network

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/copsec/collector/internal/dpi"
	"github.com/copsec/collector/pkg/ebpf"
)

// TestExtractClientIPAndPayload verifies attribution across PROXY v1, PROXY v2, and HTTP headers.
func TestExtractClientIPAndPayload(t *testing.T) {
	// 1. PROXY Protocol v1
	v1Payload := []byte("PROXY TCP4 203.0.113.195 10.0.0.1 55432 443\r\nGET /login HTTP/1.1\r\nHost: bank.local\r\n\r\n")
	ip1, body1 := ExtractClientIPAndPayload(v1Payload)
	if ip1 != "203.0.113.195" {
		t.Errorf("PROXY v1 expected IP 203.0.113.195, got %s", ip1)
	}
	if string(body1) != "GET /login HTTP/1.1\r\nHost: bank.local\r\n\r\n" {
		t.Errorf("PROXY v1 body mismatch: %s", string(body1))
	}

	// 2. PROXY Protocol v2 (Binary)
	// Header: 12-byte sig + 0x21 (PROXY) + 0x11 (TCP over IPv4) + length (12 bytes) + srcIP (198.51.100.33) + dstIP + ports
	v2Sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	v2Header := append(v2Sig, 0x21, 0x11, 0x00, 0x0C)                               // 16 bytes
	v2Addresses := []byte{198, 51, 100, 33, 10, 0, 0, 1, 0x1F, 0x90, 0x01, 0xBB} // src: 198.51.100.33
	httpReq := []byte("POST /api/transfer HTTP/1.1\r\nHost: secure.bank\r\n\r\n")
	v2Buffer := append(append(v2Header, v2Addresses...), httpReq...)

	ip2, body2 := ExtractClientIPAndPayload(v2Buffer)
	if ip2 != "198.51.100.33" {
		t.Errorf("PROXY v2 expected IP 198.51.100.33, got %s", ip2)
	}
	if string(body2) != string(httpReq) {
		t.Errorf("PROXY v2 body mismatch: %s", string(body2))
	}

	// 3. X-Forwarded-For HTTP Header
	xffReq := []byte("GET /search HTTP/1.1\r\nHost: bank.local\r\nX-Forwarded-For: 198.51.100.88, 10.0.0.1\r\nUser-Agent: curl/7.88\r\n\r\n")
	ip3, _ := ExtractClientIPAndPayload(xffReq)
	if ip3 != "198.51.100.88" {
		t.Errorf("XFF expected IP 198.51.100.88, got %s", ip3)
	}

	// 4. X-Real-IP HTTP Header
	xRealReq := []byte("GET /status HTTP/1.1\r\nHost: bank.local\r\nX-Real-IP: 203.0.113.77\r\n\r\n")
	ip4, _ := ExtractClientIPAndPayload(xRealReq)
	if ip4 != "203.0.113.77" {
		t.Errorf("X-Real-IP expected IP 203.0.113.77, got %s", ip4)
	}
}

// TestTLSMirrorServerIngress verifies that mirrored decrypted streams trigger DPI and quarantine the genuine client IP.
func TestTLSMirrorServerIngress(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copsec_mirror_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "mirror.sock")

	xdp := ebpf.GetXDPEngine()
	_ = xdp.Flush()

	inspector := dpi.NewDPIInspector()
	server := NewTLSMirrorServer(sockPath, inspector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start mirror server: %v", err)
	}
	defer server.Stop()

	// Wait for socket to be ready
	time.Sleep(50 * time.Millisecond)

	// Simulate Nginx/HAProxy mirroring a decrypted HTTP request with an embedded SQL injection exploit
	clientIP := "198.51.100.66"
	mirrorPayload := "POST /api/v1/search HTTP/1.1\r\n" +
		"Host: corporate.bank.local\r\n" +
		"X-Forwarded-For: " + clientIP + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"q=1' union select username, password from information_schema.tables--"

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to connect to mirror unix socket: %v", err)
	}

	_, err = conn.Write([]byte(mirrorPayload))
	if err != nil {
		t.Fatalf("Failed to write mirror payload: %v", err)
	}
	_ = conn.Close()

	// Allow worker goroutine to process inspection and reactions
	time.Sleep(150 * time.Millisecond)

	// Verify that the real client IP (not 127.0.0.1 or unix socket) was banned in eBPF map!
	if !xdp.IsBanned(clientIP) {
		t.Fatalf("Expected real client IP %s to be banned in eBPF map following exploit detection in mirror", clientIP)
	}

	processed, threats := server.GetStats()
	if processed == 0 {
		t.Errorf("Expected packetsProcessed > 0, got %d", processed)
	}
	if threats == 0 {
		t.Errorf("Expected threatsDetected > 0, got %d", threats)
	}
}
