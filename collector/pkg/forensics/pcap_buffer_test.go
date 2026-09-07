package forensics

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPCAPBufferCircularEviction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copsec-forensics-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Small buffer of 1KB and 2s horizon to test eviction
	buffer := NewPCAPBuffer(1024, 2*time.Second, tempDir)

	// Ingest 50 packets
	for i := 0; i < 50; i++ {
		buffer.Ingest("192.168.1.100", "10.0.0.1", 1000+i, 80, 6, []byte("GET / HTTP/1.1\r\nHost: target\r\n\r\n"))
	}

	buffer.mu.RLock()
	packetCount := len(buffer.packets)
	currSize := buffer.currentSize
	buffer.mu.RUnlock()

	if currSize > 1024 {
		t.Fatalf("Buffer current size %d exceeded max limit 1024", currSize)
	}
	if packetCount == 0 {
		t.Fatalf("Expected buffered packets, got 0")
	}

	// Test time horizon eviction
	time.Sleep(2100 * time.Millisecond)
	buffer.Ingest("192.168.1.100", "10.0.0.1", 9999, 80, 6, []byte("LATE_PACKET"))

	buffer.mu.RLock()
	newCount := len(buffer.packets)
	buffer.mu.RUnlock()

	// All old packets should be evicted, leaving only the newest packet
	if newCount != 1 {
		t.Fatalf("Expected exactly 1 packet after time expiration eviction, got %d", newCount)
	}
}

func TestPCAPBufferSnapshotOnBan(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copsec-pcap-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	buffer := NewPCAPBuffer(10*1024*1024, 30*time.Second, tempDir)

	// Ingest packets from multiple IPs
	targetAttacker := "203.0.113.55"
	innocentIP := "198.51.100.10"

	for i := 0; i < 5; i++ {
		buffer.Ingest(targetAttacker, "10.0.0.1", 50000+i, 443, 6, []byte("MALICIOUS_PAYLOAD_EXPLOIT"))
		buffer.Ingest(innocentIP, "10.0.0.1", 40000+i, 80, 6, []byte("BENIGN_TRAFFIC"))
	}

	// Trigger Snapshot for attacker IP
	snapshot, err := buffer.SnapshotForIP(targetAttacker, "Autonomous Auto-Ban SOAR Triggered")
	if err != nil {
		t.Fatalf("SnapshotForIP failed: %v", err)
	}

	if snapshot.PacketCount != 5 {
		t.Fatalf("Expected 5 matching packets for attacker %s, got %d", targetAttacker, snapshot.PacketCount)
	}

	// Verify PCAP file on disk
	pcapData, err := os.ReadFile(snapshot.FilePath)
	if err != nil {
		t.Fatalf("Failed to read created PCAP file: %v", err)
	}

	if len(pcapData) < 24 {
		t.Fatalf("PCAP file too small (%d bytes), missing global header", len(pcapData))
	}

	// Validate Libpcap Magic Number: 0xa1b2c3d4
	magic := binary.LittleEndian.Uint32(pcapData[0:4])
	if magic != 0xa1b2c3d4 {
		t.Fatalf("Invalid PCAP magic number: 0x%x, expected 0xa1b2c3d4", magic)
	}

	// Validate Version 2.4
	major := binary.LittleEndian.Uint16(pcapData[4:6])
	minor := binary.LittleEndian.Uint16(pcapData[6:8])
	if major != 2 || minor != 4 {
		t.Fatalf("Invalid PCAP version %d.%d, expected 2.4", major, minor)
	}
}

func TestForensicRESTAPI(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copsec-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	buffer := NewPCAPBuffer(10*1024*1024, 30*time.Second, tempDir)
	buffer.Ingest("192.0.2.1", "10.0.0.1", 1234, 80, 6, []byte("PAYLOAD"))
	snap, err := buffer.SnapshotForIP("192.0.2.1", "Test Ban")
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	mux := http.NewServeMux()
	RegisterHTTPHandlers(mux, buffer)

	// 1. Test GET /api/forensics/pcaps
	req1 := httptest.NewRequest("GET", "/api/forensics/pcaps", nil)
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d: %s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), snap.Filename) {
		t.Fatalf("Expected response to contain filename %s, got %s", snap.Filename, w1.Body.String())
	}

	// 2. Test GET /api/forensics/download?file=<FILENAME>
	req2 := httptest.NewRequest("GET", "/api/forensics/download?file="+snap.Filename, nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on download, got %d: %s", w2.Code, w2.Body.String())
	}
	if w2.Header().Get("Content-Type") != "application/vnd.tcpdump.pcap" {
		t.Fatalf("Expected application/vnd.tcpdump.pcap, got %s", w2.Header().Get("Content-Type"))
	}
	if !bytes.HasPrefix(w2.Body.Bytes(), []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		t.Fatalf("Downloaded file missing PCAP magic bytes")
	}

	// 3. Test Directory Traversal Defense
	req3 := httptest.NewRequest("GET", "/api/forensics/download?file=../../../../etc/passwd", nil)
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("Expected HTTP 404 on traversal attempt, got %d", w3.Code)
	}
}
