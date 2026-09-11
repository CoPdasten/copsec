package export

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CoPSeC Enterprise"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func TestCEFFormatAccuracy(t *testing.T) {
	ev := &TelemetryEvent{
		Timestamp:  time.Unix(1788812345, 0),
		SourceIP:   "198.51.100.88",
		SourcePort: 443,
		Protocol:   "TCP",
		Reason:     "L7 DPI Signature",
		Severity:   "CRITICAL",
		CVE:        "CVE-2021-44228",
		LatencyNs:  45200,
		NodeID:     "edge-sensor-01",
	}

	cef := FormatCEF(ev)
	expected := "CEF:0|CoPSeC|KernelXDP|1.4|DROP|L7 DPI Signature|CRITICAL|src=198.51.100.88 cs1Label=CVE cs1=CVE-2021-44228 cn1Label=LatencyNs cn1=45200"

	if cef != expected {
		t.Fatalf("CEF format mismatch.\nExpected: %s\nGot:      %s", expected, cef)
	}

	// Test delimiter escaping in header and extension
	evEscape := &TelemetryEvent{
		SourceIP:  "203.0.113.5",
		Reason:    "SYN|Flood\\Attack",
		Severity:  "HIGH|WARNING",
		CVE:       "CVE=2024\\01",
		LatencyNs: 1200,
	}

	cefEscaped := FormatCEF(evEscape)
	if !strings.Contains(cefEscaped, `SYN\|Flood\\Attack`) {
		t.Errorf("Expected escaped reason in CEF, got: %s", cefEscaped)
	}
	if !strings.Contains(cefEscaped, `HIGH\|WARNING`) {
		t.Errorf("Expected escaped severity in CEF, got: %s", cefEscaped)
	}
	if !strings.Contains(cefEscaped, `CVE\=2024\\01`) {
		t.Errorf("Expected escaped extension in CEF, got: %s", cefEscaped)
	}
}

func TestRFC5424SyslogFormat(t *testing.T) {
	ts := time.Date(2026, 9, 11, 19, 33, 1, 0, time.UTC)
	ev := &TelemetryEvent{
		Timestamp: ts,
		SourceIP:  "192.0.2.10",
		Reason:    "Rate Limit Exceeded",
		Severity:  "MEDIUM",
		CVE:       "NONE",
		LatencyNs: 3500,
		NodeID:    "edge-sensor-01",
		AppName:   "copsec-xdp",
	}

	syslog := FormatRFC5424(ev, 16, 6) // local0.info = 16*8 + 6 = 134

	if !strings.HasPrefix(syslog, "<134>1 ") {
		t.Errorf("Expected prefix <134>1, got: %s", syslog)
	}
	if !strings.Contains(syslog, "edge-sensor-01 copsec-xdp - DROP - CEF:0|CoPSeC|KernelXDP|1.4|DROP|") {
		t.Errorf("Expected RFC 5424 structured syslog with embedded CEF, got: %s", syslog)
	}
}

func TestRingChannelBufferNonBlockingOverflow(t *testing.T) {
	// Small ring buffer of size 10
	buf := NewRingChannelBuffer(10)

	// Push 100 items rapidly without reading
	for i := 0; i < 100; i++ {
		ev := &TelemetryEvent{
			SourceIP:  net.IPv4(10, 0, 0, byte(i)).String(),
			LatencyNs: int64(i),
		}
		pushed := buf.Push(ev)
		if !pushed {
			t.Errorf("Push should return true on displaced ring slot")
		}
	}

	if buf.Length() != 10 {
		t.Fatalf("Buffer length should stay capped at 10, got %d", buf.Length())
	}
	if buf.Pushed() != 100 {
		t.Errorf("Expected pushed count 100, got %d", buf.Pushed())
	}
	if buf.Dropped() != 90 {
		t.Errorf("Expected dropped count 90, got %d", buf.Dropped())
	}

	// Verify the items in the buffer are the 10 most recent (90 to 99)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	firstItem, ok := buf.Pop(ctx)
	if !ok || firstItem == nil {
		t.Fatal("Expected pop to succeed")
	}
	if firstItem.LatencyNs < 90 {
		t.Errorf("Expected newest items retained in ring buffer, got latency %d", firstItem.LatencyNs)
	}
}

func TestSIEMExporterRawTCPExport(t *testing.T) {
	// 1. Launch mock TCP SIEM target (e.g. Wazuh / Splunk TCP listener)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock TCP listener: %v", err)
	}
	defer ln.Close()

	var receivedLines []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			mu.Lock()
			receivedLines = append(receivedLines, scanner.Text())
			mu.Unlock()
		}
	}()

	// 2. Initialize SIEMExporter targeting mock TCP socket
	cfg := SIEMConfig{
		TargetType: TargetTypeRawTCP,
		Endpoint:   ln.Addr().String(),
		QueueSize:  100,
		Workers:    2,
		Format:     "CEF",
	}

	exporter, err := NewSIEMExporter(cfg)
	if err != nil {
		t.Fatalf("NewSIEMExporter failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	exporter.Start(ctx)

	// Enqueue test drops
	testEvent := &TelemetryEvent{
		SourceIP:  "198.51.100.99",
		Reason:    "L7 DPI Signature",
		Severity:  "CRITICAL",
		CVE:       "CVE-2021-44228",
		LatencyNs: 24000,
	}

	if !exporter.Enqueue(testEvent) {
		t.Fatal("Failed to enqueue event")
	}

	// Allow worker to flush
	time.Sleep(100 * time.Millisecond)

	cancel()
	_ = exporter.Close()
	_ = ln.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(receivedLines) != 1 {
		t.Fatalf("Expected 1 line received by mock SIEM, got %d", len(receivedLines))
	}

	expectedPrefix := "CEF:0|CoPSeC|KernelXDP|1.4|DROP|L7 DPI Signature|CRITICAL|src=198.51.100.99"
	if !strings.HasPrefix(receivedLines[0], expectedPrefix) {
		t.Errorf("Received line did not match expected CEF pattern.\nExpected prefix: %s\nGot:             %s",
			expectedPrefix, receivedLines[0])
	}
}

func TestSIEMExporterTLSSyslogExport(t *testing.T) {
	cert := generateSelfSignedCert(t)
	tlsServerConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsServerConf)
	if err != nil {
		t.Fatalf("Failed to start mock TLS Syslog listener: %v", err)
	}
	defer ln.Close()

	var receivedLines []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			mu.Lock()
			receivedLines = append(receivedLines, scanner.Text())
			mu.Unlock()
		}
	}()

	cfg := SIEMConfig{
		TargetType:      TargetTypeTLSSyslog,
		Endpoint:        ln.Addr().String(),
		QueueSize:       50,
		Workers:         1,
		Format:          "RFC5424",
		InsecureSkipTLS: true, // Self-signed cert test
	}

	exporter, err := NewSIEMExporter(cfg)
	if err != nil {
		t.Fatalf("NewSIEMExporter failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	exporter.Start(ctx)

	ev := &TelemetryEvent{
		SourceIP:  "203.0.113.15",
		Reason:    "Entropy Anomaly",
		Severity:  "HIGH",
		CVE:       "NONE",
		LatencyNs: 18000,
		NodeID:    "sensor-edge-02",
	}

	if !exporter.Enqueue(ev) {
		t.Fatal("Failed to enqueue event")
	}

	time.Sleep(100 * time.Millisecond)

	cancel()
	_ = exporter.Close()
	_ = ln.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(receivedLines) != 1 {
		t.Fatalf("Expected 1 syslog record received, got %d", len(receivedLines))
	}

	if !strings.Contains(receivedLines[0], "sensor-edge-02 copsec-xdp - DROP - CEF:0|CoPSeC|KernelXDP|1.4|DROP|Entropy Anomaly|HIGH|src=203.0.113.15") {
		t.Errorf("Unexpected RFC 5424 payload received: %s", receivedLines[0])
	}
}
