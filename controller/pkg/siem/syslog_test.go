package siem

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFormatArcSightCEF(t *testing.T) {
	ev := &AlertEvent{
		Timestamp:   time.Now(),
		NodeID:      "sensor-edge-01",
		SourceIP:    "fd00::12",
		SourcePort:  49152,
		DestIP:      "fd00::8",
		DestPort:    2223,
		Protocol:    "TCP",
		RuleID:      "SHANNON_ENTROPY_ANOMALY",
		RuleName:    "High-Entropy C2 Anomaly",
		MitreID:     "T1027",
		ThreatScore: 95,
		Severity:    "CRITICAL",
		Action:      "DROP",
		Message:     "High entropy payload detected on port 2223",
		TargetPID:   1402,
		TargetComm:  "nginx",
	}

	cef := FormatArcSightCEF(ev)

	expectedPrefix := "CEF:0|CoPSeC|ActiveDefense|1.8.0|DROP|High-Entropy C2 Anomaly|10|"
	if !strings.HasPrefix(cef, expectedPrefix) {
		t.Errorf("CEF prefix mismatch.\nGot:  %s\nWant: %s", cef, expectedPrefix)
	}

	expectedSubstrings := []string{
		"src=fd00::12",
		"dst=fd00::8",
		"spt=49152",
		"dpt=2223",
		"cs1Label=MITRE cs1=T1027",
		"cn1Label=ThreatScore cn1=95",
		"dproc=nginx",
		"dpid=1402",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(cef, sub) {
			t.Errorf("CEF missing expected substring %q in: %s", sub, cef)
		}
	}
}

func TestFormatRFC5424JSON(t *testing.T) {
	ev := &AlertEvent{
		Timestamp:   time.Now(),
		NodeID:      "node-01",
		SourceIP:    "192.168.1.50",
		SourcePort:  55432,
		RuleID:      "SYN_FLOOD_DROP",
		MitreID:     "T1498.001",
		ThreatScore: 90,
		Severity:    "HIGH",
	}

	syslogMsg := FormatRFC5424JSON(ev, "copsec-hub", "copsec-activedefense", 16, 6)

	if !strings.HasPrefix(syslogMsg, "<134>1 ") {
		t.Errorf("RFC5424 PRI mismatch: %s", syslogMsg)
	}
	if !strings.Contains(syslogMsg, `rule_id="SYN_FLOOD_DROP"`) {
		t.Errorf("RFC5424 missing structured data rule_id: %s", syslogMsg)
	}
	if !strings.Contains(syslogMsg, `"source_ip":"192.168.1.50"`) {
		t.Errorf("RFC5424 missing JSON payload source_ip: %s", syslogMsg)
	}
}

func TestSyslogForwarderUDP(t *testing.T) {
	// Start local UDP listener
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()

	cfg := SyslogConfig{
		Enabled:   true,
		Transport: TransportUDP,
		Endpoint:  addr,
		Format:    FormatCEF,
		Workers:   1,
	}

	f, err := NewSyslogForwarder(cfg)
	if err != nil {
		t.Fatalf("NewSyslogForwarder failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	defer f.Close()

	ev := &AlertEvent{
		SourceIP:    "10.10.10.5",
		SourcePort:  1234,
		RuleID:      "test_rule",
		ThreatScore: 80,
	}

	f.Push(ev)

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read from UDP listener: %v", err)
	}

	received := string(buf[:n])
	if !strings.Contains(received, "src=10.10.10.5") {
		t.Errorf("UDP payload mismatch: %s", received)
	}
}

func TestSyslogForwarderTCP(t *testing.T) {
	// Start local TCP listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen TCP: %v", err)
	}
	defer l.Close()

	addr := l.Addr().String()

	receivedChan := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		if scanner.Scan() {
			receivedChan <- scanner.Text()
		}
	}()

	cfg := SyslogConfig{
		Enabled:   true,
		Transport: TransportTCP,
		Endpoint:  addr,
		Format:    FormatJSON,
		Workers:   1,
	}

	f, err := NewSyslogForwarder(cfg)
	if err != nil {
		t.Fatalf("NewSyslogForwarder failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	defer f.Close()

	ev := &AlertEvent{
		SourceIP:    "192.168.1.100",
		RuleID:      "tcp_test",
		ThreatScore: 85,
	}

	f.Push(ev)

	select {
	case line := <-receivedChan:
		if !strings.Contains(line, `"source_ip":"192.168.1.100"`) {
			t.Errorf("TCP received line unexpected: %s", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for TCP syslog packet")
	}
}
