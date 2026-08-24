package snort

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseSnortAlertNormalAndML(t *testing.T) {
	// 1. Standard Snort 3 Alert
	rawNormal := []byte(`{"timestamp":"08/24-22:30:15.123456","pkt_num":105,"proto":"TCP","src_addr":"198.51.100.22","src_port":54321,"dst_addr":"10.0.0.5","dst_port":80,"msg":"SERVER-WEBAPP Apache Struts RCE attempt","rule":"1:1000001:1","class":"Web Application Attack","priority":1,"service":"http"}`)
	ev1, ok1 := ParseSnortAlert(rawNormal)
	if !ok1 || ev1 == nil {
		t.Fatalf("Failed to parse standard Snort 3 alert")
	}
	if ev1.SrcAddr != "198.51.100.22" || ev1.Priority != 1 {
		t.Errorf("Unexpected values in parsed standard alert: %+v", ev1)
	}
	if !ev1.IsHighConfidenceAnomaly() {
		t.Errorf("Expected Priority 1 alert to be high confidence anomaly")
	}

	// 2. Snort 3 ML Anomaly Alert
	rawML := []byte(`{"timestamp":"08/24-22:30:16.789012","proto":"TCP","src_addr":"203.0.113.88","src_port":44444,"dst_addr":"10.0.0.5","dst_port":443,"msg":"INDICATOR-SHELLCODE Potential polymorphic shellcode detected by ML","rule":"1:2000002:1","priority":2,"ml":{"model_id":"snort-flow-xgb-v1","ml_anomaly_score":0.94,"confidence":0.96,"features":{"entropy":7.85,"flow_rate":1420.0}}}`)
	ev2, ok2 := ParseSnortAlert(rawML)
	if !ok2 || ev2 == nil {
		t.Fatalf("Failed to parse Snort 3 ML alert")
	}
	if ev2.ML == nil || ev2.ML.AnomalyScore != 0.94 || ev2.ML.Confidence != 0.96 {
		t.Errorf("Failed to parse nested ML telemetry: %+v", ev2.ML)
	}
	if !ev2.IsHighConfidenceAnomaly() {
		t.Errorf("Expected ML Anomaly score 0.94 to be high confidence anomaly")
	}
	if ev2.Summary() != "[SNORT-ML] INDICATOR-SHELLCODE Potential polymorphic shellcode detected by ML (Score: 0.94)" {
		t.Errorf("Unexpected summary output: %s", ev2.Summary())
	}
}

func TestSnortStreamReaderFileTailing(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "alert_json.txt")
	sockFile := filepath.Join(tmpDir, "snort_alert.sock")

	var mu sync.Mutex
	var received []*SnortMLEvent

	reader := NewSnortStreamReader(logFile, sockFile, func(ev *SnortMLEvent) {
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader.Start(ctx)
	defer reader.Stop()

	time.Sleep(50 * time.Millisecond)

	// Append an alert line to the log file
	alertLine := `{"timestamp":"08/24-22:31:00.000000","proto":"TCP","src_addr":"198.51.100.99","src_port":1234,"dst_addr":"10.0.0.5","dst_port":22,"msg":"AUTH-SSH Brute Force ML Detected","rule":"1:3000003:1","priority":1,"ml":{"model_id":"snort-ssh-anomaly","ml_anomaly_score":0.91,"confidence":0.89}}` + "\n"
	if err := os.WriteFile(logFile, []byte(alertLine), 0644); err != nil {
		t.Fatalf("Failed to write test alert line: %v", err)
	}

	// Allow tailer to pick up
	time.Sleep(600 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("Expected 1 alert received via file tailer, got %d", count)
	}
}

func TestSnortStreamReaderUnixSocket(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "dummy.txt")
	sockFile := filepath.Join(tmpDir, "test_snort.sock")

	var mu sync.Mutex
	var received []*SnortMLEvent

	reader := NewSnortStreamReader(logFile, sockFile, func(ev *SnortMLEvent) {
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader.Start(ctx)
	defer reader.Stop()

	// Wait for socket to bind
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockFile)
	if err != nil {
		t.Fatalf("Failed to connect to Snort UDS: %v", err)
	}
	defer conn.Close()

	alertJSON := `{"timestamp":"08/24-22:32:00.000000","proto":"UDP","src_addr":"203.0.113.77","src_port":5353,"dst_addr":"10.0.0.5","dst_port":53,"msg":"PROTOCOL-DNS Tunneling ML Anomaly","rule":"1:4000004:1","priority":1,"ml":{"model_id":"snort-dns-anomaly","ml_anomaly_score":0.95,"confidence":0.98}}` + "\n"
	_, _ = conn.Write([]byte(alertJSON))

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("Expected 1 alert received via UDS, got %d", count)
	}
}
