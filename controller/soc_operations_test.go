package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestEmergencyFlushEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_flush.db")

	storage, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to create storage engine: %v", err)
	}
	defer storage.Close()

	ttlMgr := NewTTLBanManager(storage, nil)
	defer ttlMgr.Stop()

	// Add test bans
	_, err = ttlMgr.BanIP("198.51.100.77", "Test Ban 1", 3600, TierTempIsolation)
	if err != nil {
		t.Fatalf("Failed to ban IP: %v", err)
	}
	_, err = ttlMgr.BanIP("198.51.100.88", "Test Ban 2", 3600, TierTempIsolation)
	if err != nil {
		t.Fatalf("Failed to ban IP: %v", err)
	}

	if len(ttlMgr.GetActiveBans()) != 2 {
		t.Fatalf("Expected 2 active bans, got %d", len(ttlMgr.GetActiveBans()))
	}

	ws := &WebSOCServer{
		storage:    storage,
		ttlManager: ttlMgr,
	}

	// 1. Verify Method Not Allowed on GET
	getReq := httptest.NewRequest(http.MethodGet, "/api/quarantine/emergency-flush", nil)
	getRec := httptest.NewRecorder()
	ws.handleEmergencyFlush(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %d", getRec.Code)
	}

	// 2. Execute Emergency Flush via POST
	postReq := httptest.NewRequest(http.MethodPost, "/api/quarantine/emergency-flush", nil)
	postRec := httptest.NewRecorder()
	ws.handleEmergencyFlush(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", postRec.Code, postRec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(postRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("Expected success == true, got %v", resp["success"])
	}

	if len(ttlMgr.GetActiveBans()) != 0 {
		t.Errorf("Expected 0 active bans after emergency flush, got %d", len(ttlMgr.GetActiveBans()))
	}
}

func TestIncidentExportBundleEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_bundle.db")

	storage, err := NewStorageEngine(dbPath)
	if err != nil {
		t.Fatalf("Failed to create storage engine: %v", err)
	}
	defer storage.Close()

	// Insert test event with host process tracing and payload
	event := &StoredEvent{
		NodeID:           "test-node-01",
		Source:           "ebpf_xdp",
		RawLine:          "4500003c123440004006e8b4c0a80101c0a8010200501f900000000000000000",
		ClientIP:         "198.51.100.99",
		StatusCode:       403,
		TimestampMs:      time.Now().UnixMilli(),
		RuleID:           "syn_flood_drop",
		MitreTechniqueID: "T1498.001",
		ThreatScore:      90,
		TargetPID:        0,
		TargetComm:       "KERNEL_FASTPATH_DROP [PID: 0]",
	}

	if err := storage.InsertEvent(event); err != nil {
		t.Fatalf("Failed to insert event: %v", err)
	}

	ws := &WebSOCServer{
		storage: storage,
	}

	// Request bundle export for event.ID
	req := httptest.NewRequest(http.MethodGet, "/api/incidents/export-bundle?id=1", nil)
	rec := httptest.NewRecorder()
	ws.handleIncidentExportBundle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/zip" {
		t.Errorf("Expected Content-Type: application/zip, got %s", contentType)
	}

	zipBytes := rec.Body.Bytes()
	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("Failed to open zip reader: %v", err)
	}

	expectedFiles := map[string]bool{
		"packet_capture.pcap":     false,
		"merkle_audit_trail.json": false,
		"threat_metadata.json":    false,
		"incident_report.md":      false,
	}

	for _, file := range zipReader.File {
		if _, ok := expectedFiles[file.Name]; ok {
			expectedFiles[file.Name] = true
		}

		rc, err := file.Open()
		if err != nil {
			t.Fatalf("Failed to open %s in zip: %v", file.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()

		switch file.Name {
		case "packet_capture.pcap":
			if len(data) < 24 {
				t.Errorf("PCAP file too small: %d bytes", len(data))
			} else {
				magic := binary.LittleEndian.Uint32(data[:4])
				if magic != 0xa1b2c3d4 {
					t.Errorf("Expected libpcap magic 0xa1b2c3d4, got 0x%x", magic)
				}
			}

		case "threat_metadata.json":
			var meta map[string]interface{}
			if err := json.Unmarshal(data, &meta); err != nil {
				t.Errorf("threat_metadata.json invalid JSON: %v", err)
			}
			if meta["mitre_technique_id"] != "T1498.001" {
				t.Errorf("Expected T1498.001 in metadata, got %v", meta["mitre_technique_id"])
			}
			if meta["target_comm"] != "KERNEL_FASTPATH_DROP [PID: 0]" {
				t.Errorf("Expected target_comm in metadata, got %v", meta["target_comm"])
			}

		case "incident_report.md":
			if !bytes.Contains(data, []byte("Digital Forensics")) {
				t.Errorf("incident_report.md missing Digital Forensics header")
			}
			if !bytes.Contains(data, []byte("KERNEL_FASTPATH_DROP")) {
				t.Errorf("incident_report.md missing KERNEL_FASTPATH_DROP")
			}
		}
	}

	for fname, found := range expectedFiles {
		if !found {
			t.Errorf("Missing expected file in zip bundle: %s", fname)
		}
	}
}
