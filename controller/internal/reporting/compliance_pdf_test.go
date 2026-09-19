package reporting

import (
	"bytes"
	"testing"
	"time"
)

func TestGenerateCompliancePDF(t *testing.T) {
	data := AuditReportSummary{
		ReportTitle:           "CoPSeC Distributed eBPF/XDP Benchmark & Compliance Audit Report",
		GeneratedAt:           time.Now().UTC(),
		Environment:           "4-Node Distributed eBPF/XDP Laboratory Benchmark (PoC Validation Cluster)",
		TargetCluster:         "4-Node Validation Cluster (pardus1, pardus2, fedora, kali)",
		TotalActiveFleetNodes: 3,
		AggregateIncidents:    15,
		PacketsDroppedXDP:     126200,
		PcapArtifactsCount:    2,
		PcapDirectory:         "/var/log/copsec/forensics",
		AuditTrailVerified:    true,
		AuditTrailRecordCount: 42,
		AuditTrailVerdict:     "VERDICT: 100% VERIFIED - SHA-256 HASH CHAIN TAMPER-FREE",
		TriggersEnforced:      true,
		TriggerDetails:        "Active: prevent_audit_update and prevent_audit_delete strictly enforce append-only immutability",
		RecentUnbans: []UnbanAuditRecord{
			{
				ID:                1,
				Timestamp:         time.Now().UTC(),
				ActorID:           "SOC_L2_EFE",
				ActorIP:           "192.168.1.11",
				TargetIP:          "192.168.1.12",
				Justification:     "PoC Kali Test Validation Complete",
				CryptographicHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		FleetNodes: []FleetNodeSnapshot{
			{
				NodeID:              "pardus1",
				NodeGroup:           "PRIMARY_EDGE",
				IPAddress:           "192.168.1.13",
				ActiveInterface:     "eth0",
				XDPStatus:           "ACTIVE",
				CPUUsagePct:         1.4,
				MemoryUsageMB:       128.0,
				TotalPacketsDropped: 45200,
			},
			{
				NodeID:              "pardus2",
				NodeGroup:           "SECONDARY_EDGE",
				IPAddress:           "192.168.1.11",
				ActiveInterface:     "eth0",
				XDPStatus:           "ACTIVE",
				CPUUsagePct:         1.2,
				MemoryUsageMB:       118.0,
				TotalPacketsDropped: 32400,
			},
			{
				NodeID:              "fedora",
				NodeGroup:           "INGRESS_EDGE",
				IPAddress:           "192.168.1.10",
				ActiveInterface:     "eth0",
				XDPStatus:           "ACTIVE",
				CPUUsagePct:         2.1,
				MemoryUsageMB:       144.0,
				TotalPacketsDropped: 48600,
			},
		},
		PcapSnapshots: []PcapSnapshotRecord{
			{
				Filename:     "attack_192.168.1.12_synflood.pcap",
				Timestamp:    time.Now().UTC().Add(-5 * time.Minute),
				SizeBytes:    14336,
				SHA256Digest: "9f83e2a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
			},
			{
				Filename:     "incident_192.168.1.12_entropy.pcap",
				Timestamp:    time.Now().UTC().Add(-2 * time.Minute),
				SizeBytes:    8192,
				SHA256Digest: "7e4c1d2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d",
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateCompliancePDF(data, &buf)
	if err != nil {
		t.Fatalf("GenerateCompliancePDF failed: %v", err)
	}

	pdfBytes := buf.Bytes()
	if len(pdfBytes) == 0 {
		t.Fatal("expected non-empty PDF bytes")
	}

	if len(pdfBytes) < 5 || string(pdfBytes[:5]) != "%PDF-" {
		t.Fatalf("expected PDF header '%%PDF-', got %q", string(pdfBytes[:min(10, len(pdfBytes))]))
	}

	t.Logf("Generated valid PDF report: %d bytes with %%PDF- magic header", len(pdfBytes))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
