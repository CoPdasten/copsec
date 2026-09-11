package reporting

import (
	"bytes"
	"testing"
	"time"
)

func TestGenerateCompliancePDF(t *testing.T) {
	data := AuditReportSummary{
		ReportTitle:           "CoPSeC Enterprise Compliance Report",
		GeneratedAt:           time.Now().UTC(),
		Environment:           "Production",
		TargetCluster:         "Enterprise Fleet (4-Node)",
		TotalActiveFleetNodes: 2,
		AggregateIncidents:    15,
		PacketsDroppedXDP:     125000,
		PcapArtifactsCount:    3,
		PcapDirectory:         "/var/log/copsec/forensics",
		AuditTrailVerified:    true,
		AuditTrailRecordCount: 42,
		AuditTrailVerdict:     "VERDICT: 100% VERIFIED - SHA-256 HASH CHAIN TAMPER-FREE",
		TriggersEnforced:      true,
		RecentUnbans: []UnbanAuditRecord{
			{
				ID:                1,
				Timestamp:         time.Now().UTC(),
				ActorID:           "SOC_L2_EFE",
				ActorIP:           "192.168.1.11",
				TargetIP:          "192.168.1.12",
				Justification:     "Test validation complete",
				CryptographicHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		FleetNodes: []FleetNodeSnapshot{
			{
				NodeID:              "chachy",
				NodeGroup:           "DMZ_INGRESS",
				IPAddress:           "192.168.1.10",
				ActiveInterface:     "wlan0",
				XDPStatus:           "ACTIVE",
				CPUUsagePct:         12.5,
				MemoryUsageMB:       256.0,
				TotalPacketsDropped: 50000,
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
