package ttp

import (
	"testing"
)

func TestLookupByID(t *testing.T) {
	tests := []struct {
		id       string
		wantName string
		wantFind bool
	}{
		{"T1498.001", "Network Denial of Service: Direct Network Flood", true},
		{"t1498.001", "Network Denial of Service: Direct Network Flood", true},
		{"T1027", "Obfuscated Files or Information", true},
		{"T1046", "Network Service Discovery", true},
		{"T1190", "Exploit Public-Facing Application", true},
		{"T1071.004", "Application Layer Protocol: DNS", true},
		{"T9999", "", false},
	}

	for _, tt := range tests {
		info, found := LookupByID(tt.id)
		if found != tt.wantFind {
			t.Errorf("LookupByID(%q) found = %v; want %v", tt.id, found, tt.wantFind)
		}
		if found && info.Name != tt.wantName {
			t.Errorf("LookupByID(%q).Name = %q; want %q", tt.id, info.Name, tt.wantName)
		}
	}
}

func TestLookupByRule(t *testing.T) {
	tests := []struct {
		rule    string
		wantID  string
		wantOK  bool
	}{
		{"SYN_FLOOD_DROP", "T1498.001", true},
		{"xdp_syn_flood", "T1498.001", true},
		{"SHANNON_ENTROPY_ANOMALY", "T1027", true},
		{"entropy_anomaly", "T1027", true},
		{"TARPIT_PORT_SCANNER", "T1046", true},
		{"xdp_tarpit", "T1046", true},
		{"L7_EXPLOIT_PATTERN", "T1190", true},
		{"log4j", "T1190", true},
		{"DNS_C2_SINKHOLE", "T1071.004", true},
		{"dns_sinkhole", "T1071.004", true},
		{"edr_kill", "T1059.004", true},
		{"unknown_rule_xyz", "", false},
	}

	for _, tt := range tests {
		info, ok := LookupByRule(tt.rule)
		if ok != tt.wantOK {
			t.Errorf("LookupByRule(%q) ok = %v; want %v", tt.rule, ok, tt.wantOK)
		}
		if ok && info.ID != tt.wantID {
			t.Errorf("LookupByRule(%q).ID = %q; want %q", tt.rule, info.ID, tt.wantID)
		}
	}
}

func TestGetAllTechniques(t *testing.T) {
	all := GetAllTechniques()
	if len(all) < 5 {
		t.Errorf("GetAllTechniques() returned %d techniques, want >= 5", len(all))
	}
}
