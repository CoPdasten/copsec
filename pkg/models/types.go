package models

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Severity defines canonical security event and alert threat severity levels.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Layer defines the security inspection domain / boundary.
type Layer string

const (
	LayerWAF  Layer = "WAF"
	LayerEDR  Layer = "EDR"
	LayerAUTH Layer = "AUTH"
	LayerNET  Layer = "NET"
)

// UnifiedTelemetry enforces the single canonical data contract across all CoPSeC components.
type UnifiedTelemetry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceNode  string                 `json:"source_node"`
	Layer       string                 `json:"layer"` // "WAF", "EDR", "AUTH", "NET"
	SourceIP    string                 `json:"source_ip"`
	SourcePort  int                    `json:"source_port"`
	DestIP      string                 `json:"dest_ip"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"protocol"`
	ThreatScore int                    `json:"threat_score"` // 0 - 100
	Severity    Severity               `json:"severity"`
	MitreID     string                 `json:"mitre_id"`
	RuleMatched string                 `json:"rule_matched"`
	RawPayload  string                 `json:"raw_payload"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CalculateSeverity converts numeric threat score (0-100) to canonical Severity enum.
func CalculateSeverity(threatScore int) Severity {
	switch {
	case threatScore >= 85:
		return SeverityCritical
	case threatScore >= 60:
		return SeverityHigh
	case threatScore >= 30:
		return SeverityMedium
	case threatScore > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// IsValidSeverity validates if a Severity value is an allowed canonical enum.
func IsValidSeverity(s Severity) bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// NormalizeLayer standardizes layer strings into canonical names ("WAF", "EDR", "AUTH", "NET").
func NormalizeLayer(layer string) string {
	upper := strings.ToUpper(strings.TrimSpace(layer))
	switch upper {
	case "WAF", "HTTP", "NGINX", "APACHE", "WEB":
		return string(LayerWAF)
	case "EDR", "EBPF", "FIM", "AUDIT", "PROCESS", "ROOTKIT", "KERNEL":
		return string(LayerEDR)
	case "AUTH", "SSH", "PAM", "LOGIN":
		return string(LayerAUTH)
	case "NET", "NETWORK", "SURICATA", "SNORT", "DNS", "TCP", "UDP":
		return string(LayerNET)
	default:
		if upper != "" {
			return upper
		}
		return string(LayerNET)
	}
}

// Validate checks required fields and value ranges of UnifiedTelemetry.
func (u *UnifiedTelemetry) Validate() error {
	if u.ID == "" {
		return fmt.Errorf("id is required")
	}
	if u.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if u.ThreatScore < 0 || u.ThreatScore > 100 {
		return fmt.Errorf("threat_score must be between 0 and 100, got %d", u.ThreatScore)
	}
	if !IsValidSeverity(u.Severity) {
		return fmt.Errorf("invalid severity: %s", u.Severity)
	}
	if u.SourceIP != "" && u.SourceIP != "-" {
		if net.ParseIP(u.SourceIP) == nil {
			return fmt.Errorf("invalid source_ip format: %s", u.SourceIP)
		}
	}
	if u.DestIP != "" && u.DestIP != "-" {
		if net.ParseIP(u.DestIP) == nil {
			return fmt.Errorf("invalid dest_ip format: %s", u.DestIP)
		}
	}
	return nil
}

// ToJSON marshals the struct to canonical JSON bytes.
func (u *UnifiedTelemetry) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}
