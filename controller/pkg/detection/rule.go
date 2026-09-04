package detection

// RuleAction defines enforcement behavior when a detection rule triggers.
type RuleAction string

const (
	ActionBan        RuleAction = "BAN"
	ActionAlertOnly  RuleAction = "ALERT_ONLY"
	ActionHoneypot   RuleAction = "HONEYPOT_REDIRECT"
)

// DetectionRule defines a structured, hot-reloadable detection signature.
type DetectionRule struct {
	ID               string     `json:"id"`                 // e.g., "RULE-SQLI-001"
	Name             string     `json:"name"`               // e.g., "SQL Injection Detection"
	Description      string     `json:"description"`
	Severity         string     `json:"severity"`           // LOW, MEDIUM, HIGH, CRITICAL
	ThreatScore      int        `json:"threat_score"`       // 1 - 100
	MitreTechniqueID string     `json:"mitre_technique_id"` // e.g., "T1190"
	Enabled          bool       `json:"enabled"`

	// Matching Conditions
	TargetField      string     `json:"target_field"`       // "raw_payload", "uri", "headers", "source_ip"
	MatchType        string     `json:"match_type"`         // "contains", "regex", "shannon_entropy_gt"
	Pattern          string     `json:"pattern"`            // Substring or regex expression
	EntropyThreshold float64    `json:"entropy_threshold"`  // Used if match_type == "shannon_entropy_gt"

	// Stateful / Rate-based Correlation (Sliding Window)
	WindowSeconds    int        `json:"window_seconds"`     // Time-frame for threshold aggregation
	HitThreshold     int        `json:"hit_threshold"`      // Number of hits required to trigger

	// Enforcement
	Action           RuleAction `json:"action"`             // BAN, ALERT_ONLY, etc.
	BanDurationSec   int        `json:"ban_duration_sec"`   // Default isolation duration (e.g., 86400)
}
