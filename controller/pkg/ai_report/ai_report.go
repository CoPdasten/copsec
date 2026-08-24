package ai_report

import (
	"fmt"
	"strings"
	"time"

	"github.com/copsec/controller/pkg/geoip"
)

// TimelineEvent captures chronological steps in an incident chain.
type TimelineEvent struct {
	TimestampMs int64  `json:"timestamp_ms"`
	TimeStr     string `json:"time_str"`
	Source      string `json:"source"`
	Event       string `json:"event"`
	ThreatScore int    `json:"threat_score"`
}

// IncidentForensicReport encapsulates a complete executive security assessment.
type IncidentForensicReport struct {
	IncidentID         string             `json:"incident_id"`
	GeneratedAt        string             `json:"generated_at"`
	Severity           string             `json:"severity"`
	ThreatScore        int                `json:"threat_score"`
	TargetIP           string             `json:"target_ip"`
	NodeID             string             `json:"node_id"`
	Geo                *geoip.GeoLocation `json:"geo"`
	RuleID             string             `json:"rule_id"`
	MitreTechniqueID   string             `json:"mitre_technique_id"`
	MitreTechniqueName string             `json:"mitre_technique_name"`
	ExecutiveSummary   string             `json:"executive_summary"`
	AttackerIntent     string             `json:"attacker_intent"`
	RootCause          string             `json:"root_cause"`
	IoCs               []string           `json:"iocs"`
	MitigationDetails  []string           `json:"mitigation_details"`
	Recommendations    []string           `json:"recommendations"`
	Timeline           []TimelineEvent    `json:"timeline"`
	RawPayload         string             `json:"raw_payload"`
}

// ReportGenerator synthesizes forensic assessments.
type ReportGenerator struct {
	geoEngine *geoip.Engine
}

// NewReportGenerator creates a new forensic report synthesizer.
func NewReportGenerator(geoEngine *geoip.Engine) *ReportGenerator {
	if geoEngine == nil {
		geoEngine = geoip.GetDefaultEngine()
	}
	return &ReportGenerator{
		geoEngine: geoEngine,
	}
}

// GenerateIncidentReport compiles telemetry, GeoIP, and AI intent into a full forensic report.
func (rg *ReportGenerator) GenerateIncidentReport(
	incidentID string,
	targetIP string,
	nodeID string,
	source string,
	threatScore int,
	ruleID string,
	mitreID string,
	rawPayload string,
	aiAnalysis string,
	timestampMs int64,
	timelineEvents []TimelineEvent,
) *IncidentForensicReport {
	if timestampMs == 0 {
		timestampMs = time.Now().UnixMilli()
	}

	geo := rg.geoEngine.Lookup(targetIP)

	severity := "LOW"
	if threatScore >= 80 {
		severity = "CRITICAL"
	} else if threatScore >= 50 {
		severity = "HIGH"
	} else if threatScore >= 30 {
		severity = "MEDIUM"
	}

	intent, rootCause := parseAIAnalysisFields(aiAnalysis, ruleID)

	mitreName := resolveMitreName(mitreID)

	// Build IoCs
	var iocs []string
	if targetIP != "" && targetIP != "-" {
		iocs = append(iocs, fmt.Sprintf("IP Address: %s (%s, %s - %s)", targetIP, geo.CountryName, geo.City, geo.ASN))
	}
	if strings.Contains(rawPayload, "User-Agent:") || strings.Contains(rawPayload, "user_agent") {
		iocs = append(iocs, "Fingerprinted Threat Actor User-Agent Signature Captured")
	}
	if strings.Contains(rawPayload, "user:") || strings.Contains(rawPayload, "password:") {
		iocs = append(iocs, "Attacker Brute-Force Credential Stuffing Vectors Documented")
	}

	// Build SOAR Mitigations
	mitigations := []string{
		fmt.Sprintf("eBPF/XDP Fast-Path: Injected IP %s into NIC driver ring buffer for zero-CPU packet drop", targetIP),
		fmt.Sprintf("L3 Kernel Firewall: Enforced DROP rule in iptables -t raw -I PREROUTING -s %s -j DROP", targetIP),
		fmt.Sprintf("L4 Conntrack Purge: Severed active TCP sockets via conntrack -D -s %s", targetIP),
		fmt.Sprintf("L7 Application WAF: Dispatched HTTP 403 Access Denied on Nginx reverse proxy edge for IP %s", targetIP),
		"Dynamic SOAR TTL: Tiered progressive quarantine timer initialized across fleet nodes",
	}

	recommendations := []string{
		"Retain and monitor attacker CIDR prefix block in edge perimeter ACLs.",
		"Audit authentication mechanisms and enforce multi-factor authentication (MFA).",
		"Review SigmaHQ detection rule coverage for newly surfaced web probing signatures.",
		"Synchronize IoC indicators with upstream SIEM / MISP threat intelligence platforms.",
	}

	if len(timelineEvents) == 0 {
		timelineEvents = append(timelineEvents, TimelineEvent{
			TimestampMs: timestampMs,
			TimeStr:     time.UnixMilli(timestampMs).Format(time.RFC3339),
			Source:      source,
			Event:       fmt.Sprintf("Incident Triggered: %s (Threat Score: %d)", ruleID, threatScore),
			ThreatScore: threatScore,
		})
	}

	summary := fmt.Sprintf(
		"On %s, CoPSeC Autonomous Defense Matrix intercepted a %s severity attack originating from %s (%s, %s). The intrusion attempted %s matching MITRE Technique %s (%s). The autonomous SOAR engine engaged zero-latency hybrid mitigation (eBPF XDP ring-buffer drop, L3 RAW kernel drop, and L7 WAF rejection), isolating the threat with sub-millisecond execution.",
		time.UnixMilli(timestampMs).Format("2006-01-02 15:04:05 UTC"),
		severity,
		targetIP,
		geo.CountryName,
		geo.ASN,
		intent,
		mitreID,
		mitreName,
	)

	return &IncidentForensicReport{
		IncidentID:         incidentID,
		GeneratedAt:        time.Now().Format("2006-01-02 15:04:05 UTC"),
		Severity:           severity,
		ThreatScore:        threatScore,
		TargetIP:           targetIP,
		NodeID:             nodeID,
		Geo:                geo,
		RuleID:             ruleID,
		MitreTechniqueID:   mitreID,
		MitreTechniqueName: mitreName,
		ExecutiveSummary:   summary,
		AttackerIntent:     intent,
		RootCause:          rootCause,
		IoCs:               iocs,
		MitigationDetails:  mitigations,
		Recommendations:    recommendations,
		Timeline:           timelineEvents,
		RawPayload:         rawPayload,
	}
}

// ToMarkdown converts the report to a structured Markdown document.
func (r *IncidentForensicReport) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# 🛡️ CoPSeC Executive SOC Incident Forensic Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Incident ID:** `%s` | **Generated At:** `%s` | **Severity:** `%s` (Threat Score: `%d/100`)\n\n",
		r.IncidentID, r.GeneratedAt, r.Severity, r.ThreatScore))
	sb.WriteString("---\n\n")

	sb.WriteString("## 1. Executive Summary\n")
	sb.WriteString(r.ExecutiveSummary + "\n\n")

	sb.WriteString("## 2. Threat Actor & Origin Intelligence\n")
	sb.WriteString(fmt.Sprintf("- **Target IP:** `%s` %s\n", r.TargetIP, r.Geo.FlagEmoji))
	sb.WriteString(fmt.Sprintf("- **Location:** %s, %s (Coordinates: `%.4f, %.4f`)\n", r.Geo.City, r.Geo.CountryName, r.Geo.Latitude, r.Geo.Longitude))
	sb.WriteString(fmt.Sprintf("- **ASN / Network:** `%s`\n", r.Geo.ASN))
	sb.WriteString(fmt.Sprintf("- **Attacking Sensor Node:** `%s`\n", r.NodeID))
	sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK:** `%s` (%s)\n\n", r.MitreTechniqueID, r.MitreTechniqueName))

	sb.WriteString("## 3. Forensic Analysis & Root Cause\n")
	sb.WriteString(fmt.Sprintf("- **Attacker Intent:** %s\n", r.AttackerIntent))
	sb.WriteString(fmt.Sprintf("- **Root Cause:** %s\n\n", r.RootCause))

	sb.WriteString("## 4. Indicators of Compromise (IoCs)\n")
	for _, ioc := range r.IoCs {
		sb.WriteString(fmt.Sprintf("- `%s`\n", ioc))
	}
	sb.WriteString("\n")

	sb.WriteString("## 5. Autonomous SOAR Mitigations Enforced\n")
	for _, mit := range r.MitigationDetails {
		sb.WriteString(fmt.Sprintf("- ✔ %s\n", mit))
	}
	sb.WriteString("\n")

	sb.WriteString("## 6. Strategic Recommendations & Hardening\n")
	for _, rec := range r.Recommendations {
		sb.WriteString(fmt.Sprintf("1. %s\n", rec))
	}
	sb.WriteString("\n")

	sb.WriteString("## 7. Raw Telemetry Payload\n")
	sb.WriteString("```json\n" + r.RawPayload + "\n```\n")

	return sb.String()
}

// ToHTML renders a standalone, printable, cybersecurity executive report with print-to-PDF styles.
func (r *IncidentForensicReport) ToHTML() string {
	sevColor := "#00f3ff"
	if r.Severity == "CRITICAL" {
		sevColor = "#ff0055"
	} else if r.Severity == "HIGH" {
		sevColor = "#ff5500"
	} else if r.Severity == "MEDIUM" {
		sevColor = "#ffb700"
	}

	var iocHTML strings.Builder
	for _, ioc := range r.IoCs {
		iocHTML.WriteString(fmt.Sprintf("<li><code>%s</code></li>", escapeHTML(ioc)))
	}

	var mitHTML strings.Builder
	for _, mit := range r.MitigationDetails {
		mitHTML.WriteString(fmt.Sprintf("<li>✔ %s</li>", escapeHTML(mit)))
	}

	var recHTML strings.Builder
	for _, rec := range r.Recommendations {
		recHTML.WriteString(fmt.Sprintf("<li>%s</li>", escapeHTML(rec)))
	}

	var timelineHTML strings.Builder
	for _, t := range r.Timeline {
		timelineHTML.WriteString(fmt.Sprintf(
			"<tr><td>%s</td><td><span class='badge'>%s</span></td><td>%s</td><td style='color: %s; font-weight: bold;'>%d</td></tr>",
			t.TimeStr, escapeHTML(t.Source), escapeHTML(t.Event), sevColor, t.ThreatScore,
		))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CoPSeC Executive Forensic Report - %s</title>
  <style>
    :root {
      --bg: #090e1a;
      --card: #111a2e;
      --border: #1e2c4a;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: %s;
      --cyan: #00f3ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2.5rem;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2.5rem;
      box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }
    .header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand h1 { font-size: 1.5rem; color: #fff; letter-spacing: 1px; }
    .brand p { font-size: 0.8rem; color: var(--muted); font-family: monospace; }
    .severity-badge {
      background: rgba(255, 0, 85, 0.15);
      border: 1px solid var(--accent);
      color: var(--accent);
      padding: 0.4rem 1rem;
      border-radius: 6px;
      font-weight: 800;
      font-family: monospace;
      font-size: 1.1rem;
    }
    h2 { font-size: 1.15rem; color: var(--cyan); margin: 1.5rem 0 0.75rem; border-left: 4px solid var(--accent); padding-left: 0.6rem; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .meta-box {
      background: #090e1a;
      border: 1px solid var(--border);
      padding: 0.75rem 1rem;
      border-radius: 6px;
    }
    .meta-box label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; font-family: monospace; display: block; }
    .meta-box span { font-size: 0.95rem; font-weight: 700; color: #fff; }
    ul, ol { padding-left: 1.5rem; margin-bottom: 1rem; }
    li { margin-bottom: 0.4rem; font-size: 0.88rem; }
    code { font-family: ui-monospace, monospace; background: #060913; padding: 0.15rem 0.4rem; border-radius: 4px; color: var(--cyan); font-size: 0.85rem; }
    pre { background: #04070e; border: 1px solid var(--border); padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 0.78rem; color: #cbd5e1; }
    table { width: 100%%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.82rem; }
    th { background: #070b14; text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); font-family: monospace; color: var(--muted); }
    td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #17233d; }
    .badge { background: #17233d; padding: 0.15rem 0.45rem; border-radius: 4px; font-family: monospace; font-size: 0.75rem; color: var(--cyan); }
    .btn-print {
      background: var(--cyan);
      color: #000;
      border: none;
      padding: 0.5rem 1.25rem;
      border-radius: 6px;
      font-weight: 700;
      cursor: pointer;
      font-size: 0.85rem;
    }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .container { border: none; box-shadow: none; max-width: 100%%; }
      .btn-print { display: none; }
      pre, .meta-box { background: #f8fafc; border-color: #cbd5e1; color: #000; }
      code { background: #e2e8f0; color: #000; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <h1>⚡ CoPSeC CYBER DEFENSE CENTER</h1>
        <p>AUTONOMOUS FORENSIC INCIDENT INVESTIGATION REPORT</p>
      </div>
      <div style="text-align: right;">
        <div class="severity-badge">%s (%d/100)</div>
        <button class="btn-print" style="margin-top: 0.6rem;" onclick="window.print()">🖨️ Print / Save PDF</button>
      </div>
    </div>

    <div class="meta-grid">
      <div class="meta-box"><label>Incident ID</label><span>%s</span></div>
      <div class="meta-box"><label>Generated Timestamp</label><span>%s</span></div>
      <div class="meta-box"><label>Threat Actor IP</label><span>%s %s</span></div>
      <div class="meta-box"><label>Origin Country / ASN</label><span>%s (%s)</span></div>
      <div class="meta-box"><label>MITRE ATT&CK</label><span>%s</span></div>
      <div class="meta-box"><label>Sensor Node</label><span>%s</span></div>
    </div>

    <h2>1. Executive Summary</h2>
    <p style="font-size: 0.92rem; color: #cbd5e1; margin-bottom: 1.25rem;">%s</p>

    <h2>2. Threat Actor Intent & Root Cause</h2>
    <ul>
      <li><strong>Identified Intent:</strong> %s</li>
      <li><strong>Triggering Root Cause:</strong> %s</li>
      <li><strong>Detection Signature:</strong> <code>%s</code></li>
    </ul>

    <h2>3. Indicators of Compromise (IoCs)</h2>
    <ul>%s</ul>

    <h2>4. Autonomous SOAR Actions Enforced (Zero-Latency)</h2>
    <ul>%s</ul>

    <h2>5. Chronological Incident Timeline</h2>
    <table>
      <thead>
        <tr><th>Timestamp</th><th>Sensor Source</th><th>Incident Details</th><th>Score</th></tr>
      </thead>
      <tbody>%s</tbody>
    </table>

    <h2>6. Strategic Remediation & Hardening Actions</h2>
    <ol>%s</ol>

    <h2>7. Raw Telemetry Forensic Artifact</h2>
    <pre>%s</pre>

    <div style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem; font-size: 0.75rem; color: var(--muted); text-align: center; font-family: monospace;">
      CONFIDENTIAL & PROPRIETARY — GENERATED AUTONOMOUSLY BY COPSEC SOAR MATRIX
    </div>
  </div>
</body>
</html>`,
		escapeHTML(r.IncidentID),
		sevColor,
		r.Severity, r.ThreatScore,
		escapeHTML(r.IncidentID),
		escapeHTML(r.GeneratedAt),
		escapeHTML(r.TargetIP), r.Geo.FlagEmoji,
		escapeHTML(r.Geo.CountryName), escapeHTML(r.Geo.ASN),
		escapeHTML(r.MitreTechniqueID),
		escapeHTML(r.NodeID),
		escapeHTML(r.ExecutiveSummary),
		escapeHTML(r.AttackerIntent),
		escapeHTML(r.RootCause),
		escapeHTML(r.RuleID),
		iocHTML.String(),
		mitHTML.String(),
		timelineHTML.String(),
		recHTML.String(),
		escapeHTML(r.RawPayload),
	)
}

func parseAIAnalysisFields(aiAnalysis, ruleID string) (intent, rootCause string) {
	intent = "Malicious probe and unauthorized reconnaissance against edge service"
	rootCause = fmt.Sprintf("Triggered detection rule signature: %s", ruleID)

	if aiAnalysis == "" {
		return intent, rootCause
	}

	lines := strings.Split(aiAnalysis, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "• Intent:") {
			intent = strings.TrimSpace(strings.TrimPrefix(l, "• Intent:"))
		} else if strings.HasPrefix(l, "• Root Cause:") {
			rootCause = strings.TrimSpace(strings.TrimPrefix(l, "• Root Cause:"))
		}
	}
	return intent, rootCause
}

func resolveMitreName(mitreID string) string {
	names := map[string]string{
		"T1190":     "Exploit Public-Facing Application",
		"T1110":     "Brute Force",
		"T1110.001": "Password Guessing / Credential Stuffing",
		"T1595":     "Active Scanning",
		"T1595.002": "Vulnerability Scanning / Honey-URL Probing",
		"T1059":     "Command and Scripting Interpreter (RCE)",
		"T1078":     "Valid Accounts Abuse",
		"T1498":     "Network Denial of Service",
	}
	if n, ok := names[mitreID]; ok {
		return n
	}
	return "Uncategorized Threat Vector"
}

func escapeHTML(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(str, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
}
