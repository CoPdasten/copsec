package ttp

import (
	"strings"
	"sync"
)

// TTPInfo represents a MITRE ATT&CK Technique specification.
type TTPInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Tactic       string   `json:"tactic"`
	Description  string   `json:"description"`
	URL          string   `json:"url"`
	SecondaryIDs []string `json:"secondary_ids,omitempty"`
}

var (
	// Immutable registry of known MITRE ATT&CK techniques
	techniqueRegistry = map[string]TTPInfo{
		"T1498.001": {
			ID:          "T1498.001",
			Name:        "Network Denial of Service: Direct Network Flood",
			Tactic:      "Impact",
			Description: "Adversaries may conduct volumetric floods (such as TCP SYN floods or ICMP floods) to exhaust network interfaces or stateful firewall tables.",
			URL:         "https://attack.mitre.org/techniques/T1498/001/",
		},
		"T1498": {
			ID:          "T1498",
			Name:        "Network Denial of Service",
			Tactic:      "Impact",
			Description: "Adversaries may target network systems to disrupt availability of networks and systems.",
			URL:         "https://attack.mitre.org/techniques/T1498/",
		},
		"T1499": {
			ID:          "T1499",
			Name:        "Endpoint Denial of Service",
			Tactic:      "Impact",
			Description: "Adversaries may target endpoints to degrade service availability or trigger resource exhaustion.",
			URL:         "https://attack.mitre.org/techniques/T1499/",
		},
		"T1027": {
			ID:          "T1027",
			Name:        "Obfuscated Files or Information",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may attempt to make an executable or payload difficult to discover or analyze via high-entropy encryption or packers.",
			URL:         "https://attack.mitre.org/techniques/T1027/",
			SecondaryIDs: []string{"T1071"},
		},
		"T1071": {
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			Tactic:      "Command and Control",
			Description: "Adversaries may communicate using application layer protocols to blend in with normal network traffic.",
			URL:         "https://attack.mitre.org/techniques/T1071/",
		},
		"T1071.004": {
			ID:          "T1071.004",
			Name:        "Application Layer Protocol: DNS",
			Tactic:      "Command and Control",
			Description: "Adversaries may communicate using DNS request/response pairs for C2 channels or high-entropy data tunneling.",
			URL:         "https://attack.mitre.org/techniques/T1071/004/",
		},
		"T1046": {
			ID:          "T1046",
			Name:        "Network Service Discovery",
			Tactic:      "Discovery",
			Description: "Adversaries may attempt to get a listing of services and open ports running on remote hosts (e.g. SYN port scanning, sweep scans).",
			URL:         "https://attack.mitre.org/techniques/T1046/",
		},
		"T1190": {
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Tactic:      "Initial Access",
			Description: "Adversaries may exploit vulnerabilities (e.g., Log4Shell, SQLi, Spring4Shell, Remote Code Execution) in Internet-facing software.",
			URL:         "https://attack.mitre.org/techniques/T1190/",
		},
		"T1059.004": {
			ID:          "T1059.004",
			Name:        "Command and Scripting Interpreter: Unix Shell",
			Tactic:      "Execution",
			Description: "Adversaries may abuse Unix shell commands and scripts (bash, sh, zsh) for execution after initial compromise.",
			URL:         "https://attack.mitre.org/techniques/T1059/004/",
		},
		"T1078": {
			ID:          "T1078",
			Name:        "Valid Accounts",
			Tactic:      "Defense Evasion / Initial Access",
			Description: "Adversaries may obtain and abuse credentials of existing accounts, or trigger honeypot canary tokens.",
			URL:         "https://attack.mitre.org/techniques/T1078/",
		},
		"T1110": {
			ID:          "T1110",
			Name:        "Brute Force",
			Tactic:      "Credential Access",
			Description: "Adversaries may use brute force techniques to attempt credential guessing on exposed services like SSH or web logins.",
			URL:         "https://attack.mitre.org/techniques/T1110/",
		},
		"T1048": {
			ID:          "T1048",
			Name:        "Exfiltration Over Alternative Protocol",
			Tactic:      "Exfiltration",
			Description: "Adversaries may steal data by transferring it over an alternative network protocol or tunnel.",
			URL:         "https://attack.mitre.org/techniques/T1048/",
		},
	}

	// Rule to TTP mapping aliases
	ruleToTTPAliases = map[string]string{
		// SYN Flood / Layer 4 Floods
		"syn_flood_drop":             "T1498.001",
		"xdp_syn_flood":              "T1498.001",
		"drop_reason_syn_flood":      "T1498.001",
		"syn_flood":                  "T1498.001",
		"tcp_syn_flood":              "T1498.001",
		"xdp_drop_syn_flood":         "T1498.001",

		// High Shannon Entropy Anomalies
		"shannon_entropy_anomaly":    "T1027",
		"entropy_anomaly":            "T1027",
		"xdp_entropy_anomaly":        "T1027",
		"drop_reason_entropy_anomaly": "T1027",
		"pcap_entropy_anomaly":       "T1027",
		"c2_encrypted_entropy":       "T1027",

		// Tarpit / Port Scanning
		"tarpit_port_scanner":        "T1046",
		"tarpit":                     "T1046",
		"xdp_tarpit":                 "T1046",
		"drop_reason_tarpit":         "T1046",
		"port_scan":                  "T1046",
		"syn_scan":                   "T1046",

		// L7 Exploit Patterns (Log4j, Spring4Shell, CVEs)
		"l7_exploit_pattern":         "T1190",
		"xdp_l7_dpi":                 "T1190",
		"drop_reason_l7_dpi":         "T1190",
		"log4j":                      "T1190",
		"cve_2021_44228":             "T1190",
		"rce_exploit":                "T1190",
		"sqli":                       "T1190",

		// DNS C2 / Tunneling / Sinkhole
		"dns_c2_sinkhole":            "T1071.004",
		"dns_sinkhole":               "T1071.004",
		"dns_tunneling":              "T1071.004",
		"dns_entropy":                "T1071.004",
		"dns_dga":                    "T1071.004",

		// EDR / Rogue Process Terminations
		"edr_kill":                   "T1059.004",
		"rogue_process":              "T1059.004",
		"shell_spawn":                "T1059.004",

		// Honeypot / Canary
		"canary_token":               "T1078",
		"canary_trigger":             "T1078",
		"honeypot":                   "T1078",

		// Rate Limit
		"rate_limit":                 "T1499",
		"xdp_rate_limit":             "T1499",
		"drop_reason_rate_limit":     "T1499",

		// BGP
		"bgp_rtbh":                   "T1498",
		"rtbh_blackhole":             "T1498",
	}

	mu sync.RWMutex
)

// LookupByID resolves a MITRE Technique ID (e.g. "T1027", "T1498.001") to its metadata.
func LookupByID(id string) (TTPInfo, bool) {
	cleanID := strings.ToUpper(strings.TrimSpace(id))
	mu.RLock()
	defer mu.RUnlock()
	info, ok := techniqueRegistry[cleanID]
	return info, ok
}

// LookupByRule resolves an eBPF drop code, rule ID, or event reason to its MITRE ATT&CK TTPInfo.
func LookupByRule(ruleOrReason string) (TTPInfo, bool) {
	clean := strings.ToLower(strings.TrimSpace(ruleOrReason))
	if clean == "" {
		return TTPInfo{}, false
	}

	mu.RLock()
	defer mu.RUnlock()

	// 1. Check direct alias mapping
	if techID, ok := ruleToTTPAliases[clean]; ok {
		if info, found := techniqueRegistry[techID]; found {
			return info, true
		}
	}

	// 2. Check if clean string already is a technique ID
	upper := strings.ToUpper(clean)
	if info, found := techniqueRegistry[upper]; found {
		return info, true
	}

	// 3. Substring matching for robust fallback
	for k, techID := range ruleToTTPAliases {
		if strings.Contains(clean, k) {
			if info, found := techniqueRegistry[techID]; found {
				return info, true
			}
		}
	}

	return TTPInfo{}, false
}

// GetAllTechniques returns a snapshot of all registered MITRE techniques.
func GetAllTechniques() map[string]TTPInfo {
	mu.RLock()
	defer mu.RUnlock()
	res := make(map[string]TTPInfo, len(techniqueRegistry))
	for k, v := range techniqueRegistry {
		res[k] = v
	}
	return res
}
