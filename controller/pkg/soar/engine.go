package soar

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// PlaybookStep defines an individual remediation, triage, or eradication phase.
type PlaybookStep struct {
	Index            int    `json:"index"`
	Badge            string `json:"badge"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	Command          string `json:"command,omitempty"`
	AutomatedAction  string `json:"automated_action,omitempty"`
	RequiresApproval bool   `json:"requires_approval"`
	Status           string `json:"status"` // PENDING, IN_PROGRESS, COMPLETED, SKIPPED, FAILED
	Output           string `json:"output,omitempty"`
	CompletedAtMs    int64  `json:"completed_at_ms,omitempty"`
}

// Playbook represents a curated SOAR incident response workflow.
type Playbook struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Category         string         `json:"category"`
	MitreTechniques  []string       `json:"mitre_techniques"`
	SeverityTarget   string         `json:"severity_target"` // HIGH, CRITICAL
	SLATargetSeconds int            `json:"sla_target_seconds"`
	Description      string         `json:"description"`
	TriggerRules     []string       `json:"trigger_rules"`
	Steps            []PlaybookStep `json:"steps"`
	AutoTrigger      bool           `json:"auto_trigger"`
}

// PlaybookRun captures a live, executed instance of a playbook for an incident.
type PlaybookRun struct {
	RunID            string         `json:"run_id"`
	IncidentID       int64          `json:"incident_id"`
	PlaybookID       string         `json:"playbook_id"`
	PlaybookName     string         `json:"playbook_name"`
	ActorIP          string         `json:"actor_ip"`
	NodeID           string         `json:"node_id"`
	ThreatScore      int            `json:"threat_score"`
	MitreID          string         `json:"mitre_id"`
	TriggerReason    string         `json:"trigger_reason"`
	CurrentStepIdx   int            `json:"current_step_idx"`
	TotalSteps       int            `json:"total_steps"`
	Status           string         `json:"status"` // PENDING, RUNNING, CONTAINED, RESOLVED, FAILED
	StartedAtMs      int64          `json:"started_at_ms"`
	CompletedAtMs    int64          `json:"completed_at_ms,omitempty"`
	SLATargetSeconds int            `json:"sla_target_seconds"`
	Steps            []PlaybookStep `json:"steps"`
	ActionsExecuted  []string       `json:"actions_executed"`
}

// Engine manages playbook catalog, execution state, and high-fidelity trigger gating.
type Engine struct {
	mu         sync.RWMutex
	playbooks  map[string]*Playbook
	activeRuns map[string]*PlaybookRun
	runHistory []*PlaybookRun
	actionHook func(actionType, actorIP, nodeID, param string) (string, error)
}

var (
	defaultEngine *Engine
	once          sync.Once
)

// GetDefaultEngine returns the global singleton SOAR Engine.
func GetDefaultEngine() *Engine {
	once.Do(func() {
		defaultEngine = NewEngine()
	})
	return defaultEngine
}

// NewEngine instantiates a SOAR Engine with curated industrial playbooks.
func NewEngine() *Engine {
	e := &Engine{
		playbooks:  make(map[string]*Playbook),
		activeRuns: make(map[string]*PlaybookRun),
		runHistory: make([]*PlaybookRun, 0, 100),
	}
	e.seedCuratedPlaybooks()
	return e
}

// SetActionHook configures external dispatch hooks (e.g. into XDP, Tarpit, P2P, Telegram).
func (e *Engine) SetActionHook(hook func(actionType, actorIP, nodeID, param string) (string, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actionHook = hook
}

// seedCuratedPlaybooks registers curated industrial SOAR response workflows.
func (e *Engine) seedCuratedPlaybooks() {
	// 1. PB-101: Web App RCE & Injection Mitigation
	e.playbooks["PB-101"] = &Playbook{
		ID:               "PB-101",
		Name:             "Web Application RCE & Injection Mitigation",
		Category:         "Web Defense",
		MitreTechniques:  []string{"T1190", "T1059"},
		SeverityTarget:   "CRITICAL",
		SLATargetSeconds: 60,
		Description:      "Mitigates critical remote code execution, SQL injection, and web shell upload sequences targeting public ingress endpoints.",
		TriggerRules:     []string{"rce", "sqli", "revshell", "webshell", "cmd_injection"},
		AutoTrigger:      true,
		Steps: []PlaybookStep{
			{
				Index:           0,
				Badge:           "STEP 1: TRIAGE",
				Title:           "Correlate Ingress Request & Offending Payload",
				Description:     "Inspect web access logs for request URI, HTTP methods, and parameter payloads around incident timestamp.",
				Command:         "grep '<IP>' /var/log/nginx/access.log | tail -n 25",
				AutomatedAction: "PULL_ACCESS_LOGS",
				Status:          "PENDING",
			},
			{
				Index:           1,
				Badge:           "STEP 2: SCOPE",
				Title:           "Assess Process Tree & Response HTTP Status",
				Description:     "Verify whether web daemon spawned interactive sub-shells or responded with HTTP 200 OK.",
				Command:         "ps auxf | grep -E 'www-data|nginx|httpd|apache' | grep -E 'sh|bash|python|nc'",
				AutomatedAction: "AI_FORENSICS",
				Status:          "PENDING",
			},
			{
				Index:           2,
				Badge:           "STEP 3: CONTAINMENT",
				Title:           "Enforce Fleet-Wide Kernel XDP Blackhole",
				Description:     "Inject attacker IP into NIC ring-buffer XDP drop map across all edge nodes and kill active conntrack sockets.",
				Command:         "conntrack -D -s <IP>",
				AutomatedAction: "XDP_BLACKHOLE",
				Status:          "PENDING",
			},
			{
				Index:           3,
				Badge:           "STEP 4: ERADICATION",
				Title:           "Patch Application Endpoint & Invalidate Sessions",
				Description:     "Deploy zero-day WAF signature, restart affected web service, and audit /tmp and /dev/shm for web shells.",
				Command:         "nginx -t && systemctl reload nginx",
				AutomatedAction: "RELOAD_WAF",
				Status:          "PENDING",
			},
		},
	}

	// 2. PB-204: SSH & PAM Authentication Brute-Force Tarpit
	e.playbooks["PB-204"] = &Playbook{
		ID:               "PB-204",
		Name:             "SSH & PAM Authentication Brute-Force Tarpit",
		Category:         "Identity & Auth",
		MitreTechniques:  []string{"T1110", "T1078"},
		SeverityTarget:   "HIGH",
		SLATargetSeconds: 30,
		Description:      "Detects high-velocity credential stuffing and SSH brute-force campaigns, trapping sockets in Zero-Window TCP Tarpits.",
		TriggerRules:     []string{"ssh_auth_burst", "pam_auth_fail", "bruteforce", "credential_spray"},
		AutoTrigger:      true,
		Steps: []PlaybookStep{
			{
				Index:           0,
				Badge:           "STEP 1: TRIAGE",
				Title:           "Calculate Authentication Failure Velocity",
				Description:     "Analyze rate of authentication rejections and targeted user accounts in /var/log/auth.log.",
				Command:         "grep '<IP>' /var/log/auth.log | grep -E 'Failed password|authentication failure' | tail -n 20",
				AutomatedAction: "PULL_ACCESS_LOGS",
				Status:          "PENDING",
			},
			{
				Index:           1,
				Badge:           "STEP 2: CONTAINMENT",
				Title:           "Route Attacker to Zero-Window Deception Tarpit",
				Description:     "Divert incoming TCP port 22/80/443 connection streams into sticky Zero-Window Tarpit to exhaust attacker sockets.",
				Command:         "iptables -t nat -A PREROUTING -s <IP> -p tcp -j REDIRECT --to-ports 12223",
				AutomatedAction: "TARPIT_TRAP",
				Status:          "PENDING",
			},
			{
				Index:           2,
				Badge:           "STEP 3: SCOPE",
				Title:           "Audit Targeted User Accounts for Breach Acceptance",
				Description:     "Confirm whether any targeted user was successfully authenticated from this actor IP.",
				Command:         "grep '<IP>' /var/log/auth.log | grep 'Accepted'",
				Status:          "PENDING",
			},
			{
				Index:           3,
				Badge:           "STEP 4: ERADICATION",
				Title:           "Lock Compromised Accounts & Enforce Key-Based Auth",
				Description:     "Temporarily lock breached accounts (passwd -l), invalidate PAM tokens, and sync swarm-wide quarantine.",
				Command:         "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
				AutomatedAction: "FLEET_BAN",
				Status:          "PENDING",
			},
		},
	}

	// 3. PB-305: C2 Egress & DNS Exfiltration Containment
	e.playbooks["PB-305"] = &Playbook{
		ID:               "PB-305",
		Name:             "C2 Egress & DNS Exfiltration Containment",
		Category:         "Network & C2",
		MitreTechniques:  []string{"T1071", "T1568", "T1048"},
		SeverityTarget:   "CRITICAL",
		SLATargetSeconds: 45,
		Description:      "Identifies outbound C2 beaconing, DGA domains, and Shannon high-entropy DNS tunneling channels.",
		TriggerRules:     []string{"c2_beacon", "dga_domain", "dns_tunneling", "ml_flow_anomaly"},
		AutoTrigger:      true,
		Steps: []PlaybookStep{
			{
				Index:           0,
				Badge:           "STEP 1: TRIAGE",
				Title:           "Inspect Statistical Shannon Entropy & Jitter",
				Description:     "Verify query domain entropy and correlate outbound TCP/UDP beaconing interval distributions.",
				Command:         "ss -tulpn | grep '<IP>'",
				AutomatedAction: "AI_FORENSICS",
				Status:          "PENDING",
			},
			{
				Index:           1,
				Badge:           "STEP 2: CONTAINMENT",
				Title:           "Sinkhole Malicious Domain on Local Resolver",
				Description:     "Redirect all outbound DNS lookups for malicious FQDN to local zero-trust sinkhole resolver (0.0.0.0).",
				Command:         "rndc flush || systemd-resolve --flush-caches",
				AutomatedAction: "DNS_SINKHOLE",
				Status:          "PENDING",
			},
			{
				Index:           2,
				Badge:           "STEP 3: SCOPE",
				Title:           "Isolate Attacker Outbound Flows via XDP",
				Description:     "Block all outbound and inbound packets to C2 destination endpoints across edge sensor mesh.",
				Command:         "conntrack -F",
				AutomatedAction: "XDP_BLACKHOLE",
				Status:          "PENDING",
			},
			{
				Index:           3,
				Badge:           "STEP 4: ERADICATION",
				Title:           "Terminate Beaconing Process & Purge Persistence",
				Description:     "Identify and SIGKILL PID responsible for beaconing socket and check systemd services / crontab.",
				Command:         "ls -lat /tmp /dev/shm /var/tmp | head -n 25",
				Status:          "PENDING",
			},
		},
	}

	// 4. PB-406: Rootkit Defense & eBPF Hook Tamper Guard
	pb406 := &Playbook{
		ID:               "PB-406",
		Name:             "Kernel Rootkit & eBPF Hook Tamper Guard",
		Category:         "Host & Kernel",
		MitreTechniques:  []string{"T1014", "T1055"},
		SeverityTarget:   "CRITICAL",
		SLATargetSeconds: 15,
		Description:      "Instantly intercepts unauthorized ptrace injection, LKM rootkit loading, and critical system file hash drift.",
		TriggerRules:     []string{"rootkit_tamper", "ptrace_injection", "fim_tamper", "module_taint"},
		AutoTrigger:      true,
		Steps: []PlaybookStep{
			{
				Index:           0,
				Badge:           "STEP 1: TRIAGE",
				Title:           "Audit Kernel Ring Buffer & Symbol Tables",
				Description:     "Inspect /proc/modules and kernel dmesg for tainted flags or unauthorized syscall hooks.",
				Command:         "dmesg -T | grep -E 'taint|module|hook|ptrace' | tail -n 25",
				AutomatedAction: "AUDIT_KERNEL",
				Status:          "PENDING",
			},
			{
				Index:           1,
				Badge:           "STEP 2: CONTAINMENT",
				Title:           "Terminate Rogue Injection PID via SIGKILL",
				Description:     "Issue kernel-level SIGKILL to rogue process attempting process_vm_writev or ptrace injection.",
				Command:         "kill -9 <PID>",
				AutomatedAction: "SIGKILL_PID",
				Status:          "PENDING",
			},
			{
				Index:           2,
				Badge:           "STEP 3: REMEDIATION",
				Title:           "Trigger FIM Self-Healing Restoration",
				Description:     "Restore tampered system configuration files from cryptographic snapshot storage.",
				Command:         "dpkg -V || rpm -V -a",
				AutomatedAction: "FIM_SELF_HEAL",
				Status:          "PENDING",
			},
			{
				Index:           3,
				Badge:           "STEP 4: HARDENING",
				Title:           "Lock Kernel Module Loading",
				Description:     "Disable kernel module loading runtime switch (sysctl kernel.modules_disabled=1).",
				Command:         "sysctl -w kernel.modules_disabled=1",
				AutomatedAction: "LOCK_MODULES",
				Status:          "PENDING",
			},
		},
	}
	e.playbooks["PB-406"] = pb406
	e.playbooks["PB-402"] = pb406

	// 5. PB-501: Privilege Escalation & Sudo Anomaly Alert
	e.playbooks["PB-501"] = &Playbook{
		ID:               "PB-501",
		Name:             "Privilege Escalation & Sudo Anomaly Alert",
		Category:         "Host & Privilege",
		MitreTechniques:  []string{"T1068", "T1078"},
		SeverityTarget:   "HIGH",
		SLATargetSeconds: 90,
		Description:      "Triages abnormal sudo executions, unauthorized root shell escalation, and su attempts outside maintenance windows.",
		TriggerRules:     []string{"sudo_escalation", "setuid_exec", "unauthorized_root"},
		AutoTrigger:      false,
		Steps: []PlaybookStep{
			{
				Index:       0,
				Badge:       "STEP 1: TRIAGE",
				Title:       "Verify Sudoer Execution Context",
				Description: "Correlate executed sudo command, requesting user, and originating terminal or TTY.",
				Command:     "grep 'sudo:' /var/log/auth.log | tail -n 20",
				Status:      "PENDING",
			},
			{
				Index:       1,
				Badge:       "STEP 2: SCOPE",
				Title:       "Audit Interactive Shell Sockets",
				Description: "Check if user holds active root terminal sessions.",
				Command:     "w && who && ps -ef | grep -E 'pts/|tty'",
				Status:      "PENDING",
			},
			{
				Index:           2,
				Badge:           "STEP 3: CONTAINMENT",
				Title:           "Invalidate Active User Session Tokens",
				Description:     "Terminate active user TTY sessions and revoke temporary sudo permissions.",
				Command:         "pkill -KILL -u <USER>",
				AutomatedAction: "REVOKE_SESSION",
				Status:          "PENDING",
			},
			{
				Index:       3,
				Badge:       "STEP 4: HARDENING",
				Title:       "Audit Sudoers File Integrity",
				Description: "Verify /etc/sudoers and /etc/sudoers.d/ configuration integrity.",
				Command:     "visudo -c",
				Status:      "PENDING",
			},
		},
	}
}

// GetPlaybooks returns all registered playbook templates.
func (e *Engine) GetPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	list := make([]*Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		list = append(list, pb)
	}
	return list
}

// GetPlaybook retrieves a single playbook template.
func (e *Engine) GetPlaybook(id string) *Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.playbooks[id]
}

// ShouldTriggerSOAR evaluates whether an incoming telemetry event qualifies for automated SOAR intervention.
// It applies strict anti-noise filters to reject benign static asset requests, internal DNS, and routine probes.
func (e *Engine) ShouldTriggerSOAR(
	threatScore int,
	clientIP string,
	ruleID string,
	mitreID string,
	rawLine string,
	recentEventsCount int,
) (bool, string, string) {
	ruleLower := strings.ToLower(ruleID)
	mitreUpper := strings.ToUpper(mitreID)

	// 1. High-Severity Instant Triggers (Kernel Tamper / Rootkit / FIM / eBPF - applies to host-local too)
	if strings.Contains(ruleLower, "rootkit") ||
		strings.Contains(ruleLower, "ptrace") ||
		strings.Contains(ruleLower, "fim_healing") ||
		strings.Contains(ruleLower, "module_taint") ||
		mitreUpper == "T1014" || mitreUpper == "T1055" {
		return true, "Critical Kernel / Rootkit Security Violation Intercepted", "PB-406"
	}

	// 2. Absolute Exclusions (Host/Bogon or benign static asset requests)
	ipClean := strings.TrimSpace(clientIP)
	if ipClean == "" || ipClean == "-" {
		return false, "", ""
	}

	// Filter out whitelisted DNS resolvers and local IPs for network attacks
	if ipClean == "8.8.8.8" || ipClean == "8.8.4.4" || ipClean == "1.1.1.1" || ipClean == "1.0.0.1" ||
		ipClean == "9.9.9.9" || ipClean == "208.67.222.222" || ipClean == "208.67.220.220" ||
		ipClean == "213.186.33.99" || ipClean == "213.186.33.100" || ipClean == "127.0.0.1" || ipClean == "::1" ||
		strings.HasPrefix(ipClean, "10.") || strings.HasPrefix(ipClean, "192.168.") || strings.HasPrefix(ipClean, "100.") {
		return false, "", ""
	}

	rawLower := strings.ToLower(rawLine)

	// Filter out benign static asset requests, routine health checks, and standard DNS queries
	if strings.Contains(rawLower, "robots.txt") ||
		strings.Contains(rawLower, "favicon.ico") ||
		strings.Contains(rawLower, ".png") ||
		strings.Contains(rawLower, ".jpg") ||
		strings.Contains(rawLower, ".css") ||
		strings.Contains(rawLower, ".js") ||
		strings.Contains(rawLower, ".woff") ||
		strings.Contains(rawLower, "/health") ||
		strings.Contains(rawLower, "/metrics") ||
		strings.Contains(rawLower, `"event_type":"stats"`) ||
		strings.Contains(rawLower, `"event_type":"dns"`) ||
		ruleID == "suricata_flow" || ruleID == "suricata_dns" {
		return false, "", ""
	}

	// Filter out routine auditd command execution logs
	if strings.Contains(rawLower, "type=user_cmd") || strings.Contains(rawLower, "type=cred_acq") || strings.Contains(rawLower, "type=syscall") {
		if threatScore < 90 {
			return false, "", ""
		}
	}

	// 3. DNS C2 Tunneling / Exfiltration Interception
	if strings.Contains(ruleLower, "dns_tunnel") ||
		strings.Contains(ruleLower, "dga_domain") ||
		strings.Contains(ruleLower, "c2_beacon") {
		return true, "Autonomous DNS C2 Exfiltration & Beaconing Detected", "PB-305"
	}

	// 4. Critical Web Application Exploits (RCE, Injection, Webshell)
	if (threatScore >= 80 || strings.Contains(ruleLower, "rce") || strings.Contains(ruleLower, "revshell") || strings.Contains(ruleLower, "webshell")) &&
		(strings.Contains(rawLower, "/bin/sh") || strings.Contains(rawLower, "/bin/bash") || strings.Contains(rawLower, "nc -e") || strings.Contains(rawLower, "union select") || strings.Contains(rawLower, "system(")) {
		return true, fmt.Sprintf("High-Confidence Web Application Exploit (Score: %d)", threatScore), "PB-101"
	}

	// 5. High-Velocity Authentication Brute-Force (>= 3 events within window)
	if (strings.Contains(ruleLower, "auth") || strings.Contains(ruleLower, "pam") || strings.Contains(ruleLower, "ssh")) &&
		(recentEventsCount >= 3 || threatScore >= 85) {
		return true, fmt.Sprintf("High-Velocity Authentication Brute-Force (%d attempts)", recentEventsCount), "PB-204"
	}

	// 6. Generic High Threat Score Gating (Score >= 80 and confirmed malicious MITRE technique)
	if threatScore >= 80 {
		mitreUpper := strings.ToUpper(mitreID)
		if mitreUpper == "T1190" || mitreUpper == "T1059" {
			return true, fmt.Sprintf("High-Threat Telemetry Trigger (Score: %d, MITRE: %s)", threatScore, mitreUpper), "PB-101"
		} else if mitreUpper == "T1110" || mitreUpper == "T1078" {
			return true, fmt.Sprintf("High-Threat Authentication Anomaly (Score: %d, MITRE: %s)", threatScore, mitreUpper), "PB-204"
		} else if mitreUpper == "T1071" || mitreUpper == "T1568" {
			return true, fmt.Sprintf("High-Threat Network C2 Flow (Score: %d, MITRE: %s)", threatScore, mitreUpper), "PB-305"
		} else if mitreUpper == "T1014" || mitreUpper == "T1055" {
			return true, fmt.Sprintf("High-Threat Host Integrity Breach (Score: %d, MITRE: %s)", threatScore, mitreUpper), "PB-406"
		}
	}

	return false, "", ""
}

// StartPlaybookRun instantiates and registers an active playbook execution instance.
func (e *Engine) StartPlaybookRun(
	incidentID int64,
	playbookID string,
	actorIP string,
	nodeID string,
	threatScore int,
	mitreID string,
	triggerReason string,
) *PlaybookRun {
	e.mu.Lock()
	defer e.mu.Unlock()

	template, exists := e.playbooks[playbookID]
	if !exists {
		template = e.playbooks["PB-101"]
		playbookID = "PB-101"
	}

	runID := fmt.Sprintf("RUN-%d-%d", incidentID, time.Now().Unix())
	if incidentID == 0 {
		runID = fmt.Sprintf("RUN-%s-%d", playbookID, time.Now().Unix())
	}

	// Clone template steps
	steps := make([]PlaybookStep, len(template.Steps))
	for i, s := range template.Steps {
		cmd := strings.ReplaceAll(s.Command, "<IP>", actorIP)
		cmd = strings.ReplaceAll(cmd, "<PID>", "1234")
		steps[i] = PlaybookStep{
			Index:            s.Index,
			Badge:            s.Badge,
			Title:            s.Title,
			Description:      s.Description,
			Command:          cmd,
			AutomatedAction:  s.AutomatedAction,
			RequiresApproval: s.RequiresApproval,
			Status:           "PENDING",
		}
	}
	if len(steps) > 0 {
		steps[0].Status = "IN_PROGRESS"
	}

	run := &PlaybookRun{
		RunID:            runID,
		IncidentID:       incidentID,
		PlaybookID:       playbookID,
		PlaybookName:     template.Name,
		ActorIP:          actorIP,
		NodeID:           nodeID,
		ThreatScore:      threatScore,
		MitreID:          mitreID,
		TriggerReason:    triggerReason,
		CurrentStepIdx:   0,
		TotalSteps:       len(steps),
		Status:           "RUNNING",
		StartedAtMs:      time.Now().UnixMilli(),
		SLATargetSeconds: template.SLATargetSeconds,
		Steps:            steps,
		ActionsExecuted:  make([]string, 0),
	}

	e.activeRuns[runID] = run
	e.runHistory = append(e.runHistory, run)
	if len(e.runHistory) > 100 {
		e.runHistory = e.runHistory[1:]
	}

	return run
}

// GetActiveRuns returns all currently active or recently executed playbook runs.
func (e *Engine) GetActiveRuns() []*PlaybookRun {
	e.mu.RLock()
	defer e.mu.RUnlock()
	runs := make([]*PlaybookRun, 0, len(e.runHistory))
	for _, r := range e.runHistory {
		runs = append(runs, r)
	}
	return runs
}

// GetRun retrieves a playbook run by its ID.
func (e *Engine) GetRun(runID string) *PlaybookRun {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeRuns[runID]
}

// AdvanceStep transitions a playbook step state and advances progress.
func (e *Engine) AdvanceStep(runID string, stepIdx int, status string, output string) (*PlaybookRun, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	run, exists := e.activeRuns[runID]
	if !exists {
		return nil, fmt.Errorf("playbook run %s not found", runID)
	}

	if stepIdx < 0 || stepIdx >= len(run.Steps) {
		return nil, fmt.Errorf("step index %d out of bounds (total %d)", stepIdx, len(run.Steps))
	}

	run.Steps[stepIdx].Status = status
	run.Steps[stepIdx].Output = output
	run.Steps[stepIdx].CompletedAtMs = time.Now().UnixMilli()

	// Check next step
	if status == "COMPLETED" {
		if stepIdx+1 < len(run.Steps) {
			run.CurrentStepIdx = stepIdx + 1
			if run.Steps[stepIdx+1].Status == "PENDING" {
				run.Steps[stepIdx+1].Status = "IN_PROGRESS"
			}
		} else {
			run.Status = "CONTAINED"
			run.CompletedAtMs = time.Now().UnixMilli()
		}
	}

	return run, nil
}

// ExecuteRemediationAction dispatches an actionable remediation command.
func (e *Engine) ExecuteRemediationAction(actionType, actorIP, nodeID, param string) (map[string]interface{}, error) {
	e.mu.RLock()
	hook := e.actionHook
	e.mu.RUnlock()

	msg := fmt.Sprintf("Executed action %s on %s", actionType, actorIP)
	if hook != nil {
		out, err := hook(actionType, actorIP, nodeID, param)
		if err != nil {
			return nil, err
		}
		if out != "" {
			msg = out
		}
	}

	return map[string]interface{}{
		"success":     true,
		"action_type": actionType,
		"actor_ip":    actorIP,
		"node_id":     nodeID,
		"message":     msg,
		"executed_at": time.Now().UnixMilli(),
	}, nil
}
