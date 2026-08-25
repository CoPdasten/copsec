package ai_agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AITriageBrief represents a structured, executive LLM forensic report for high-severity incidents.
type AITriageBrief struct {
	ID                 string `json:"id"`
	TimestampMs        int64  `json:"timestamp_ms"`
	ClientIP           string `json:"client_ip"`
	NodeID             string `json:"node_id"`
	ThreatScore        int    `json:"threat_score"`
	RuleID             string `json:"rule_id"`
	MitreTechniqueID   string `json:"mitre_technique_id"`
	CountryCode        string `json:"country_code"`
	CountryName        string `json:"country_name"`
	FlagEmoji          string `json:"flag_emoji"`
	ASN                string `json:"asn"`
	VectorAndTarget    string `json:"vector_and_target"`
	ThreatAssessment   string `json:"threat_assessment"`
	EnforcedMitigation string `json:"enforced_mitigation"`
	RecommendedAction  string `json:"recommended_action"`
	ConfidenceScore    int    `json:"confidence_score"`
	ExecutiveSummary   string `json:"executive_summary"`
	RawMarkdown        string `json:"raw_markdown"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
}

// IncidentContext provides raw telemetry and security signals to the LLM.
type IncidentContext struct {
	NodeID           string
	Source           string
	RawLine          string
	ClientIP         string
	StatusCode       int
	ThreatScore      int
	RuleID           string
	MitreTechniqueID string
	CountryCode      string
	CountryName      string
	FlagEmoji        string
	ASN              string
	ContainmentState string
	MLAnomaly        bool
	MLConfidencePct  float64
	SnortML          bool
	SnortConfidence  float64
}

// Config defines LLM agent settings.
type Config struct {
	Provider       string        `json:"provider"` // "gemini", "openai", "ollama", "local"
	APIKey         string        `json:"api_key"`
	Endpoint       string        `json:"endpoint"`
	Model          string        `json:"model"`
	DebounceWindow time.Duration `json:"debounce_window"`
	ScoreThreshold int           `json:"score_threshold"`
}

// Agent coordinates LLM-based autonomous forensic investigation and debounced triage generation.
type Agent struct {
	mu           sync.RWMutex
	cfg          Config
	httpClient   *http.Client
	debounced    map[string]time.Time
	recentBriefs []*AITriageBrief
	maxHistory   int
}

var (
	defaultAgent *Agent
	once         sync.Once
)

// GetDefaultAgent returns or initializes the singleton AI agent.
func GetDefaultAgent() *Agent {
	once.Do(func() {
		defaultAgent = NewAgent(Config{})
	})
	return defaultAgent
}

// NewAgent creates and initializes the autonomous LLM SOC analyst agent.
func NewAgent(cfg Config) *Agent {
	if cfg.Provider == "" {
		cfg.Provider = os.Getenv("COPSEC_AI_PROVIDER")
		if cfg.Provider == "" {
			cfg.Provider = os.Getenv("LLM_PROVIDER")
		}
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("COPSEC_AI_API_KEY")
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("LLM_API_KEY")
		}
	}
	if cfg.Model == "" {
		cfg.Model = os.Getenv("COPSEC_AI_MODEL")
		if cfg.Model == "" {
			cfg.Model = os.Getenv("LLM_MODEL")
		}
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = os.Getenv("COPSEC_AI_ENDPOINT")
		if cfg.Endpoint == "" {
			cfg.Endpoint = os.Getenv("LLM_ENDPOINT")
		}
	}

	if cfg.Provider == "" {
		if cfg.APIKey != "" {
			if strings.HasPrefix(cfg.APIKey, "AIza") {
				cfg.Provider = "gemini"
			} else {
				cfg.Provider = "openai"
			}
		} else {
			cfg.Provider = "local"
		}
	}

	if cfg.Model == "" {
		switch cfg.Provider {
		case "gemini":
			cfg.Model = "gemini-2.5-flash"
		case "openai":
			cfg.Model = "gpt-4o-mini"
		case "ollama":
			cfg.Model = "llama3"
		default:
			cfg.Model = "copsec-cyber-analyst-v1"
		}
	}

	if cfg.DebounceWindow <= 0 {
		cfg.DebounceWindow = 5 * time.Minute
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 85
	}

	log.Printf("[INFO] Autonomous LLM SOC Analyst initialized (Provider: %s, Model: %s, Threshold: %d)",
		cfg.Provider, cfg.Model, cfg.ScoreThreshold)

	return &Agent{
		cfg:          cfg,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		debounced:    make(map[string]time.Time),
		recentBriefs: make([]*AITriageBrief, 0, 100),
		maxHistory:   100,
	}
}

// UpdateConfig dynamically updates AI model, provider, and API key.
func (a *Agent) UpdateConfig(apiKey, model, provider string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if apiKey != "" {
		a.cfg.APIKey = apiKey
	}
	if model != "" {
		a.cfg.Model = model
	}
	if provider != "" {
		a.cfg.Provider = provider
	} else if apiKey != "" {
		if strings.HasPrefix(apiKey, "AIza") {
			a.cfg.Provider = "gemini"
		} else {
			a.cfg.Provider = "openai"
		}
	}
	log.Printf("[CONFIG] Autonomous LLM SOC Analyst updated (Provider: %s, Model: %s)", a.cfg.Provider, a.cfg.Model)
}

// ShouldAnalyze checks whether an event qualifies for autonomous AI triage (score >= 85 or critical scope, debounced per IP).
func (a *Agent) ShouldAnalyze(threatScore int, clientIP, ruleID string) bool {
	isCriticalRule := strings.Contains(strings.ToLower(ruleID), "rce") ||
		strings.Contains(strings.ToLower(ruleID), "revshell") ||
		strings.Contains(strings.ToLower(ruleID), "rootkit") ||
		strings.Contains(strings.ToLower(ruleID), "sqli") ||
		strings.Contains(strings.ToLower(ruleID), "c2")

	if threatScore < a.cfg.ScoreThreshold && !isCriticalRule {
		return false
	}

	cleanIP := strings.TrimSpace(clientIP)
	if cleanIP == "" {
		cleanIP = "host_local"
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if lastTime, exists := a.debounced[cleanIP]; exists {
		if now.Sub(lastTime) < a.cfg.DebounceWindow {
			return false // Debounced: alert already generated within 5 minutes
		}
	}

	a.debounced[cleanIP] = now
	return true
}

// AnalyzeIncident executes LLM prompt engineering pipeline and generates a structured 4-bullet executive triage card.
func (a *Agent) AnalyzeIncident(ctx context.Context, ic *IncidentContext) (*AITriageBrief, error) {
	if ic == nil {
		return nil, fmt.Errorf("nil incident context")
	}

	var brief *AITriageBrief
	var err error

	switch a.cfg.Provider {
	case "gemini":
		brief, err = a.callGeminiAPI(ctx, ic)
	case "openai":
		brief, err = a.callOpenAIAPI(ctx, ic)
	case "ollama":
		brief, err = a.callOllamaAPI(ctx, ic)
	default:
		brief = a.generateLocalHeuristicBrief(ic)
	}

	if err != nil {
		log.Printf("[WARN] LLM API call failed (%v), falling back to offline forensic engine", err)
		brief = a.generateLocalHeuristicBrief(ic)
	}

	// Format final structured fields
	brief.ID = generateBriefID()
	brief.TimestampMs = time.Now().UnixMilli()
	brief.ClientIP = ic.ClientIP
	brief.NodeID = ic.NodeID
	brief.ThreatScore = ic.ThreatScore
	brief.RuleID = ic.RuleID
	brief.MitreTechniqueID = ic.MitreTechniqueID
	brief.CountryCode = ic.CountryCode
	brief.CountryName = ic.CountryName
	brief.FlagEmoji = ic.FlagEmoji
	brief.ASN = ic.ASN
	brief.Provider = a.cfg.Provider
	brief.Model = a.cfg.Model

	if brief.EnforcedMitigation == "" {
		if ic.ContainmentState != "" {
			brief.EnforcedMitigation = ic.ContainmentState
		} else if ic.ClientIP == "127.0.0.1" || ic.ClientIP == "local" || ic.ClientIP == "" {
			brief.EnforcedMitigation = "HOST_CONTAINED (Process Guard / Local Isolation)"
		} else {
			brief.EnforcedMitigation = "XDP_DROP (eBPF NIC Fast-Path Quarantine Active)"
		}
	}

	brief.RawMarkdown = fmt.Sprintf(
		"🎯 **Vector & Target:** %s\n"+
			"🧠 **AI Threat Assessment:** %s (Confidence: %d%%)\n"+
			"🛡️ **Enforced Mitigation:** %s\n"+
			"💡 **Recommended Operator Action:** %s",
		brief.VectorAndTarget,
		brief.ThreatAssessment,
		brief.ConfidenceScore,
		brief.EnforcedMitigation,
		brief.RecommendedAction,
	)

	brief.ExecutiveSummary = fmt.Sprintf("[%s] %s | %s", brief.MitreTechniqueID, brief.VectorAndTarget, brief.ThreatAssessment)

	a.recordBrief(brief)
	return brief, nil
}

func (a *Agent) recordBrief(brief *AITriageBrief) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recentBriefs = append([]*AITriageBrief{brief}, a.recentBriefs...)
	if len(a.recentBriefs) > a.maxHistory {
		a.recentBriefs = a.recentBriefs[:a.maxHistory]
	}
}

// GetRecentBriefs returns the list of historical AI triage briefs.
func (a *Agent) GetRecentBriefs(limit int) []*AITriageBrief {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if limit <= 0 || limit > len(a.recentBriefs) {
		limit = len(a.recentBriefs)
	}

	res := make([]*AITriageBrief, limit)
	copy(res, a.recentBriefs[:limit])
	return res
}

func (a *Agent) buildSystemPrompt() string {
	return `You are CoPSeC Autonomous Cyber SOC AI Analyst. 
Your role is to produce high-precision, executive-ready forensic triage cards for critical Linux security alerts.
Always return a valid JSON object matching this exact schema:
{
  "vector_and_target": "Concise 1-sentence description of the attack vector, targeted process/port, and node",
  "threat_assessment": "1-2 sentences on attacker intent, exploit mechanism, and tactical threat level",
  "enforced_mitigation": "Current automated SOAR containment status (e.g. XDP_DROP Kernel Drop, Zero-Window Tarpit, SIGKILL Rogue PID)",
  "recommended_action": "Actionable operator follow-up command or investigation step",
  "confidence_score": 95
}
No extra text, no markdown codeblocks, only pure JSON.`
}

func (a *Agent) buildUserPrompt(ic *IncidentContext) string {
	return fmt.Sprintf(
		"Incident Details:\n"+
			"- Node: %s\n"+
			"- Source: %s\n"+
			"- Client IP: %s (%s %s, %s)\n"+
			"- HTTP Status: %d\n"+
			"- Threat Score: %d/100\n"+
			"- Matched Rule: %s\n"+
			"- MITRE Technique: %s\n"+
			"- ML Anomaly: %v (Confidence: %.1f%%)\n"+
			"- Raw Telemetry Payload:\n%s",
		ic.NodeID, ic.Source, ic.ClientIP, ic.FlagEmoji, ic.CountryName, ic.ASN,
		ic.StatusCode, ic.ThreatScore, ic.RuleID, ic.MitreTechniqueID,
		ic.MLAnomaly || ic.SnortML, ic.MLConfidencePct, ic.RawLine,
	)
}

func (a *Agent) callGeminiAPI(ctx context.Context, ic *IncidentContext) (*AITriageBrief, error) {
	if a.cfg.APIKey == "" {
		return nil, fmt.Errorf("missing Gemini API key")
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		a.cfg.Model, a.cfg.APIKey)

	prompt := fmt.Sprintf("%s\n\n%s", a.buildSystemPrompt(), a.buildUserPrompt(ic))

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":        0.1,
			"responseMimeType":  "application/json",
		},
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gemini api returned status %d: %s", resp.StatusCode, string(body))
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("invalid gemini response: %v", err)
	}

	rawJSON := geminiResp.Candidates[0].Content.Parts[0].Text
	return parseTriageJSON(rawJSON)
}

func (a *Agent) callOpenAIAPI(ctx context.Context, ic *IncidentContext) (*AITriageBrief, error) {
	if a.cfg.APIKey == "" {
		return nil, fmt.Errorf("missing OpenAI API key")
	}

	endpoint := a.cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com"
	}
	url := fmt.Sprintf("%s/v1/chat/completions", strings.TrimSuffix(endpoint, "/"))

	reqBody := map[string]interface{}{
		"model": a.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": a.buildSystemPrompt()},
			{"role": "user", "content": a.buildUserPrompt(ic)},
		},
		"temperature": 0.1,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.cfg.APIKey))

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("openai api returned status %d: %s", resp.StatusCode, string(body))
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &openAIResp); err != nil || len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("invalid openai response: %v", err)
	}

	return parseTriageJSON(openAIResp.Choices[0].Message.Content)
}

func (a *Agent) callOllamaAPI(ctx context.Context, ic *IncidentContext) (*AITriageBrief, error) {
	endpoint := a.cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	url := fmt.Sprintf("%s/api/generate", strings.TrimSuffix(endpoint, "/"))

	prompt := fmt.Sprintf("%s\n\n%s", a.buildSystemPrompt(), a.buildUserPrompt(ic))
	reqBody := map[string]interface{}{
		"model":  a.cfg.Model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ollama api returned status %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, err
	}

	return parseTriageJSON(ollamaResp.Response)
}

func parseTriageJSON(raw string) (*AITriageBrief, error) {
	clean := strings.TrimSpace(raw)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)

	var res struct {
		VectorAndTarget    string `json:"vector_and_target"`
		ThreatAssessment   string `json:"threat_assessment"`
		EnforcedMitigation string `json:"enforced_mitigation"`
		RecommendedAction  string `json:"recommended_action"`
		ConfidenceScore    int    `json:"confidence_score"`
	}

	if err := json.Unmarshal([]byte(clean), &res); err != nil {
		return nil, err
	}

	if res.ConfidenceScore <= 0 {
		res.ConfidenceScore = 90
	}

	return &AITriageBrief{
		VectorAndTarget:    res.VectorAndTarget,
		ThreatAssessment:   res.ThreatAssessment,
		EnforcedMitigation: res.EnforcedMitigation,
		RecommendedAction:  res.RecommendedAction,
		ConfidenceScore:    res.ConfidenceScore,
	}, nil
}

func (a *Agent) generateLocalHeuristicBrief(ic *IncidentContext) *AITriageBrief {
	raw := strings.ToLower(ic.RawLine)
	rule := strings.ToLower(ic.RuleID)
	tech := ic.MitreTechniqueID

	vector := fmt.Sprintf("High-severity anomaly targeting node %s", ic.NodeID)
	assessment := "Unauthenticated malicious vector attempting remote compromise"
	mitigation := "XDP_DROP (Kernel-level Fast-Path Ring Buffer Quarantine)"
	recommended := "Inspect process tree and review upstream firewall logs"
	confidence := 85

	if strings.Contains(rule, "sqli") || strings.Contains(raw, "union") || strings.Contains(raw, "select") {
		vector = fmt.Sprintf("SQL Injection exploitation probe targeting web endpoint on %s", ic.NodeID)
		assessment = "Attacker attempting relational database exfiltration and auth bypass via UNION/SELECT payload"
		mitigation = "XDP_DROP + Conntrack Socket Purge Active"
		recommended = "Audit web application SQL parameter bindings and verify database user privileges"
		confidence = 96
	} else if strings.Contains(rule, "revshell") || strings.Contains(raw, "/dev/tcp") || strings.Contains(raw, "nc -e") {
		vector = fmt.Sprintf("Interactive Reverse Shell execution spawn detected on node %s", ic.NodeID)
		assessment = "High-criticality command & control session established to remote socket"
		mitigation = "Host Process Terminated via SIGKILL & XDP Swarm Drop"
		recommended = "Run 'ps auxef' on targeted node and check /proc/net/tcp for residual sockets"
		confidence = 98
	} else if strings.Contains(rule, "rootkit") || strings.Contains(rule, "ebpf") || strings.Contains(rule, "ptrace") {
		vector = fmt.Sprintf("Kernel Rootkit / Process Code Injection attempt detected on node %s", ic.NodeID)
		assessment = "Privilege escalation payload attempting LKM hooking or memory buffer patching"
		mitigation = "eBPF Ring-Buffer Kill + Process Memory Freeze"
		recommended = "Verify kernel integrity with lsmod and run CoPSeC memory scanner"
		confidence = 99
	} else if strings.Contains(rule, "sudo") || rule == "sudo_execution" {
		vector = fmt.Sprintf("Privileged Host Sudo Execution logged on node %s", ic.NodeID)
		assessment = "Local privilege escalation command executed within host OS environment"
		mitigation = "HOST_CONTAINED (Internal Audit Guard Active, Network Ban Inhibited)"
		recommended = "Review sudoers audit log in /var/log/auth.log for authorized operator activity"
		confidence = 92
	} else if strings.Contains(rule, "fim") || strings.Contains(rule, "tamper") {
		vector = fmt.Sprintf("Unauthorized File Integrity Drift detected on node %s", ic.NodeID)
		assessment = "Critical system file modification detected (possible persistence insertion)"
		mitigation = "FIM Self-Healing Active (Restored original SHA256 baseline)"
		recommended = "Check auditd logs to identify the user session that modified the file"
		confidence = 95
	} else if ic.MLAnomaly || ic.SnortML {
		vector = fmt.Sprintf("High-Confidence Traffic Flow Anomaly detected on node %s", ic.NodeID)
		assessment = fmt.Sprintf("Pure-Go Isolation Forest detected zero-day burst pattern (Confidence: %.1f%%)", ic.MLConfidencePct)
		mitigation = "Zero-Window TCP Tarpit Trap Active"
		recommended = "Inspect pcap packet capture stream and correlate with threat intelligence feeds"
		confidence = int(ic.MLConfidencePct)
		if confidence <= 0 {
			confidence = 88
		}
	} else if strings.HasPrefix(tech, "T1110") {
		vector = fmt.Sprintf("Distributed Authentication Brute-Force attack against node %s", ic.NodeID)
		assessment = "High-frequency credential stuffing against exposed SSH/Web service"
		mitigation = "XDP Swarm-Wide Extended Quarantine (24h TTL)"
		recommended = "Enforce SSH public key authentication only and disable password logins"
		confidence = 90
	}

	return &AITriageBrief{
		VectorAndTarget:    vector,
		ThreatAssessment:   assessment,
		EnforcedMitigation: mitigation,
		RecommendedAction:  recommended,
		ConfidenceScore:    confidence,
	}
}

func generateBriefID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("triage-%s", hex.EncodeToString(b))
}
