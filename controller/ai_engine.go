package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIThreatIntel stores structured threat reasoning and mitigation advice.
type AIThreatIntel struct {
	AttackerIntent  string `json:"attacker_intent"`
	RootCause       string `json:"root_cause"`
	Mitigation      string `json:"mitigation"`
	ConfidenceScore int    `json:"confidence_score"`
}

// AIEngine coordinates local heuristic intelligence and optional LLM REST API lookups.
type AIEngine struct {
	provider   string // "local", "openai", "gemini", "ollama", "deepseek"
	apiKey     string
	endpoint   string
	modelName  string
	httpClient *http.Client
}

// NewAIEngine initializes the AI threat analysis engine.
func NewAIEngine() *AIEngine {
	provider := os.Getenv("COPSEC_AI_PROVIDER")
	apiKey := os.Getenv("COPSEC_AI_API_KEY")
	endpoint := os.Getenv("COPSEC_AI_ENDPOINT")
	model := os.Getenv("COPSEC_AI_MODEL")

	if provider == "" {
		if apiKey != "" {
			provider = "openai"
		} else {
			provider = "local"
		}
	}

	if model == "" {
		if provider == "openai" {
			model = "gpt-4o-mini"
		} else if provider == "gemini" {
			model = "gemini-1.5-flash"
		} else if provider == "ollama" {
			model = "llama3"
		} else {
			model = "copsec-heuristic-v2"
		}
	}

	log.Printf("[INFO] AI Threat Engine initialized (Provider: %s, Model: %s)", provider, model)

	return &AIEngine{
		provider:   provider,
		apiKey:     apiKey,
		endpoint:   endpoint,
		modelName:  model,
		httpClient: &http.Client{Timeout: 6 * time.Second},
	}
}

// AnalyzeIntent computes tactical intent, root cause, and mitigation for high-severity events.
func (ai *AIEngine) AnalyzeIntent(ctx context.Context, ev *StoredEvent) AIThreatIntel {
	if ai.provider == "openai" || ai.provider == "deepseek" {
		intel, err := ai.callOpenAICompatibleAPI(ctx, ev)
		if err == nil {
			return intel
		}
		log.Printf("[WARN] AI API error (%v), falling back to local heuristic intelligence", err)
	}

	return ai.localHeuristicAnalysis(ev)
}

func (ai *AIEngine) localHeuristicAnalysis(ev *StoredEvent) AIThreatIntel {
	tech := ev.MitreTechniqueID
	lower := strings.ToLower(ev.RawLine)

	intent := "Reconnaissance & Vulnerability Probing"
	rootCause := "Unauthenticated endpoint exposure"
	mitigation := "Enforce strict IP rate limiting and pre-routing drop"
	confidence := 85

	if strings.HasPrefix(tech, "T1190") {
		if strings.Contains(lower, "select") || strings.Contains(lower, "union") {
			intent = "Database Exfiltration via SQL Injection"
			rootCause = "Unsanitized user input concatenated into SQL query"
			mitigation = "Use parameterized prepared statements and block attacker CIDR"
			confidence = 95
		} else if strings.Contains(lower, "jndi") || strings.Contains(lower, "classloader") {
			intent = "Remote Code Execution (Log4j / Spring4Shell)"
			rootCause = "Vulnerable framework component accepting untrusted remote lookups"
			mitigation = "Patch Java/Spring library and immediately ban IP"
			confidence = 98
		} else if strings.Contains(lower, "..") || strings.Contains(lower, "/etc/") {
			intent = "Local File Inclusion / Sensitive System Information Theft"
			rootCause = "Improper file path validation in web controller"
			mitigation = "Sanitize file path inputs with basename constraint"
			confidence = 90
		}
	} else if strings.HasPrefix(tech, "T1059") {
		intent = "Interactive Unix Shell Execution & Lateral Movement"
		rootCause = "Command injection vulnerability or compromised credentials"
		mitigation = "Isolate host, terminate rogue shell PID, and execute Global Fleet Ban"
		confidence = 95
	} else if strings.HasPrefix(tech, "T1110") {
		intent = "Authentication Brute Force / Credential Stuffing"
		rootCause = "Exposed SSH/Web login interface without fail2ban/MFA protection"
		mitigation = "Enforce public-key authentication only and ban IP for 24 hours"
		confidence = 90
	} else if strings.HasPrefix(tech, "T1070") || strings.HasPrefix(tech, "T1562") {
		intent = "Defense Evasion & Security Log Tampering"
		rootCause = "Post-exploitation intruder attempting to disable monitoring"
		mitigation = "Audit kernel auditd logs and perform immediate incident response"
		confidence = 92
	} else if strings.HasPrefix(tech, "T1027") {
		intent = "Evasive Payload Delivery (High Entropy / Obfuscation)"
		rootCause = "Attacker utilizing multi-stage encoding to bypass perimeter WAF"
		mitigation = "Deploy strict payload normalization and ban source IP"
		confidence = 88
	}

	return AIThreatIntel{
		AttackerIntent:  intent,
		RootCause:       rootCause,
		Mitigation:      mitigation,
		ConfidenceScore: confidence,
	}
}

func (ai *AIEngine) callOpenAICompatibleAPI(ctx context.Context, ev *StoredEvent) (AIThreatIntel, error) {
	apiURL := "https://api.openai.com/v1/chat/completions"
	if ai.endpoint != "" {
		apiURL = ai.endpoint
	}

	prompt := fmt.Sprintf(`Analyze this security log incident and return JSON with keys "attacker_intent", "root_cause", "mitigation", "confidence_score" (0-100).
Source: %s
Client IP: %s
MITRE: %s
ThreatScore: %d
Payload: %s`, ev.Source, ev.ClientIP, ev.MitreTechniqueID, ev.ThreatScore, ev.RawLine)

	bodyData := map[string]interface{}{
		"model": ai.modelName,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a cyber threat intelligence AI expert. Answer strictly in valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
	}

	jsonBytes, err := json.Marshal(bodyData)
	if err != nil {
		return AIThreatIntel{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return AIThreatIntel{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ai.apiKey)

	resp, err := ai.httpClient.Do(req)
	if err != nil {
		return AIThreatIntel{}, err
	}
	defer resp.Body.Close()

	var apiRes struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiRes); err != nil || len(apiRes.Choices) == 0 {
		return AIThreatIntel{}, fmt.Errorf("invalid API response")
	}

	content := apiRes.Choices[0].Message.Content
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var intel AIThreatIntel
	if err := json.Unmarshal([]byte(content), &intel); err != nil {
		return AIThreatIntel{}, err
	}

	return intel, nil
}
