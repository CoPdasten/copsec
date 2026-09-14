package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotifierSlackAndDiscordFormatting(t *testing.T) {
	alert := &WebhookAlert{
		Timestamp:   time.Now(),
		NodeID:      "sensor-01",
		SourceIP:    "198.51.100.99",
		RuleID:      "L7_LOG4J_EXPLOIT",
		RuleName:    "Apache Log4j RCE Attempt",
		MitreID:     "T1190",
		ThreatScore: 100,
		Severity:    "CRITICAL",
		Action:      "DROP",
		Details:     "JNDI LDAP injection payload detected in HTTP User-Agent",
		TargetPID:   1402,
		TargetComm:  "nginx",
	}

	// 1. Test Slack Payload
	nSlack, _ := NewNotifier(WebhookConfig{
		URL:  "https://hooks.slack.com/services/XXX",
		Type: TypeSlack,
	})
	slackBytes, err := nSlack.formatPayload(alert)
	if err != nil {
		t.Fatalf("Slack format failed: %v", err)
	}
	slackStr := string(slackBytes)
	if !strings.Contains(slackStr, "198.51.100.99") || !strings.Contains(slackStr, "T1190") {
		t.Errorf("Slack payload missing expected fields: %s", slackStr)
	}

	// 2. Test Discord Payload
	nDiscord, _ := NewNotifier(WebhookConfig{
		URL:  "https://discord.com/api/webhooks/123/abc",
		Type: TypeDiscord,
	})
	discordBytes, err := nDiscord.formatPayload(alert)
	if err != nil {
		t.Fatalf("Discord format failed: %v", err)
	}
	discordStr := string(discordBytes)
	if !strings.Contains(discordStr, "198.51.100.99") || !strings.Contains(discordStr, "T1190") {
		t.Errorf("Discord payload missing expected fields: %s", discordStr)
	}
}

func TestNotifierDispatchHTTP(t *testing.T) {
	receivedChan := make(chan map[string]interface{}, 1)

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		receivedChan <- parsed
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		Enabled:     true,
		URL:         server.URL,
		Type:        TypeGeneric,
		MinSeverity: "HIGH",
		Workers:     1,
	}

	notifier, err := NewNotifier(cfg)
	if err != nil {
		t.Fatalf("NewNotifier failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifier.Start(ctx)
	defer notifier.Close()

	// 1. Low severity should NOT be dispatched
	lowAlert := &WebhookAlert{
		ThreatScore: 30,
		Severity:    "LOW",
	}
	if notifier.Dispatch(lowAlert) {
		t.Error("Expected Dispatch to return false for LOW severity alert")
	}

	// 2. High severity should be dispatched
	highAlert := &WebhookAlert{
		SourceIP:    "203.0.113.5",
		ThreatScore: 85,
		Severity:    "HIGH",
		RuleID:      "PORT_SCAN",
		Action:      "TARPIT",
	}
	if !notifier.Dispatch(highAlert) {
		t.Error("Expected Dispatch to return true for HIGH severity alert")
	}

	select {
	case received := <-receivedChan:
		if received["event"] != "copsec_security_alert" {
			t.Errorf("Unexpected payload: %+v", received)
		}
		inc, ok := received["incident"].(map[string]interface{})
		if !ok || inc["source_ip"] != "203.0.113.5" {
			t.Errorf("Unexpected incident data: %+v", inc)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for webhook dispatch")
	}
}
