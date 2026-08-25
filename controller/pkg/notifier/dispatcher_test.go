package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/copsec/controller/pkg/ai_agent"
)

func TestTelegramAndDiscordAlertDispatch(t *testing.T) {
	var telegramReceived bool
	var discordReceived bool

	// Mock Telegram Server
	mockTelegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		telegramReceived = true
		body, _ := io.ReadAll(r.Body)

		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)

		text, _ := payload["text"].(string)
		if !strings.Contains(text, "CoPSeC") {
			t.Errorf("Expected CoPSeC header in Telegram message, got %s", text)
		}

		replyMarkup, ok := payload["reply_markup"].(map[string]interface{})
		if !ok || replyMarkup["inline_keyboard"] == nil {
			t.Errorf("Expected inline_keyboard buttons in Telegram payload")
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"result":{"message_id":1001}}`))
	}))
	defer mockTelegram.Close()

	// Mock Discord Server
	mockDiscord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discordReceived = true
		body, _ := io.ReadAll(r.Body)

		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)

		embeds, ok := payload["embeds"].([]interface{})
		if !ok || len(embeds) == 0 {
			t.Errorf("Expected embeds in Discord webhook payload")
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer mockDiscord.Close()

	var toastReceived bool
	dispatcher := NewDispatcher(Config{
		TelegramBotToken: "mock-token",
		TelegramChatID:   "123456",
		DiscordWebhook:   mockDiscord.URL,
	})
	dispatcher.SetTelegramBaseURL(mockTelegram.URL)

	dispatcher.SetToastListener(func(brief *ai_agent.AITriageBrief) {
		toastReceived = true
	})

	brief := &ai_agent.AITriageBrief{
		ID:                 "triage-test-1",
		TimestampMs:        time.Now().UnixMilli(),
		ClientIP:           "198.51.100.44",
		NodeID:             "node-edge-1",
		ThreatScore:        95,
		RuleID:             "sigma-web-sqli",
		MitreTechniqueID:   "T1190",
		CountryCode:        "US",
		CountryName:        "United States",
		FlagEmoji:          "🇺🇸",
		ASN:                "AS16509 Amazon AWS",
		VectorAndTarget:    "SQL Injection against /login",
		ThreatAssessment:   "Database extraction attack",
		EnforcedMitigation: "XDP_DROP Active",
		RecommendedAction:  "Review SQL parameterization",
		ConfidenceScore:    96,
		Model:              "gemini-2.5-flash",
	}

	// 1. Test Discord Embed Dispatch
	errDiscord := dispatcher.sendDiscordEmbed(context.Background(), mockDiscord.URL, brief)
	if errDiscord != nil {
		t.Fatalf("sendDiscordEmbed failed: %v", errDiscord)
	}
	if !discordReceived {
		t.Errorf("Discord server did not receive webhook")
	}

	// 2. Test Telegram Alert Dispatch with mock endpoint
	errTg := dispatcher.sendTelegramAlert(context.Background(), "mock-token", "123456", brief)
	if errTg != nil {
		t.Fatalf("sendTelegramAlert failed: %v", errTg)
	}
	if !telegramReceived {
		t.Errorf("Telegram mock server did not receive alert")
	}

	// 3. Test Full DispatchTriageAlert with Toast Callback
	res := dispatcher.DispatchTriageAlert(context.Background(), brief)
	if !res.WebSOCDispatched || !toastReceived {
		t.Errorf("Expected Web SOC Toast to be dispatched")
	}
	if !res.DiscordSuccess {
		t.Errorf("Expected Discord webhook to succeed, err: %s", res.DiscordError)
	}
	if !res.TelegramSuccess {
		t.Errorf("Expected Telegram to succeed, err: %s", res.TelegramError)
	}
}
