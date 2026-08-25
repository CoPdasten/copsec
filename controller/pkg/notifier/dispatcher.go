package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/copsec/controller/pkg/ai_agent"
)

// Config holds notification channel authentication and webhook targets.
type Config struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
	DiscordWebhook   string `json:"discord_webhook_url"`
}

// DispatchResult tracks delivery status across notification channels.
type DispatchResult struct {
	TelegramSuccess bool   `json:"telegram_success"`
	TelegramError   string `json:"telegram_error,omitempty"`
	DiscordSuccess  bool   `json:"discord_success"`
	DiscordError    string `json:"discord_error,omitempty"`
	WebSOCDispatched bool   `json:"websoc_dispatched"`
}

// ToastCallback is invoked when an AI triage brief is dispatched, notifying the Web SOC UI.
type ToastCallback func(brief *ai_agent.AITriageBrief)

// ActionHandler is invoked when an interactive button callback is executed from Telegram.
type ActionHandler func(action, ip string) error

// Dispatcher manages multi-channel security incident alert forwarding.
type Dispatcher struct {
	mu              sync.RWMutex
	cfg             Config
	httpClient      *http.Client
	toastListener   ToastCallback
	actionHandler   ActionHandler
	telegramBaseURL string
}

var (
	defaultDispatcher *Dispatcher
	once              sync.Once
)

// GetDefaultDispatcher returns or initializes the singleton Dispatcher.
func GetDefaultDispatcher() *Dispatcher {
	once.Do(func() {
		defaultDispatcher = NewDispatcher(Config{})
	})
	return defaultDispatcher
}

// NewDispatcher initializes the multi-channel notification dispatcher.
func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.TelegramBotToken == "" {
		cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
		if cfg.TelegramBotToken == "" {
			cfg.TelegramBotToken = os.Getenv("COPSEC_TELEGRAM_TOKEN")
		}
	}
	if cfg.TelegramChatID == "" {
		cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")
		if cfg.TelegramChatID == "" {
			cfg.TelegramChatID = os.Getenv("COPSEC_TELEGRAM_CHAT")
		}
	}
	if cfg.DiscordWebhook == "" {
		cfg.DiscordWebhook = os.Getenv("DISCORD_WEBHOOK_URL")
		if cfg.DiscordWebhook == "" {
			cfg.DiscordWebhook = os.Getenv("COPSEC_DISCORD_WEBHOOK")
		}
	}

	tgActive := cfg.TelegramBotToken != "" && cfg.TelegramChatID != ""
	discordActive := cfg.DiscordWebhook != ""

	log.Printf("[INFO] Multi-Channel Alert Dispatcher initialized (Telegram: %v, Discord: %v)",
		tgActive, discordActive)

	return &Dispatcher{
		cfg:             cfg,
		httpClient:      &http.Client{Timeout: 6 * time.Second},
		telegramBaseURL: "https://api.telegram.org",
	}
}

// SetTelegramBaseURL overrides the Telegram API base URL (useful for local mock testing).
func (d *Dispatcher) SetTelegramBaseURL(url string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.telegramBaseURL = strings.TrimSuffix(url, "/")
}

// UpdateConfig dynamically updates notification targets.
func (d *Dispatcher) UpdateConfig(cfg Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cfg.TelegramBotToken != "" {
		d.cfg.TelegramBotToken = cfg.TelegramBotToken
	}
	if cfg.TelegramChatID != "" {
		d.cfg.TelegramChatID = cfg.TelegramChatID
	}
	if cfg.DiscordWebhook != "" {
		d.cfg.DiscordWebhook = cfg.DiscordWebhook
	}
}

// SetToastListener registers a callback for live Web SOC dashboard toasts.
func (d *Dispatcher) SetToastListener(cb ToastCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.toastListener = cb
}

// SetActionHandler registers a callback for interactive containment actions triggered via Telegram buttons.
func (d *Dispatcher) SetActionHandler(h ActionHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.actionHandler = h
}

// DispatchTriageAlert distributes an AI forensic brief to Telegram, Discord, and Web SOC.
func (d *Dispatcher) DispatchTriageAlert(ctx context.Context, brief *ai_agent.AITriageBrief) *DispatchResult {
	if brief == nil {
		return &DispatchResult{}
	}

	res := &DispatchResult{}

	// 1. Web SOC Toast Notification (Non-blocking)
	d.mu.RLock()
	toastCb := d.toastListener
	tgToken := d.cfg.TelegramBotToken
	tgChat := d.cfg.TelegramChatID
	discordURL := d.cfg.DiscordWebhook
	d.mu.RUnlock()

	if toastCb != nil {
		toastCb(brief)
		res.WebSOCDispatched = true
	}

	// 2. Telegram Alert Dispatch
	if tgToken != "" && tgChat != "" {
		err := d.sendTelegramAlert(ctx, tgToken, tgChat, brief)
		if err != nil {
			log.Printf("[WARN] Failed to dispatch Telegram alert: %v", err)
			res.TelegramError = err.Error()
		} else {
			res.TelegramSuccess = true
		}
	}

	// 3. Discord Webhook Dispatch
	if discordURL != "" {
		err := d.sendDiscordEmbed(ctx, discordURL, brief)
		if err != nil {
			log.Printf("[WARN] Failed to dispatch Discord alert: %v", err)
			res.DiscordError = err.Error()
		} else {
			res.DiscordSuccess = true
		}
	}

	return res
}

func (d *Dispatcher) sendTelegramAlert(ctx context.Context, token, chatID string, brief *ai_agent.AITriageBrief) error {
	d.mu.RLock()
	baseURL := d.telegramBaseURL
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	d.mu.RUnlock()

	url := fmt.Sprintf("%s/bot%s/sendMessage", baseURL, token)

	header := "🚨 *[CoPSeC AI Incident Triage Brief]*"
	if brief.ThreatScore >= 95 {
		header = "🔥 *[CoPSeC CRITICAL AI INCIDENT TRIAGE]*"
	}

	geoStr := ""
	if brief.CountryCode != "" && brief.CountryCode != "LOC" {
		geoStr = fmt.Sprintf(" %s (%s, %s)", brief.FlagEmoji, brief.CountryName, brief.ASN)
	} else if brief.ClientIP == "127.0.0.1" || brief.ClientIP == "local" {
		geoStr = " 🖥️ (HOST LOCAL)"
	}

	text := fmt.Sprintf("%s\n\n"+
		"🎯 *Target / Node:* `%s`\n"+
		"🌍 *Threat Actor:* `%s`%s\n"+
		"⚡ *Threat Score:* `%d/100` | 🏷 `%s` (%s)\n\n"+
		"🧠 *AI Threat Assessment:*\n%s (Confidence: %d%%)\n\n"+
		"🎯 *Vector & Target:*\n%s\n\n"+
		"🛡️ *Enforced Mitigation:*\n`%s`\n\n"+
		"💡 *Recommended Operator Action:*\n_%s_\n\n"+
		"⏱ _Generated by CoPSeC LLM Agent (%s)_",
		header,
		brief.NodeID,
		brief.ClientIP,
		geoStr,
		brief.ThreatScore,
		brief.RuleID,
		brief.MitreTechniqueID,
		brief.ThreatAssessment,
		brief.ConfidenceScore,
		brief.VectorAndTarget,
		brief.EnforcedMitigation,
		brief.RecommendedAction,
		brief.Model,
	)

	// Interactive Telegram Buttons
	var buttons [][]map[string]string
	if brief.ClientIP != "" && brief.ClientIP != "127.0.0.1" && brief.ClientIP != "local" && brief.ClientIP != "-" {
		buttons = [][]map[string]string{
			{
				{"text": "⚡ Swarm Ban", "callback_data": fmt.Sprintf("ban:%s", brief.ClientIP)},
				{"text": "🕳 Move to Tarpit", "callback_data": fmt.Sprintf("tarpit:%s", brief.ClientIP)},
				{"text": "🔓 Release", "callback_data": fmt.Sprintf("unban:%s", brief.ClientIP)},
			},
		}
	}

	reqPayload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if len(buttons) > 0 {
		reqPayload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": buttons,
		}
	}

	jsonBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func (d *Dispatcher) sendDiscordEmbed(ctx context.Context, webhookURL string, brief *ai_agent.AITriageBrief) error {
	// Color: Neon Red (0xFF0055 = 16711765) for >= 90, Neon Amber (0xF59E0B = 16096779) for >= 70
	color := 16096779
	if brief.ThreatScore >= 90 {
		color = 16711765
	}

	actorValue := fmt.Sprintf("`%s` %s %s\n%s", brief.ClientIP, brief.FlagEmoji, brief.CountryName, brief.ASN)
	if brief.ClientIP == "127.0.0.1" || brief.ClientIP == "local" || brief.ClientIP == "" {
		actorValue = "🖥️ `127.0.0.1` (HOST_LOCAL)"
	}

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("🚨 AI SOC Forensic Incident Triage - Node %s", brief.NodeID),
		"description": fmt.Sprintf("**Threat Score:** `%d/100` • **MITRE:** `%s` • **Rule:** `%s`", brief.ThreatScore, brief.MitreTechniqueID, brief.RuleID),
		"color":       color,
		"fields": []map[string]interface{}{
			{
				"name":   "🎯 Vector & Target",
				"value":  brief.VectorAndTarget,
				"inline": false,
			},
			{
				"name":   "🧠 AI Threat Assessment",
				"value":  fmt.Sprintf("%s *(Confidence: %d%%)*", brief.ThreatAssessment, brief.ConfidenceScore),
				"inline": false,
			},
			{
				"name":   "🛡️ Enforced Mitigation",
				"value":  fmt.Sprintf("`%s`", brief.EnforcedMitigation),
				"inline": true,
			},
			{
				"name":   "🌍 Threat Actor",
				"value":  actorValue,
				"inline": true,
			},
			{
				"name":   "💡 Recommended Operator Action",
				"value":  brief.RecommendedAction,
				"inline": false,
			},
		},
		"footer": map[string]string{
			"text": fmt.Sprintf("CoPSeC Autonomous SIEM/SOAR Matrix • AI Agent (%s)", brief.Model),
		},
		"timestamp": time.UnixMilli(brief.TimestampMs).UTC().Format(time.RFC3339),
	}

	reqBody := map[string]interface{}{
		"username":   "CoPSeC Autonomous SOC Analyst",
		"avatar_url": "https://raw.githubusercontent.com/CoPdasten/copsec/main/docs/assets/shield.png",
		"embeds":     []map[string]interface{}{embed},
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord webhook status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}
