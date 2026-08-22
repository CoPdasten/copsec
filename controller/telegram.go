package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TelegramBotConfig holds the bot authentication and routing parameters.
type TelegramBotConfig struct {
	BotToken string
	ChatID   string
	Enabled  bool
}

// TelegramSOARBot manages alert forwarding and inline response buttons for global SOAR operations.
type TelegramSOARBot struct {
	cfg        TelegramBotConfig
	server     *CentralServer
	httpClient *http.Client
	mu         sync.Mutex
	lastUpdate int64
}

// NewTelegramSOARBot initializes the Telegram bot client.
func NewTelegramSOARBot(cfg TelegramBotConfig, server *CentralServer) *TelegramSOARBot {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		cfg.Enabled = false
		log.Println("[INFO] Telegram SOAR Bot disabled (token or chat_id not provided)")
	} else {
		cfg.Enabled = true
		log.Printf("[INFO] Telegram SOAR Bot initialized for Chat ID: %s", cfg.ChatID)
	}

	return &TelegramSOARBot{
		cfg:        cfg,
		server:     server,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Start begins listening for high-severity events and polling for callback actions.
func (b *TelegramSOARBot) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !b.cfg.Enabled {
		return
	}

	wg.Add(1)
	go b.pollCallbacks(ctx, wg)
}

// ProcessEvent checks threat thresholds and dispatches interactive Telegram alerts.
func (b *TelegramSOARBot) ProcessEvent(ev *StoredEvent) {
	if !b.cfg.Enabled || ev == nil {
		return
	}

	// Alert condition: ThreatScore >= 40 or critical MITRE tag
	if ev.ThreatScore < 40 && !strings.Contains(ev.RuleID, "rce") && !strings.Contains(ev.RuleID, "sqli") {
		return
	}

	text := fmt.Sprintf("🚨 *CoPSeC Threat Alert*\n\n"+
		"🖥 *Node:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🎯 *Target/IP:* `%s`\n"+
		"🛡 *Rule:* `%s`\n"+
		"🏷 *MITRE:* `%s`\n"+
		"⚡ *Threat Score:* `%d`\n"+
		"⏱ *Time:* `%s`\n\n"+
		"📜 *Payload:*\n`%s`",
		ev.NodeID, ev.Source, ev.ClientIP, ev.RuleID, ev.MitreTechniqueID,
		ev.ThreatScore, time.UnixMilli(ev.TimestampMs).Format("15:04:05"),
		truncateString(ev.RawLine, 120))

	// Interactive Inline Buttons
	buttons := [][]map[string]string{
		{
			{"text": "🚫 Global Ban", "callback_data": fmt.Sprintf("ban:%s", ev.ClientIP)},
			{"text": "🔓 Unban IP", "callback_data": fmt.Sprintf("unban:%s", ev.ClientIP)},
			{"text": "🛡 Whitelist", "callback_data": fmt.Sprintf("white:%s", ev.ClientIP)},
		},
	}

	payload := map[string]interface{}{
		"chat_id":    b.cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
		"reply_markup": map[string]interface{}{
			"inline_keyboard": buttons,
		},
	}

	go b.sendTelegramRequest("sendMessage", payload)
}

func (b *TelegramSOARBot) sendTelegramRequest(method string, payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/%s", b.cfg.BotToken, method)
	resp, err := b.httpClient.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes(), nil
}

// pollCallbacks checks for user button clicks and triggers fleet actions.
func (b *TelegramSOARBot) pollCallbacks(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.fetchUpdates()
		}
	}
}

func (b *TelegramSOARBot) fetchUpdates() {
	payload := map[string]interface{}{
		"offset":  b.lastUpdate + 1,
		"timeout": 2,
	}

	respBytes, err := b.sendTelegramRequest("getUpdates", payload)
	if err != nil {
		return
	}

	var res struct {
		Ok     bool `json:"ok"`
		Result []struct {
			UpdateID      int64 `json:"update_id"`
			CallbackQuery *struct {
				ID      string `json:"id"`
				Data    string `json:"data"`
				Message struct {
					MessageID int64 `json:"message_id"`
				} `json:"message"`
			} `json:"callback_query"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &res); err != nil || !res.Ok {
		return
	}

	for _, update := range res.Result {
		if update.UpdateID > b.lastUpdate {
			b.lastUpdate = update.UpdateID
		}

		if update.CallbackQuery != nil {
			data := update.CallbackQuery.Data
			parts := strings.SplitN(data, ":", 2)
			if len(parts) != 2 {
				continue
			}

			action, ip := parts[0], parts[1]
			var notification string

			switch action {
			case "ban":
				dispatched := b.server.BroadcastSOARCommand("BAN_IP", ip, 86400)
				notification = fmt.Sprintf("🚫 IP %s globally banned across %d nodes.", ip, dispatched)
			case "unban":
				dispatched := b.server.BroadcastSOARCommand("UNBAN_IP", ip, 0)
				notification = fmt.Sprintf("🔓 IP %s unbanned across %d nodes.", ip, dispatched)
			case "white":
				notification = fmt.Sprintf("🛡 IP %s marked as whitelisted.", ip)
			}

			// Acknowledge callback in Telegram
			b.sendTelegramRequest("answerCallbackQuery", map[string]interface{}{
				"callback_query_id": update.CallbackQuery.ID,
				"text":              notification,
				"show_alert":        true,
			})
		}
	}
}

func truncateString(str string, length int) string {
	if len(str) <= length {
		return str
	}
	return str[:length] + "..."
}
