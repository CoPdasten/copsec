package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
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

// TelegramSOARBot manages alert forwarding, inline callbacks, and interactive operator command handling.
type TelegramSOARBot struct {
	cfg        TelegramBotConfig
	server     *CentralServer
	httpClient *http.Client
	lastUpdate int64
}

// NewTelegramSOARBot creates an instance of TelegramSOARBot.
func NewTelegramSOARBot(cfg TelegramBotConfig, server *CentralServer) *TelegramSOARBot {
	if cfg.BotToken != "" && cfg.ChatID != "" {
		cfg.Enabled = true
	}

	return &TelegramSOARBot{
		cfg:        cfg,
		server:     server,
		httpClient: &http.Client{Timeout: 6 * time.Second},
	}
}

// Start begins listening for high-severity events and polling for operator commands and callbacks.
func (b *TelegramSOARBot) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !b.cfg.Enabled {
		return
	}

	log.Printf("[INFO] Telegram SOAR Command Bot starting (ChatID: %s)", b.cfg.ChatID)
	wg.Add(1)
	go b.pollUpdates(ctx, wg)
}

// ProcessEvent checks threat thresholds and dispatches interactive Telegram alerts.
func (b *TelegramSOARBot) ProcessEvent(ev *StoredEvent) {
	if !b.cfg.Enabled || ev == nil {
		return
	}

	// Alert threshold: ThreatScore >= 50
	if ev.ThreatScore < 50 {
		return
	}

	severityEmoji := "⚠️"
	if ev.ThreatScore >= 80 {
		severityEmoji = "🔥"
	} else if ev.ThreatScore >= 65 {
		severityEmoji = "🚨"
	}

	aiSection := ""
	if ev.AIAnalysis != "" {
		aiSection = fmt.Sprintf("\n\n🧠 *AI Threat Intel:*\n%s", ev.AIAnalysis)
	}

	text := fmt.Sprintf("%s *CoPSeC Threat Incident*\n\n"+
		"🖥 *Node:* `%s`\n"+
		"🌐 *Source:* `%s`\n"+
		"🎯 *Target/IP:* `%s`\n"+
		"🛡 *Rule:* `%s`\n"+
		"🏷 *MITRE:* `%s`\n"+
		"⚡ *Threat Score:* `%d/100`\n"+
		"⏱ *Time:* `%s`\n\n"+
		"📜 *Payload:*\n`%s`%s",
		severityEmoji,
		ev.NodeID, ev.Source, ev.ClientIP, ev.RuleID, ev.MitreTechniqueID,
		ev.ThreatScore, time.UnixMilli(ev.TimestampMs).Format("15:04:05"),
		truncateString(ev.RawLine, 140),
		aiSection)

	var buttons [][]map[string]string
	if ev.ClientIP != "" && net.ParseIP(ev.ClientIP) != nil {
		buttons = [][]map[string]string{
			{
				{"text": "🚫 BAN IP", "callback_data": fmt.Sprintf("ban:%s", ev.ClientIP)},
				{"text": "🔓 UNBAN IP", "callback_data": fmt.Sprintf("unban:%s", ev.ClientIP)},
				{"text": "🛡 WHITELIST", "callback_data": fmt.Sprintf("whitelist:%s", ev.ClientIP)},
			},
		}
	}

	payload := map[string]interface{}{
		"chat_id":    b.cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if len(buttons) > 0 {
		payload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": buttons,
		}
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

// pollUpdates polls Telegram for operator text commands and inline button callbacks.
func (b *TelegramSOARBot) pollUpdates(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(1500 * time.Millisecond)
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
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				MessageID int64 `json:"message_id"`
				Chat      struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				Text string `json:"text"`
			} `json:"message"`
			CallbackQuery *struct {
				ID      string `json:"id"`
				Data    string `json:"data"`
				Message struct {
					MessageID int64 `json:"message_id"`
					Chat      struct {
						ID int64 `json:"id"`
					} `json:"chat"`
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

		// 1. Process Callback Buttons
		if update.CallbackQuery != nil {
			chatID := strconv.FormatInt(update.CallbackQuery.Message.Chat.ID, 10)
			if chatID != b.cfg.ChatID {
				log.Printf("[SECURITY_WARN] Unauthorized callback attempt from chat ID %s", chatID)
				b.sendTelegramRequest("answerCallbackQuery", map[string]interface{}{
					"callback_query_id": update.CallbackQuery.ID,
					"text":              "⚠️ Yetkisiz erişim denemesi engellendi.",
					"show_alert":        true,
				})
				continue
			}

			b.handleCallback(update.CallbackQuery.ID, update.CallbackQuery.Data)
		}

		// 2. Process Operator Chat Commands
		if update.Message != nil && update.Message.Text != "" {
			chatID := strconv.FormatInt(update.Message.Chat.ID, 10)
			if chatID != b.cfg.ChatID {
				log.Printf("[SECURITY_WARN] Unauthorized message attempt from chat ID %s", chatID)
				b.sendTelegramRequest("sendMessage", map[string]interface{}{
					"chat_id": chatID,
					"text":    "⚠️ Yetkisiz erişim denemesi engellendi. Bu bot yalnızca yetkili CoPSeC SOC operatörlerine açıktır.",
				})
				continue
			}

			b.handleCommand(strings.TrimSpace(update.Message.Text))
		}
	}
}

func (b *TelegramSOARBot) handleCallback(queryID, data string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return
	}

	action, ip := parts[0], strings.TrimSpace(parts[1])
	if ip == "" || net.ParseIP(ip) == nil {
		b.sendTelegramRequest("answerCallbackQuery", map[string]interface{}{
			"callback_query_id": queryID,
			"text":              "⚠️ Geçersiz IP adresi.",
			"show_alert":        true,
		})
		return
	}

	var notification string
	var chatReply string

	switch action {
	case "ban":
		dispatched := b.server.BroadcastSOARCommand("BAN_IP", ip, 86400)
		notification = fmt.Sprintf("🚫 IP %s engellendi (%d düğüm)", ip, dispatched)
		chatReply = fmt.Sprintf("🚫 *[SOAR FLEET BAN]* `%s` adresi %d bağlı düğümde iptables DROP ile karantinaya alındı.", ip, dispatched)

	case "unban":
		dispatched := b.server.BroadcastSOARCommand("UNBAN_IP", ip, 0)
		notification = fmt.Sprintf("🔓 IP %s engeli kaldırıldı (%d düğüm)", ip, dispatched)
		chatReply = fmt.Sprintf("🔓 *[SOAR UNBAN]* `%s` adresi üzerindeki engel kuralı kaldırıldı (%d düğüm).", ip, dispatched)

	case "whitelist", "white":
		dispatched := b.server.BroadcastSOARCommand("WHITELIST_IP", ip, 0)
		notification = fmt.Sprintf("🛡 IP %s beyaz listeye alındı (%d düğüm)", ip, dispatched)
		chatReply = fmt.Sprintf("🛡 *[SOAR WHITELIST]* `%s` beyaz listeye eklendi, korumaya alındı ve mevcut engeli kaldırıldı (%d düğüm).", ip, dispatched)
	}

	// 1. Toast Alert Popup
	b.sendTelegramRequest("answerCallbackQuery", map[string]interface{}{
		"callback_query_id": queryID,
		"text":              notification,
		"show_alert":        false,
	})

	// 2. Chat Log Confirmation
	if chatReply != "" {
		b.sendTelegramRequest("sendMessage", map[string]interface{}{
			"chat_id":    b.cfg.ChatID,
			"text":       chatReply,
			"parse_mode": "Markdown",
		})
	}
}

func (b *TelegramSOARBot) handleCommand(text string) {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "/ban":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			b.replyMessage("⚠️ *Geçersiz IP formatı.*\nKullanım: `/ban 185.220.101.5`")
			return
		}
		targetIP := parts[1]
		dispatched := b.server.BroadcastSOARCommand("BAN_IP", targetIP, 86400)
		b.replyMessage(fmt.Sprintf("🚫 *[SOAR MANUAL BAN]* `%s` adresi %d bağlı düğümde başarıyla engellendi.", targetIP, dispatched))

	case "/unban":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			b.replyMessage("⚠️ *Geçersiz IP formatı.*\nKullanım: `/unban 185.220.101.5`")
			return
		}
		targetIP := parts[1]
		dispatched := b.server.BroadcastSOARCommand("UNBAN_IP", targetIP, 0)
		b.replyMessage(fmt.Sprintf("🔓 *[SOAR MANUAL UNBAN]* `%s` adresinin engeli %d düğümde kaldırıldı.", targetIP, dispatched))

	case "/whitelist", "/wl":
		if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
			b.replyMessage("⚠️ *Geçersiz IP formatı.*\nKullanım: `/whitelist 176.88.125.20`")
			return
		}
		targetIP := parts[1]
		dispatched := b.server.BroadcastSOARCommand("WHITELIST_IP", targetIP, 0)
		b.replyMessage(fmt.Sprintf("🛡 *[SOAR WHITELIST]* `%s` beyaz listeye eklendi, korumaya alındı ve varsa mevcut engeli kaldırıldı (%d düğüm).", targetIP, dispatched))

	case "/status":
		nodes := b.server.GetNodesSnapshot()
		eps := b.server.GetEPS()
		total := b.server.GetTotalEvents()

		nodeListStr := "Bağlı aktif düğüm yok."
		if len(nodes) > 0 {
			var sb strings.Builder
			for _, n := range nodes {
				status := "🟢"
				if time.Since(n.LastSeen) > 20*time.Second {
					status = "🔴"
				}
				sb.WriteString(fmt.Sprintf("  %s `%s` (CPU: %0.1f%%, RAM: %0.1fMB, Bans: %d)\n",
					status, n.NodeID, n.CPUUsage, n.MemoryUsage, n.ActiveBansCount))
			}
			nodeListStr = sb.String()
		}

		jailCount := 0
		jailStr := "Cezaevinde (Jail) aktif IP yok."
		if b.server.storage != nil {
			if bans, err := b.server.storage.GetActiveBans(); err == nil && len(bans) > 0 {
				jailCount = len(bans)
				var sb strings.Builder
				for _, ban := range bans {
					sb.WriteString(fmt.Sprintf("  🚫 `%s` (%s)\n", ban.IP, ban.Reason))
				}
				jailStr = sb.String()
			}
		}

		statusReport := fmt.Sprintf("📊 *CoPSeC Enterprise SOC Durum Raporu*\n\n"+
			"🌐 *Aktif Düğümler (%d):*\n%s\n"+
			"🛡 *Aktif Cezaevi / Jail (%d IP):*\n%s\n"+
			"⚡ *Canlı Akış Hızı:* `%d EPS`\n"+
			"📦 *Toplam İşlenen Log:* `%d`",
			len(nodes), nodeListStr, jailCount, jailStr, eps, total)

		b.replyMessage(statusReport)

	case "/help", "/start":
		helpText := "🤖 *CoPSeC SOC & SOAR Uzaktan Komuta Merkezi*\n\n" +
			"Kullanılabilir Komutlar:\n" +
			"• `/ban <IP>` - Belirtilen IP adresini tüm bağlı düğümlerde derhal engeller.\n" +
			"• `/unban <IP>` - Belirtilen IP'nin engelini tüm düğümlerde kaldırır.\n" +
			"• `/whitelist <IP>` (veya `/wl`) - IP'yi beyaz listeye alır, korur ve engelini açar.\n" +
			"• `/status` - Canlı düğüm listesi, aktif banlar ve EPS durum raporunu döndürür.\n" +
			"• `/help` - Bu yardım menüsünü görüntüler.\n\n" +
			"_Not: Yalnızca yetkili Chat ID üzerinden verilen komutlar işleme alınır._"
		b.replyMessage(helpText)

	default:
		b.replyMessage("❓ *Bilinmeyen komut.* Kullanılabilir komutları görmek için `/help` yazabilirsiniz.")
	}
}

func (b *TelegramSOARBot) replyMessage(text string) {
	payload := map[string]interface{}{
		"chat_id":    b.cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	go b.sendTelegramRequest("sendMessage", payload)
}

func truncateString(str string, length int) string {
	if length <= 0 {
		return ""
	}
	if len(str) <= length {
		return str
	}
	if length <= 3 {
		return str[:length]
	}
	return str[:length-3] + "..."
}
