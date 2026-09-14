package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WebhookType identifies target webhook service provider.
type WebhookType string

const (
	TypeGeneric WebhookType = "GENERIC"
	TypeSlack   WebhookType = "SLACK"
	TypeDiscord WebhookType = "DISCORD"
)

// WebhookAlert models an alert card payload dispatched to incident response channels.
type WebhookAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	NodeID      string    `json:"node_id"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  uint16    `json:"source_port,omitempty"`
	DestIP      string    `json:"dest_ip,omitempty"`
	DestPort    uint16    `json:"dest_port,omitempty"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	MitreID     string    `json:"mitre_id"`
	ThreatScore int       `json:"threat_score"`
	Severity    string    `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Action      string    `json:"action"`   // "DROP", "TARPIT", "BAN", "EDR_KILL"
	Details     string    `json:"details"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	TargetPID   int32     `json:"target_pid,omitempty"`
	TargetComm  string    `json:"target_comm,omitempty"`
}

// WebhookConfig defines webhook destination parameters.
type WebhookConfig struct {
	Enabled       bool          `json:"enabled"`
	URL           string        `json:"url"`
	Type          WebhookType   `json:"type"` // GENERIC, SLACK, DISCORD
	QueueSize     int           `json:"queue_size"`
	Workers       int           `json:"workers"`
	MinSeverity   string        `json:"min_severity"` // "CRITICAL", "HIGH" (defaults to HIGH)
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// Notifier handles asynchronous non-blocking webhook dispatching.
type Notifier struct {
	mu         sync.RWMutex
	cfg        WebhookConfig
	queue      chan *WebhookAlert
	client     *http.Client
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	running    atomic.Bool
	dispatched atomic.Uint64
	dropped    atomic.Uint64
	errors     atomic.Uint64
}

// NewNotifier creates an asynchronous Webhook Notifier instance.
func NewNotifier(cfg WebhookConfig) (*Notifier, error) {
	if cfg.URL == "" {
		return nil, errors.New("webhook destination URL cannot be empty")
	}
	if cfg.Type == "" {
		// Auto-detect type from URL
		if strings.Contains(cfg.URL, "hooks.slack.com") {
			cfg.Type = TypeSlack
		} else if strings.Contains(cfg.URL, "discord.com/api/webhooks") || strings.Contains(cfg.URL, "discordapp.com/api/webhooks") {
			cfg.Type = TypeDiscord
		} else {
			cfg.Type = TypeGeneric
		}
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "HIGH"
	}

	return &Notifier{
		cfg:   cfg,
		queue: make(chan *WebhookAlert, cfg.QueueSize),
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

// IsActionable checks if the alert meets the minimum severity threshold for dispatch.
func (n *Notifier) IsActionable(alert *WebhookAlert) bool {
	if alert == nil {
		return false
	}
	sev := strings.ToUpper(strings.TrimSpace(alert.Severity))
	minSev := strings.ToUpper(strings.TrimSpace(n.cfg.MinSeverity))

	if minSev == "CRITICAL" {
		return sev == "CRITICAL" || alert.ThreatScore >= 90
	}
	// Default: "HIGH" or "CRITICAL"
	return sev == "CRITICAL" || sev == "HIGH" || alert.ThreatScore >= 70
}

// Dispatch queues an alert non-blockingly for transmission if severity qualifies.
func (n *Notifier) Dispatch(alert *WebhookAlert) bool {
	if !n.IsActionable(alert) {
		return false
	}

	select {
	case n.queue <- alert:
		return true
	default:
		// Queue full: evict oldest item to maintain real-time alerts
		select {
		case <-n.queue:
			n.dropped.Add(1)
		default:
		}
		select {
		case n.queue <- alert:
			return true
		default:
			n.dropped.Add(1)
			return false
		}
	}
}

// Start spawns background dispatch worker routines.
func (n *Notifier) Start(ctx context.Context) {
	if n.running.Swap(true) {
		return
	}

	workerCtx, cancel := context.WithCancel(ctx)
	n.cancel = cancel

	for i := 0; i < n.cfg.Workers; i++ {
		n.wg.Add(1)
		go n.worker(workerCtx, i)
	}

	log.Printf("[WEBHOOK_NOTIFIER] ⚡ Active Defense Webhook Dispatcher started (Target: %s [%s], Workers: %d)",
		n.cfg.URL, n.cfg.Type, n.cfg.Workers)
}

func (n *Notifier) worker(ctx context.Context, id int) {
	defer n.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case alert, ok := <-n.queue:
			if !ok {
				return
			}
			n.sendWithRetry(ctx, alert)
		}
	}
}

func (n *Notifier) sendWithRetry(ctx context.Context, alert *WebhookAlert) {
	payloadBytes, err := n.formatPayload(alert)
	if err != nil {
		n.errors.Add(1)
		return
	}

	for attempt := 1; attempt <= n.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(payloadBytes))
		if err != nil {
			n.errors.Add(1)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "CoPSeC-ActiveDefense/1.8.0")
		for k, v := range n.cfg.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := n.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				n.dispatched.Add(1)
				return
			}
		}

		if attempt < n.cfg.MaxRetries {
			time.Sleep(time.Duration(attempt*200) * time.Millisecond)
		}
	}

	n.errors.Add(1)
}

func (n *Notifier) formatPayload(alert *WebhookAlert) ([]byte, error) {
	switch n.cfg.Type {
	case TypeSlack:
		color := "#e11d48" // red for critical
		if alert.Severity == "HIGH" {
			color = "#f59e0b" // amber
		}
		title := fmt.Sprintf("🚨 [%s] Threat Incident: %s", alert.Severity, alert.RuleName)
		if alert.RuleName == "" {
			title = fmt.Sprintf("🚨 [%s] Threat Incident: %s", alert.Severity, alert.RuleID)
		}

		type field struct {
			Title string `json:"title"`
			Value string `json:"value"`
			Short bool   `json:"short"`
		}
		fields := []field{
			{Title: "Attacker IP", Value: alert.SourceIP, Short: true},
			{Title: "Threat Score", Value: fmt.Sprintf("%d/100", alert.ThreatScore), Short: true},
			{Title: "MITRE ATT&CK", Value: alert.MitreID, Short: true},
			{Title: "Action Taken", Value: alert.Action, Short: true},
			{Title: "Sensor Node", Value: alert.NodeID, Short: true},
			{Title: "Geo / ASN", Value: fmt.Sprintf("%s / %s", alert.Country, alert.ASN), Short: true},
		}
		if alert.TargetComm != "" || alert.TargetPID > 0 {
			fields = append(fields, field{
				Title: "Target Process",
				Value: fmt.Sprintf("%s [PID: %d]", alert.TargetComm, alert.TargetPID),
				Short: true,
			})
		}

		payload := map[string]interface{}{
			"text": title,
			"attachments": []map[string]interface{}{
				{
					"color":  color,
					"title":  title,
					"text":   alert.Details,
					"fields": fields,
					"ts":     alert.Timestamp.Unix(),
				},
			},
		}
		return json.Marshal(payload)

	case TypeDiscord:
		colorCode := 15158332 // Red
		if alert.Severity == "HIGH" {
			colorCode = 16098851 // Orange
		}
		title := fmt.Sprintf("🚨 [%s] CoPSeC Threat Incident: %s", alert.Severity, alert.RuleID)

		type field struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Inline bool   `json:"inline"`
		}
		fields := []field{
			{Name: "Attacker IP", Value: alert.SourceIP, Inline: true},
			{Name: "Threat Score", Value: fmt.Sprintf("%d/100", alert.ThreatScore), Inline: true},
			{Name: "MITRE TTP", Value: alert.MitreID, Inline: true},
			{Name: "Enforced Action", Value: alert.Action, Inline: true},
			{Name: "Sensor Node", Value: alert.NodeID, Inline: true},
			{Name: "Target Process", Value: fmt.Sprintf("%s [PID: %d]", alert.TargetComm, alert.TargetPID), Inline: true},
		}

		payload := map[string]interface{}{
			"content": "⚠️ **CoPSeC Active Defense High-Priority Incident Alert**",
			"embeds": []map[string]interface{}{
				{
					"title":       title,
					"description": alert.Details,
					"color":       colorCode,
					"fields":      fields,
					"timestamp":   alert.Timestamp.UTC().Format(time.RFC3339),
				},
			},
		}
		return json.Marshal(payload)

	default: // Generic JSON
		return json.Marshal(map[string]interface{}{
			"event":      "copsec_security_alert",
			"severity":   alert.Severity,
			"score":      alert.ThreatScore,
			"incident":   alert,
			"emitted_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// Metrics returns operational telemetry.
func (n *Notifier) Metrics() map[string]uint64 {
	return map[string]uint64{
		"dispatched": n.dispatched.Load(),
		"dropped":    n.dropped.Load(),
		"errors":     n.errors.Load(),
	}
}

// Close gracefully terminates worker routines.
func (n *Notifier) Close() error {
	if !n.running.Swap(false) {
		return nil
	}
	if n.cancel != nil {
		n.cancel()
	}
	n.wg.Wait()
	return nil
}
