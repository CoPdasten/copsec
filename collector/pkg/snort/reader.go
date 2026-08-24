package snort

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SnortMLMetadata contains machine learning inference and feature telemetry.
type SnortMLMetadata struct {
	ModelID      string             `json:"model_id"`
	AnomalyScore float64            `json:"ml_anomaly_score"`
	Confidence   float64            `json:"confidence"`
	Features     map[string]float64 `json:"features,omitempty"`
}

// SnortMLEvent represents a structured Snort 3 ML security event.
type SnortMLEvent struct {
	Timestamp string           `json:"timestamp"`
	PktNum    uint64           `json:"pkt_num,omitempty"`
	Proto     string           `json:"proto"`
	SrcAddr   string           `json:"src_addr"`
	SrcPort   int              `json:"src_port"`
	DstAddr   string           `json:"dst_addr"`
	DstPort   int              `json:"dst_port"`
	Msg       string           `json:"msg"`
	Rule      string           `json:"rule"`
	Class     string           `json:"class,omitempty"`
	Priority  int              `json:"priority"`
	Service   string           `json:"service,omitempty"`
	ML        *SnortMLMetadata `json:"ml,omitempty"`
	RawJSON   string           `json:"raw_json,omitempty"`
}

// Summary returns a formatted badge-ready incident summary string.
func (e *SnortMLEvent) Summary() string {
	if e.ML != nil && e.ML.AnomalyScore > 0 {
		return fmt.Sprintf("[SNORT-ML] %s (Score: %.2f)", e.Msg, e.ML.AnomalyScore)
	}
	return fmt.Sprintf("[SNORT] %s", e.Msg)
}

// IsHighConfidenceAnomaly returns true if the alert indicates a high-threat intrusion.
func (e *SnortMLEvent) IsHighConfidenceAnomaly() bool {
	if e.Priority == 1 {
		return true
	}
	if e.ML != nil && (e.ML.Confidence >= 0.80 || e.ML.AnomalyScore >= 0.85) {
		return true
	}
	return false
}

// ParseSnortAlert parses a JSON string or line from Snort 3 alert_json output.
func ParseSnortAlert(line []byte) (*SnortMLEvent, bool) {
	trimmed := strings.TrimSpace(string(line))
	if len(trimmed) == 0 {
		return nil, false
	}

	firstBrace := strings.Index(trimmed, "{")
	lastBrace := strings.LastIndex(trimmed, "}")
	if firstBrace == -1 || lastBrace <= firstBrace {
		return nil, false
	}

	var ev SnortMLEvent
	if err := json.Unmarshal([]byte(trimmed[firstBrace:lastBrace+1]), &ev); err != nil {
		return nil, false
	}

	if ev.SrcAddr == "" && ev.Msg == "" && ev.Rule == "" {
		return nil, false
	}

	ev.RawJSON = trimmed[firstBrace : lastBrace+1]
	return &ev, true
}

// SnortStreamReader manages real-time ingestion from file tailing or Unix Domain Sockets.
type SnortStreamReader struct {
	mu           sync.Mutex
	filePath     string
	sockPath     string
	running      bool
	cancelFunc   context.CancelFunc
	alertHandler func(ev *SnortMLEvent)
}

// NewSnortStreamReader creates a new Snort ingestion reader.
func NewSnortStreamReader(filePath, sockPath string, alertHandler func(ev *SnortMLEvent)) *SnortStreamReader {
	if filePath == "" {
		filePath = "/var/log/snort/alert_json.txt"
	}
	if sockPath == "" {
		sockPath = "/var/run/snort/snort_alert.sock"
	}

	return &SnortStreamReader{
		filePath:     filePath,
		sockPath:     sockPath,
		alertHandler: alertHandler,
	}
}

// Start begins background ingestion from both Unix Socket (if available) and JSON alert log.
func (r *SnortStreamReader) Start(ctx context.Context) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	r.cancelFunc = cancel
	r.running = true
	r.mu.Unlock()

	// 1. Launch Unix Socket Listener (if socket path configured)
	if r.sockPath != "" {
		go r.listenUnixSocket(ctx)
	}

	// 2. Launch Log File Tailer
	if r.filePath != "" {
		go r.tailAlertFile(ctx)
	}
}

// Stop cleanly shuts down background listeners.
func (r *SnortStreamReader) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.running = false
}

func (r *SnortStreamReader) listenUnixSocket(ctx context.Context) {
	// Clean up stale socket file if it exists
	_ = os.Remove(r.sockPath)

	l, err := net.Listen("unix", r.sockPath)
	if err != nil {
		// Non-fatal, Snort socket might require root or snort service not started yet
		return
	}
	defer l.Close()
	defer os.Remove(r.sockPath)

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go r.handleSocketConn(ctx, conn)
	}
}

func (r *SnortStreamReader) handleSocketConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Bytes()
		if ev, ok := ParseSnortAlert(line); ok && r.alertHandler != nil {
			r.alertHandler(ev)
		}
	}
}

func (r *SnortStreamReader) tailAlertFile(ctx context.Context) {
	var offset int64 = 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		file, err := os.Open(r.filePath)
		if err != nil {
			// Wait and retry if file does not exist yet
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		// Check if file was truncated/rotated
		fi, err := file.Stat()
		if err == nil && fi.Size() < offset {
			offset = 0
		}

		_, _ = file.Seek(offset, io.SeekStart)
		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				file.Close()
				return
			default:
			}

			line := scanner.Bytes()
			if ev, ok := ParseSnortAlert(line); ok && r.alertHandler != nil {
				r.alertHandler(ev)
			}
		}

		offset, _ = file.Seek(0, io.SeekCurrent)
		file.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
