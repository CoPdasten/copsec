package export

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TargetType designates the network transport protocol used for SIEM exportation.
type TargetType string

const (
	TargetTypeRawTCP    TargetType = "RAW_TCP"
	TargetTypeTLSSyslog TargetType = "TLS_SYSLOG"
)

// TelemetryEvent captures the normalized security metadata of an edge/kernel packet drop.
type TelemetryEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	SourcePort uint16    `json:"source_port"`
	Protocol   string    `json:"protocol"`
	Reason     string    `json:"reason"`
	Severity   string    `json:"severity"`
	CVE        string    `json:"cve,omitempty"`
	LatencyNs  int64     `json:"latency_ns"`
	NodeID     string    `json:"node_id"`
	Host       string    `json:"host,omitempty"`
	AppName    string    `json:"app_name,omitempty"`
}

// EscapeCEFHeader escapes reserved delimiter characters ('|' and '\') in CEF header fields.
func EscapeCEFHeader(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `|`, `\|`)
	return val
}

// EscapeCEFExtension escapes reserved characters ('=' and '\') in CEF extension values.
func EscapeCEFExtension(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `=`, `\=`)
	return val
}

// FormatCEF formats telemetry into ArcSight Common Event Format (CEF) strictly matching:
// CEF:0|CoPSeC|KernelXDP|1.4|DROP|<Reason>|<Severity>|src=<IP> cs1Label=CVE cs1=<CVE> cn1Label=LatencyNs cn1=<Latency>
func FormatCEF(ev *TelemetryEvent) string {
	reason := EscapeCEFHeader(ev.Reason)
	if reason == "" {
		reason = "SecurityDrop"
	}
	sev := EscapeCEFHeader(ev.Severity)
	if sev == "" {
		sev = "HIGH"
	}

	cve := EscapeCEFExtension(ev.CVE)
	if cve == "" {
		cve = "NONE"
	}

	srcIP := ev.SourceIP
	if srcIP == "" {
		srcIP = "0.0.0.0"
	}

	return fmt.Sprintf("CEF:0|CoPSeC|KernelXDP|1.4|DROP|%s|%s|src=%s cs1Label=CVE cs1=%s cn1Label=LatencyNs cn1=%d",
		reason, sev, srcIP, cve, ev.LatencyNs)
}

// FormatRFC5424 encapsulates a CEF record inside an RFC 5424 Syslog frame:
// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG\n
func FormatRFC5424(ev *TelemetryEvent, facility int, severity int) string {
	pri := (facility * 8) + severity

	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	tsStr := ts.UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	host := ev.Host
	if host == "" {
		host = ev.NodeID
	}
	if host == "" {
		host = "copsec-edge"
	}

	app := ev.AppName
	if app == "" {
		app = "copsec-xdp"
	}

	cefMsg := FormatCEF(ev)

	return fmt.Sprintf("<%d>1 %s %s %s - DROP - %s\n", pri, tsStr, host, app, cefMsg)
}

// RingChannelBuffer implements a high-throughput circular ring buffer over a channel.
// Under burst congestion, oldest events are discarded to guarantee that callers never block.
type RingChannelBuffer struct {
	queue   chan *TelemetryEvent
	size    int
	dropped atomic.Uint64
	pushed  atomic.Uint64
}

// NewRingChannelBuffer initializes a ring-channel buffer with the specified capacity.
func NewRingChannelBuffer(size int) *RingChannelBuffer {
	if size <= 0 {
		size = 65536
	}
	return &RingChannelBuffer{
		queue: make(chan *TelemetryEvent, size),
		size:  size,
	}
}

// Push non-blockingly inserts an event into the ring buffer, displacing the oldest event if full.
func (r *RingChannelBuffer) Push(ev *TelemetryEvent) bool {
	select {
	case r.queue <- ev:
		r.pushed.Add(1)
		return true
	default:
		// Capacity reached: displace oldest item to preserve real-time telemetry
		select {
		case <-r.queue:
			r.dropped.Add(1)
		default:
		}
		select {
		case r.queue <- ev:
			r.pushed.Add(1)
			return true
		default:
			r.dropped.Add(1)
			return false
		}
	}
}

// Pop reads the next event from the queue or blocks until available/closed.
func (r *RingChannelBuffer) Pop(ctx context.Context) (*TelemetryEvent, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	case ev, ok := <-r.queue:
		return ev, ok
	}
}

// Length returns the current number of queued events in the buffer.
func (r *RingChannelBuffer) Length() int {
	return len(r.queue)
}

// Dropped returns the total number of evicted events due to ring overflows.
func (r *RingChannelBuffer) Dropped() uint64 {
	return r.dropped.Load()
}

// Pushed returns the total count of successfully enqueued events.
func (r *RingChannelBuffer) Pushed() uint64 {
	return r.pushed.Load()
}

// SIEMConfig defines connection parameters and mTLS cryptographic settings for upstream SIEM exporters.
type SIEMConfig struct {
	TargetType       TargetType
	Endpoint         string // "host:port" (e.g. "siem.enterprise.local:6514" or "wazuh:514")
	QueueSize        int
	Workers          int
	BatchSize        int
	FlushInterval    time.Duration
	Format           string // "CEF" or "RFC5424"
	Facility         int    // Default: 16 (local0)
	Severity         int    // Default: 6 (info)
	TLSClientCert    string // Path to client certificate (mTLS)
	TLSClientKey     string // Path to client private key (mTLS)
	TLSCACert        string // Path to Root CA certificate
	TLSServerName    string // SNI server name
	InsecureSkipTLS  bool   // Testing only
	ReconnectBackoff time.Duration
}

// ExporterMetrics reports real-time export performance counters.
type ExporterMetrics struct {
	Pushed   uint64
	Dropped  uint64
	Exported uint64
	Errors   uint64
}

// SIEMExporter coordinates the asynchronous worker pool, ring buffer, and upstream TCP/mTLS sockets.
type SIEMExporter struct {
	cfg       SIEMConfig
	buffer    *RingChannelBuffer
	tlsConfig *tls.Config
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   atomic.Bool
	exported  atomic.Uint64
	errors    atomic.Uint64
}

// NewSIEMExporter constructs and initializes a production-grade SIEM telemetry exporter.
func NewSIEMExporter(cfg SIEMConfig) (*SIEMExporter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("upstream SIEM endpoint host:port cannot be empty")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 65536
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 50 * time.Millisecond
	}
	if cfg.Format == "" {
		cfg.Format = "CEF"
	}
	if cfg.Facility == 0 {
		cfg.Facility = 16 // local0
	}
	if cfg.Severity == 0 {
		cfg.Severity = 6 // Informational
	}
	if cfg.ReconnectBackoff <= 0 {
		cfg.ReconnectBackoff = 500 * time.Millisecond
	}

	var tlsConf *tls.Config
	if cfg.TargetType == TargetTypeTLSSyslog {
		var err error
		tlsConf, err = buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build mTLS configuration: %w", err)
		}
	}

	exporter := &SIEMExporter{
		cfg:       cfg,
		buffer:    NewRingChannelBuffer(cfg.QueueSize),
		tlsConfig: tlsConf,
	}

	return exporter, nil
}

func buildTLSConfig(cfg SIEMConfig) (*tls.Config, error) {
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipTLS,
	}

	if cfg.TLSServerName != "" {
		tlsConf.ServerName = cfg.TLSServerName
	} else {
		host, _, err := net.SplitHostPort(cfg.Endpoint)
		if err == nil && net.ParseIP(host) == nil {
			tlsConf.ServerName = host
		}
	}

	// Ingest Root CA certificate if specified
	if cfg.TLSCACert != "" {
		caData, err := os.ReadFile(cfg.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, errors.New("failed to append PEM data to root CA pool")
		}
		tlsConf.RootCAs = pool
	}

	// Ingest Client Certificate & Private Key (Mutual TLS / mTLS)
	if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSClientCert, cfg.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client mTLS keypair: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	return tlsConf, nil
}

// Start spawns the asynchronous worker pool goroutines.
func (e *SIEMExporter) Start(ctx context.Context) {
	if e.running.Swap(true) {
		return
	}

	workerCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	for i := 0; i < e.cfg.Workers; i++ {
		e.wg.Add(1)
		go e.worker(workerCtx, i)
	}

	log.Printf("[SIEM_EXPORTER] ⚡ Started asynchronous SIEM worker pool (%d workers, queue: %d) -> Target: %s [%s]",
		e.cfg.Workers, e.cfg.QueueSize, e.cfg.Endpoint, e.cfg.TargetType)
}

// Enqueue submits a telemetry event into the ring buffer without ever blocking the gRPC engine.
func (e *SIEMExporter) Enqueue(ev *TelemetryEvent) bool {
	if ev == nil {
		return false
	}
	return e.buffer.Push(ev)
}

// worker drains the ring-channel buffer and flushes formatted payloads to upstream sockets.
func (e *SIEMExporter) worker(ctx context.Context, workerID int) {
	defer e.wg.Done()

	var conn net.Conn
	var err error

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	connect := func() net.Conn {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		if e.cfg.TargetType == TargetTypeTLSSyslog {
			c, dErr := tls.DialWithDialer(dialer, "tcp", e.cfg.Endpoint, e.tlsConfig)
			if dErr != nil {
				e.errors.Add(1)
				return nil
			}
			return c
		}

		c, dErr := dialer.DialContext(ctx, "tcp", e.cfg.Endpoint)
		if dErr != nil {
			e.errors.Add(1)
			return nil
		}
		return c
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ev, ok := e.buffer.Pop(ctx)
		if !ok {
			return
		}

		// Ensure active connection
		if conn == nil {
			conn = connect()
			if conn == nil {
				// Failed to connect, back off before retry
				select {
				case <-ctx.Done():
					return
				case <-time.After(e.cfg.ReconnectBackoff):
					continue
				}
			}
		}

		var payload string
		if strings.EqualFold(e.cfg.Format, "RFC5424") {
			payload = FormatRFC5424(ev, e.cfg.Facility, e.cfg.Severity)
		} else {
			payload = FormatCEF(ev) + "\n"
		}

		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(conn, payload)
		if err != nil {
			e.errors.Add(1)
			_ = conn.Close()
			conn = nil
			continue
		}

		e.exported.Add(1)
	}
}

// Metrics returns the operational counters of the exporter.
func (e *SIEMExporter) Metrics() ExporterMetrics {
	return ExporterMetrics{
		Pushed:   e.buffer.Pushed(),
		Dropped:  e.buffer.Dropped(),
		Exported: e.exported.Load(),
		Errors:   e.errors.Load(),
	}
}

// Close gracefully signals workers to stop and awaits termination.
func (e *SIEMExporter) Close() error {
	if !e.running.Swap(false) {
		return nil
	}
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	log.Printf("[SIEM_EXPORTER] Shutdown complete. Final stats: pushed=%d, exported=%d, dropped=%d, errors=%d",
		e.buffer.Pushed(), e.exported.Load(), e.buffer.Dropped(), e.errors.Load())
	return nil
}
