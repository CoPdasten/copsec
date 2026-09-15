package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// TransportType defines the network protocol used to communicate with the SIEM.
type TransportType string

const (
	TransportUDP TransportType = "UDP"
	TransportTCP TransportType = "TCP"
	TransportTLS TransportType = "TLS"
)

// FormatType defines the payload formatting for Syslog export.
type FormatType string

const (
	FormatCEF  FormatType = "CEF"
	FormatJSON FormatType = "JSON"
)

// AlertEvent encapsulates the security telemetry to be exported to upstream SIEMs.
type AlertEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	NodeID      string    `json:"node_id"`
	Source      string    `json:"source"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  uint16    `json:"source_port"`
	DestIP      string    `json:"dest_ip"`
	DestPort    uint16    `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	MitreID     string    `json:"mitre_id"`
	ThreatScore int       `json:"threat_score"`
	Severity    string    `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Action      string    `json:"action"`   // "DROP", "TARPIT", "BAN", "PASS"
	Message     string    `json:"message"`
	TargetPID   int32     `json:"target_pid,omitempty"`
	TargetComm  string    `json:"target_comm,omitempty"`
}

// SyslogConfig holds connection and formatting settings for the SIEM forwarder.
type SyslogConfig struct {
	Enabled          bool          `json:"enabled"`
	Transport        TransportType `json:"transport"` // UDP, TCP, TLS
	Endpoint         string        `json:"endpoint"`  // "host:port" (e.g. "siem.local:514")
	Format           FormatType    `json:"format"`     // CEF, JSON
	Facility         int           `json:"facility"`   // Default: 16 (local0)
	Severity         int           `json:"severity"`   // Default: 6 (info)
	Hostname         string        `json:"hostname"`
	AppName          string        `json:"app_name"`
	QueueSize        int           `json:"queue_size"`
	Workers          int           `json:"workers"`
	ReconnectBackoff time.Duration `json:"reconnect_backoff"`
	TLSInsecure      bool          `json:"tls_insecure"`
	TLSCACert        string        `json:"tls_ca_cert"`
	TLSClientCert    string        `json:"tls_client_cert"`
	TLSClientKey     string        `json:"tls_client_key"`
	TLSServerName    string        `json:"tls_server_name"`
}

// EscapeCEFHeader escapes delimiters ('|' and '\') in CEF headers.
func EscapeCEFHeader(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `|`, `\|`)
	return val
}

// EscapeCEFExtension escapes delimiters ('=' and '\') in CEF extension values.
func EscapeCEFExtension(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `=`, `\=`)
	val = strings.ReplaceAll(val, "\n", `\n`)
	val = strings.ReplaceAll(val, "\r", `\r`)
	return val
}

// FormatArcSightCEF formats an alert event strictly matching ArcSight CEF 0.1:
// CEF:0|CoPSeC|ActiveDefense|1.8.0|DROP|<Name>|<Severity>|src=fd00::12 dst=fd00::8 spt=49152 dpt=2223 cs1Label=MITRE cs1=T1027 ...
func FormatArcSightCEF(ev *AlertEvent) string {
	action := ev.Action
	if action == "" {
		action = "DROP"
	}
	name := ev.RuleName
	if name == "" {
		name = ev.RuleID
	}
	if name == "" {
		name = "SecurityAlert"
	}

	sevVal := "7"
	switch strings.ToUpper(ev.Severity) {
	case "CRITICAL":
		sevVal = "10"
	case "HIGH":
		sevVal = "8"
	case "MEDIUM":
		sevVal = "5"
	case "LOW":
		sevVal = "3"
	default:
		if ev.ThreatScore >= 90 {
			sevVal = "10"
		} else if ev.ThreatScore >= 70 {
			sevVal = "8"
		} else if ev.ThreatScore >= 40 {
			sevVal = "5"
		} else {
			sevVal = "2"
		}
	}

	srcIP := ev.SourceIP
	if srcIP == "" {
		srcIP = "0.0.0.0"
	}
	dstIP := ev.DestIP
	if dstIP == "" {
		dstIP = "0.0.0.0"
	}

	mitre := ev.MitreID
	if mitre == "" {
		mitre = "NONE"
	}

	proto := ev.Protocol
	if proto == "" {
		proto = "TCP"
	}

	header := fmt.Sprintf("CEF:0|CoPSeC|ActiveDefense|1.8.0|%s|%s|%s|",
		EscapeCEFHeader(action),
		EscapeCEFHeader(name),
		EscapeCEFHeader(sevVal),
	)

	ext := fmt.Sprintf("src=%s dst=%s spt=%d dpt=%d proto=%s cs1Label=MITRE cs1=%s cs2Label=RuleID cs2=%s cn1Label=ThreatScore cn1=%d act=%s msg=%s",
		EscapeCEFExtension(srcIP),
		EscapeCEFExtension(dstIP),
		ev.SourcePort,
		ev.DestPort,
		EscapeCEFExtension(proto),
		EscapeCEFExtension(mitre),
		EscapeCEFExtension(ev.RuleID),
		ev.ThreatScore,
		EscapeCEFExtension(action),
		EscapeCEFExtension(ev.Message),
	)

	if ev.TargetPID > 0 || ev.TargetComm != "" {
		ext += fmt.Sprintf(" dproc=%s dpid=%d", EscapeCEFExtension(ev.TargetComm), ev.TargetPID)
	}

	return header + ext
}

// FormatRFC5424JSON encapsulates structured JSON within standard RFC 5424 Syslog:
// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [structured-data] JSON-PAYLOAD
func FormatRFC5424JSON(ev *AlertEvent, hostname, appName string, facility, severity int) string {
	pri := (facility * 8) + severity
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	tsStr := ts.UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	if hostname == "" {
		hostname = ev.NodeID
	}
	if hostname == "" {
		hostname = "copsec-hub"
	}
	if appName == "" {
		appName = "copsec-activedefense"
	}

	jsonBytes, err := json.Marshal(ev)
	if err != nil {
		jsonBytes = []byte("{}")
	}

	return fmt.Sprintf("<%d>1 %s %s %s - ALERT [copsec@48544 rule_id=\"%s\" mitre=\"%s\" score=\"%d\"] %s\n",
		pri, tsStr, hostname, appName, ev.RuleID, ev.MitreID, ev.ThreatScore, string(jsonBytes))
}

// SyslogForwarder manages non-blocking event queuing and transmission over UDP/TCP/TLS.
type SyslogForwarder struct {
	mu        sync.RWMutex
	cfg       SyslogConfig
	queue     chan *AlertEvent
	tlsConf   *tls.Config
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   atomic.Bool
	pushed    atomic.Uint64
	exported  atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64
}

// NewSyslogForwarder creates and initializes a production SyslogForwarder.
func NewSyslogForwarder(cfg SyslogConfig) (*SyslogForwarder, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("SIEM endpoint host:port cannot be empty")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 65536
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.ReconnectBackoff <= 0 {
		cfg.ReconnectBackoff = 500 * time.Millisecond
	}
	if cfg.Facility == 0 {
		cfg.Facility = 16 // local0
	}
	if cfg.Severity == 0 {
		cfg.Severity = 6 // Informational
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportUDP
	}
	if cfg.Format == "" {
		cfg.Format = FormatCEF
	}

	var tlsConf *tls.Config
	if cfg.Transport == TransportTLS {
		var err error
		tlsConf, err = buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS configuration: %w", err)
		}
	}

	return &SyslogForwarder{
		cfg:     cfg,
		queue:   make(chan *AlertEvent, cfg.QueueSize),
		tlsConf: tlsConf,
	}, nil
}

func buildTLSConfig(cfg SyslogConfig) (*tls.Config, error) {
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.TLSInsecure,
	}

	if cfg.TLSServerName != "" {
		tlsConf.ServerName = cfg.TLSServerName
	} else {
		host, _, err := net.SplitHostPort(cfg.Endpoint)
		if err == nil && net.ParseIP(host) == nil {
			tlsConf.ServerName = host
		}
	}

	if cfg.TLSCACert != "" {
		caData, err := os.ReadFile(cfg.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, errors.New("failed to parse root CA cert PEM")
		}
		tlsConf.RootCAs = pool
	}

	if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSClientCert, cfg.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client mTLS cert/key: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	return tlsConf, nil
}

// Start launches the background worker pool.
func (f *SyslogForwarder) Start(ctx context.Context) {
	if f.running.Swap(true) {
		return
	}

	workerCtx, cancel := context.WithCancel(ctx)
	f.cancel = cancel

	for i := 0; i < f.cfg.Workers; i++ {
		f.wg.Add(1)
		go f.worker(workerCtx, i)
	}

	log.Printf("[SIEM_FORWARDER] [FASTPATH] Started Syslog forwarder (%s, format: %s, endpoint: %s, workers: %d)",
		f.cfg.Transport, f.cfg.Format, f.cfg.Endpoint, f.cfg.Workers)
}

// Push submits an alert into the ring queue. Displaces oldest entry non-blockingly if full.
func (f *SyslogForwarder) Push(ev *AlertEvent) bool {
	if ev == nil {
		return false
	}
	f.pushed.Add(1)

	select {
	case f.queue <- ev:
		return true
	default:
		// Queue full: evict oldest item to maintain real-time telemetry
		select {
		case <-f.queue:
			f.dropped.Add(1)
		default:
		}
		select {
		case f.queue <- ev:
			return true
		default:
			f.dropped.Add(1)
			return false
		}
	}
}

func (f *SyslogForwarder) worker(ctx context.Context, workerID int) {
	defer f.wg.Done()

	var conn net.Conn

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	connect := func() net.Conn {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		switch f.cfg.Transport {
		case TransportTLS:
			c, err := tls.DialWithDialer(dialer, "tcp", f.cfg.Endpoint, f.tlsConf)
			if err != nil {
				f.errors.Add(1)
				return nil
			}
			return c
		case TransportTCP:
			c, err := dialer.DialContext(ctx, "tcp", f.cfg.Endpoint)
			if err != nil {
				f.errors.Add(1)
				return nil
			}
			return c
		default: // UDP
			c, err := dialer.DialContext(ctx, "udp", f.cfg.Endpoint)
			if err != nil {
				f.errors.Add(1)
				return nil
			}
			return c
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-f.queue:
			if !ok {
				return
			}

			if conn == nil {
				conn = connect()
				if conn == nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(f.cfg.ReconnectBackoff):
						continue
					}
				}
			}

			var payload string
			if f.cfg.Format == FormatJSON {
				payload = FormatRFC5424JSON(ev, f.cfg.Hostname, f.cfg.AppName, f.cfg.Facility, f.cfg.Severity)
			} else {
				payload = FormatArcSightCEF(ev) + "\n"
			}

			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err := io.WriteString(conn, payload)
			if err != nil {
				f.errors.Add(1)
				_ = conn.Close()
				conn = nil
				continue
			}

			f.exported.Add(1)
		}
	}
}

// Metrics returns operational telemetry counters.
func (f *SyslogForwarder) Metrics() map[string]uint64 {
	return map[string]uint64{
		"pushed":   f.pushed.Load(),
		"exported": f.exported.Load(),
		"dropped":  f.dropped.Load(),
		"errors":   f.errors.Load(),
	}
}

// Close signals workers to terminate and waits for queue drainage.
func (f *SyslogForwarder) Close() error {
	if !f.running.Swap(false) {
		return nil
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.wg.Wait()
	return nil
}
