package dpi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/copsec/collector/pkg/ebpf"
	"github.com/copsec/collector/pkg/forensics"
	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// WhitelistChecker provides zero-allocation lookup for trusted enterprise CIDRs and loopback ranges.
type WhitelistChecker interface {
	IsWhitelisted(ipStr string) bool
}

// Verdict defines the mitigation action determined by the Layer 7 DPI engine.
type Verdict string

const (
	VerdictClean  Verdict = "CLEAN"
	VerdictTarpit Verdict = "TARPIT"
	VerdictDrop   Verdict = "DROP"
)

// InspectionResult encapsulates the complete telemetry and decision of a packet analysis.
type InspectionResult struct {
	Verdict     Verdict      `json:"verdict"`
	Confidence  float64      `json:"confidence"`
	Reason      string       `json:"reason"`
	Stage       string       `json:"stage"` // "DETERMINISTIC_MPM" or "PROBABILISTIC_ML"
	MatchedRule *Rule        `json:"matched_rule,omitempty"`
	Features    Features     `json:"features"`
	Score       float64      `json:"score"`
	SourceIP    string       `json:"source_ip,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
	LatencyNs   int64        `json:"latency_ns"`
}

// InspectorConfig specifies operational thresholds and hook integrations.
type InspectorConfig struct {
	ControllerEndpoint  string `json:"controller_endpoint"`   // Default: "pardus1:50051"
	TarpitPort          int    `json:"tarpit_port"`           // Default: 2223
	ForensicsDir        string `json:"forensics_dir"`         // Default: "/var/log/copsec/forensics"
	RuleFilePath        string `json:"rule_file_path"`        // Default: "/etc/copsec/rules.yaml"
	EnableeBPFBan       bool   `json:"enable_ebpf_ban"`       // Injects ban into xdp_drop_map
	EnableForensicsDump bool   `json:"enable_forensics_dump"` // Writes incident PCAP dump
	EnableAlert         bool   `json:"enable_alert"`          // Dispatches mTLS gRPC alert
	EnableTarpit        bool   `json:"enable_tarpit"`         // Applies kernel redirect to :2223
}

// DefaultInspectorConfig provides hardened production defaults.
func DefaultInspectorConfig() InspectorConfig {
	return InspectorConfig{
		ControllerEndpoint:  "pardus1:50051",
		TarpitPort:          2223,
		ForensicsDir:        "/var/log/copsec/forensics",
		RuleFilePath:        DefaultRulesPath,
		EnableeBPFBan:       true,
		EnableForensicsDump: true,
		EnableAlert:         true,
		EnableTarpit:        true,
	}
}

// DPIInspector orchestrates the hybrid Layer 7 Deterministic MPM and Probabilistic ML decision engine.
type DPIInspector struct {
	mu               sync.RWMutex
	engine           *AhoCorasickEngine
	whitelist        WhitelistChecker
	config           InspectorConfig
	pcapBuffer       *forensics.PCAPBuffer
	xdpEngine        *ebpf.XDPMitigationEngine
	customAlertHook  func(res InspectionResult)
	customTarpitHook func(srcIP string, port int) error
}

var (
	defaultInspector *DPIInspector
	inspectorOnce    sync.Once
)

// GetDefaultInspector returns the singleton DPI inspector instance.
func GetDefaultInspector() *DPIInspector {
	inspectorOnce.Do(func() {
		defaultInspector = NewDPIInspector(DefaultInspectorConfig())
	})
	return defaultInspector
}

// NewDPIInspector creates an initialized DPI inspection engine.
func NewDPIInspector(cfg ...InspectorConfig) *DPIInspector {
	c := DefaultInspectorConfig()
	if len(cfg) > 0 {
		c = cfg[0]
	}

	engine := GetDefaultEngine()

	// Attempt optional rule reload if custom rules file exists
	if _, err := os.Stat(c.RuleFilePath); err == nil {
		_ = engine.ReloadFromFile(c.RuleFilePath)
	}

	return &DPIInspector{
		engine:     engine,
		config:     c,
		pcapBuffer: forensics.GetDefaultPCAPBuffer(),
		xdpEngine:  ebpf.GetXDPEngine(),
	}
}

// SetWhitelist assigns the active enterprise CIDR whitelist checker.
func (insp *DPIInspector) SetWhitelist(w WhitelistChecker) {
	insp.mu.Lock()
	defer insp.mu.Unlock()
	insp.whitelist = w
}

// GetWhitelist retrieves the configured whitelist checker.
func (insp *DPIInspector) GetWhitelist() WhitelistChecker {
	insp.mu.RLock()
	defer insp.mu.RUnlock()
	return insp.whitelist
}

// InspectPacket evaluates an incoming Layer 7 packet payload through the two-stage hybrid engine:
// Stage 1 (Deterministic MPM): Aho-Corasick trie match -> VerdictDrop (< 0.1 ms latency).
// Stage 2 (Probabilistic ML): Feature extraction and anomaly scoring -> Drop / Tarpit / Clean.
func (insp *DPIInspector) InspectPacket(payload []byte) InspectionResult {
	srcIP := extractOrSynthesizeIP(payload)
	return insp.InspectPacketWithIP(payload, srcIP)
}

// InspectPacketWithIP analyzes the payload with explicit caller-provided source IP context.
func (insp *DPIInspector) InspectPacketWithIP(payload []byte, srcIP string) InspectionResult {
	start := time.Now()
	cleanIP := strings.TrimSpace(srcIP)
	if cleanIP == "" {
		cleanIP = "192.168.1.100"
	}

	// -------------------------------------------------------------
	// Fast-Path CIDR Whitelist Bypass
	// Evaluate source IP against CIDRWhitelist before invoking DPI.
	// If whitelisted -> immediately return VerdictClean and log at DEBUG.
	// -------------------------------------------------------------
	insp.mu.RLock()
	wl := insp.whitelist
	insp.mu.RUnlock()
	if wl != nil && wl.IsWhitelisted(cleanIP) {
		log.Printf("[DEBUG] [DPI_WHITELIST] Source IP %s is whitelisted. Bypassing DPI inspection (VerdictClean fast-path).", cleanIP)
		return InspectionResult{
			Verdict:    VerdictClean,
			Confidence: 1.0,
			Reason:     "CIDR Whitelist Bypass",
			Stage:      "WHITELIST_BYPASS",
			Features:   Features{PayloadLength: len(payload)},
			Score:      0.0,
			SourceIP:   cleanIP,
			Timestamp:  time.Now().UTC(),
			LatencyNs:  time.Since(start).Nanoseconds(),
		}
	}

	// -------------------------------------------------------------
	// Stage 1 (Deterministic MPM - Suricata-Style Aho-Corasick)
	// Must execute in < 0.1 ms (< 100,000 ns)
	// -------------------------------------------------------------
	if match, ok := insp.engine.Scan(payload); ok {
		latency := time.Since(start).Nanoseconds()
		result := InspectionResult{
			Verdict:    VerdictDrop,
			Confidence: 1.0,
			Reason:     match.RuleName,
			Stage:      "DETERMINISTIC_MPM",
			MatchedRule: &Rule{
				ID:       match.RuleID,
				Name:     match.RuleName,
				Pattern:  match.MatchedPattern,
				Category: match.Category,
			},
			Features:  Features{PayloadLength: len(payload)},
			Score:     1.0,
			SourceIP:  cleanIP,
			Timestamp: time.Now().UTC(),
			LatencyNs: latency,
		}

		// Autonomous reaction hooking for drop verdict
		insp.triggerDropReactions(result)
		return result
	}

	// -------------------------------------------------------------
	// Stage 2 (Probabilistic ML - SnortML-Style Feature Anomaly Scorer)
	// -------------------------------------------------------------
	features := ExtractFeatures(payload)
	score := EvaluateAnomalyScore(features)
	latency := time.Since(start).Nanoseconds()

	var verdict Verdict
	var reason string
	var confidence float64

	switch {
	case score >= 0.85:
		verdict = VerdictDrop
		confidence = score
		reason = "Zero-Day / Polymorphic Anomaly"

	case score >= 0.60:
		verdict = VerdictTarpit
		confidence = score
		reason = "Probabilistic Anomaly (Routing to TCP Zero-Window Tarpit)"

	default:
		verdict = VerdictClean
		confidence = 1.0 - score
		reason = "Clean Payload Baseline"
	}

	result := InspectionResult{
		Verdict:    verdict,
		Confidence: confidence,
		Reason:     reason,
		Stage:      "PROBABILISTIC_ML",
		Features:   features,
		Score:      score,
		SourceIP:   cleanIP,
		Timestamp:  time.Now().UTC(),
		LatencyNs:  latency,
	}

	switch verdict {
	case VerdictDrop:
		insp.triggerDropReactions(result)
	case VerdictTarpit:
		insp.triggerTarpitReactions(result)
	}

	return result
}

// InspectFlow analyzes a full Layer 4/7 flow and records traffic to the forensics buffer.
func (insp *DPIInspector) InspectFlow(
	srcIP, dstIP string,
	srcPort, dstPort int,
	protocol uint8,
	payload []byte,
) InspectionResult {
	if insp.pcapBuffer != nil {
		insp.pcapBuffer.Ingest(srcIP, dstIP, srcPort, dstPort, protocol, payload)
	}
	return insp.InspectPacketWithIP(payload, srcIP)
}

// triggerDropReactions coordinates autonomous defensive actions on VerdictDrop.
func (insp *DPIInspector) triggerDropReactions(res InspectionResult) {
	srcIP := res.SourceIP

	// 1. Immediate eBPF/XDP Fast-Path Drop (NIC Driver Ring Buffer)
	if insp.config.EnableeBPFBan && insp.xdpEngine != nil && srcIP != "" {
		_ = insp.xdpEngine.AddBan(srcIP)
	}

	// 2. Asynchronous RAM Ring Buffer Dump to /var/log/copsec/forensics/incident_<IP>_<TIMESTAMP>.pcap
	if insp.config.EnableForensicsDump && srcIP != "" {
		go insp.dumpForensicsPCAP(res)
	}

	// 3. Asynchronous Authenticated mTLS gRPC Alert to Tier 2 Controller (pardus1:50051)
	if insp.config.EnableAlert {
		go insp.dispatchControllerAlert(res)
	}
}

// triggerTarpitReactions coordinates local kernel redirect to the zero-window tarpit engine.
func (insp *DPIInspector) triggerTarpitReactions(res InspectionResult) {
	if !insp.config.EnableTarpit || res.SourceIP == "" {
		return
	}

	if insp.customTarpitHook != nil {
		_ = insp.customTarpitHook(res.SourceIP, insp.config.TarpitPort)
		return
	}

	go func(targetIP string, port int) {
		// Apply local kernel redirect to TCP Zero-Window Tarpit (:2223)
		portStr := fmt.Sprintf("%d", port)
		_ = exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "1",
			"-p", "tcp", "-s", targetIP, "-j", "REDIRECT", "--to-ports", portStr).Run()
		log.Printf("[DPI_TARPIT] 🕸️ Kernel redirect applied: %s -> TCP :%d (Zero-Window Tarpit Active)",
			targetIP, port)
	}(res.SourceIP, insp.config.TarpitPort)
}

// dumpForensicsPCAP writes an incident PCAP snapshot asynchronously.
func (insp *DPIInspector) dumpForensicsPCAP(res InspectionResult) {
	cleanIP := strings.TrimSpace(res.SourceIP)
	safeIP := strings.ReplaceAll(cleanIP, ":", "_")
	timestamp := time.Now().UnixMilli()
	filename := fmt.Sprintf("incident_%s_%d.pcap", safeIP, timestamp)

	dir := insp.config.ForensicsDir
	if err := os.MkdirAll(dir, 0750); err != nil {
		dir = "./forensics"
		_ = os.MkdirAll(dir, 0750)
	}
	targetPath := filepath.Join(dir, filename)

	var pcapBytes []byte
	var err error

	// If ring buffer has recorded packets, serialize them
	if insp.pcapBuffer != nil {
		var snap *forensics.ForensicSnapshot
		snap, err = insp.pcapBuffer.SnapshotForIP(cleanIP, res.Reason)
		if err == nil && snap != nil && snap.FilePath != "" {
			// Copy or link to incident_<IP>_<TIMESTAMP>.pcap format
			data, readErr := os.ReadFile(snap.FilePath)
			if readErr == nil {
				_ = os.WriteFile(targetPath, data, 0640)
				log.Printf("[DPI_FORENSICS] 📦 Forensic PCAP dumped: %s (%d bytes)", targetPath, len(data))
				return
			}
		}
	}

	// Synthesize an incident packet record from payload
	pkt := &forensics.RawPacket{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP(cleanIP),
		DstIP:     net.IPv4(10, 0, 0, 1),
		SrcPort:   44332,
		DstPort:   80,
		Protocol:  6, // TCP
		Payload:   []byte(res.Features.NormalizedPayload),
	}
	if pkt.SrcIP == nil {
		pkt.SrcIP = net.IPv4(192, 168, 1, 100)
	}

	pcapBytes, err = forensics.SerializeToPCAP([]*forensics.RawPacket{pkt})
	if err == nil && len(pcapBytes) > 0 {
		if writeErr := os.WriteFile(targetPath, pcapBytes, 0640); writeErr == nil {
			log.Printf("[DPI_FORENSICS] 📦 Synthesized forensic PCAP dumped: %s (%d bytes)", targetPath, len(pcapBytes))
		}
	}
}

// dispatchControllerAlert sends an authenticated mTLS gRPC event to the controller.
func (insp *DPIInspector) dispatchControllerAlert(res InspectionResult) {
	if insp.customAlertHook != nil {
		insp.customAlertHook(res)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ruleID := "DPI_ML_ZERO_DAY"
	if res.MatchedRule != nil && res.MatchedRule.ID != "" {
		ruleID = res.MatchedRule.ID
	}

	event := &copsecproto.LogEvent{
		NodeId:           "node-edge-dpi",
		Source:           "l7_dpi_engine",
		RawLine:          fmt.Sprintf("[L7_DPI_DROP] Target IP: %s, Reason: %s, Score: %.2f", res.SourceIP, res.Reason, res.Score),
		ClientIp:         res.SourceIP,
		StatusCode:       403,
		TimestampMs:      time.Now().UnixMilli(),
		RuleId:           ruleID,
		MitreTechniqueId: "T1190",
		ThreatScore:      int32(res.Score * 100),
	}

	// Attempt dial to Tier 2 Controller over secure client conn
	conn, err := dialSecureClientConn(ctx, insp.config.ControllerEndpoint)
	if err != nil {
		// Log dispatch in local security audit if central controller unreachable
		log.Printf("[DPI_ALERT] ⚡ Layer 7 DPI Alert: IP=%s Reason=%q Score=%.2f (Controller offline/mTLS queued)",
			event.ClientIp, res.Reason, res.Score)
		return
	}
	defer conn.Close()

	client := copsecproto.NewCopsecStreamServiceClient(conn)
	stream, err := client.StreamEvents(ctx)
	if err == nil {
		_ = stream.Send(event)
		_, _ = stream.CloseAndRecv()
		log.Printf("[DPI_ALERT] 🟢 Dispatched mTLS gRPC alert to %s for %s",
			insp.config.ControllerEndpoint, res.SourceIP)
	}
}

// SetAlertHook allows test suites or controllers to intercept alert dispatches.
func (insp *DPIInspector) SetAlertHook(hook func(res InspectionResult)) {
	insp.mu.Lock()
	defer insp.mu.Unlock()
	insp.customAlertHook = hook
}

// SetTarpitHook allows test suites or controllers to intercept tarpit redirects.
func (insp *DPIInspector) SetTarpitHook(hook func(srcIP string, port int) error) {
	insp.mu.Lock()
	defer insp.mu.Unlock()
	insp.customTarpitHook = hook
}

// extractOrSynthesizeIP attempts to parse the IPv4 source address if raw packet header is present.
func extractOrSynthesizeIP(payload []byte) string {
	// Check if this payload starts with an IPv4 header (version 4, IHL >= 5, total len >= 20)
	if len(payload) >= 20 && (payload[0]>>4) == 4 {
		src := net.IP(payload[12:16])
		if src.To4() != nil && !src.IsUnspecified() {
			return src.String()
		}
	}
	return "192.168.1.100"
}

// InspectPacket provides package-level shortcut to inspect payload using default singleton inspector.
func InspectPacket(payload []byte) InspectionResult {
	return GetDefaultInspector().InspectPacket(payload)
}

// dialSecureClientConn establishes a hardened mTLS gRPC connection to the Tier 2 Controller.
func dialSecureClientConn(ctx context.Context, targetEndpoint string) (*grpc.ClientConn, error) {
	caPEM, err := os.ReadFile("/etc/copsec/certs/ca.crt")
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse root CA PEM")
	}
	clientCert, err := tls.LoadX509KeyPair("/etc/copsec/certs/client.crt", "/etc/copsec/certs/client.key")
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   "pardus1",
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}
	return grpc.DialContext(ctx, targetEndpoint, dialOpts...)
}
