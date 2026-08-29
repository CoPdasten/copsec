package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/copsec/collector/pkg/dns"
	"github.com/copsec/collector/pkg/ebpf"
	"github.com/copsec/collector/pkg/healing"
	"github.com/copsec/collector/pkg/honeypot"
	"github.com/copsec/collector/pkg/tarpit"
	"github.com/copsec/collector/pkg/yara"
	copsecproto "github.com/copsec/collector/proto"
)

func main() {
	controllerAddr := flag.String("controller", "127.0.0.1:50051", "Controller gRPC host:port address (over Tailscale / LAN)")
	nodeIdentityPath := flag.String("node-identity", "/etc/copsec/node.json", "Path to node identity file")
	bufferDbPath := flag.String("buffer-db", "/var/lib/copsec/buffer.db", "Path to offline SQLite / buffer queue database")
	nginxLogPath := flag.String("nginx-log", "/var/log/nginx/access.log", "Path to Nginx access log file")
	authLogPath := flag.String("auth-log", "/var/log/auth.log", "Path to SSH / Auth log file")
	syslogPath := flag.String("syslog", "/var/log/syslog", "Path to system syslog file")
	suricataLogPath := flag.String("suricata-log", "/var/log/suricata/eve.json", "Path to Suricata EVE JSON log file")
	snortLogPath := flag.String("snort-log", "/var/log/snort/alert_json.txt", "Path to Snort 3 Alert JSON log file")
	auditLogPath := flag.String("audit-log", "/var/log/audit/audit.log", "Path to Linux auditd log file")
	offsetFilePath := flag.String("offset-file", "/var/lib/copsec/offsets.json", "Path to save/load file offsets")
	whitelistPath := flag.String("whitelist", "/etc/copsec/whitelist.json", "Path to whitelist configuration JSON")
	flag.Parse()

	log.Println("[INFO] CoPSeC Ultra-Fast Edge Collector initializing (Hub-and-Spoke SIEM Ingestion)...")

	// 1. Identity & Auto-Enrollment
	identityMgr, err := LoadOrCreateIdentity(*nodeIdentityPath)
	if err != nil {
		log.Fatalf("[FATAL] Identity initialization failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Offline Buffering & Autonomous Fallback Engine
	finalBufferPath := *bufferDbPath
	if err := os.MkdirAll(filepath.Dir(finalBufferPath), 0750); err != nil {
		finalBufferPath = "./buffer.db"
	}
	offlineBuffer, err := NewOfflineBuffer(finalBufferPath)
	if err != nil {
		log.Fatalf("[FATAL] Offline buffer initialization failed: %v", err)
	}
	defer offlineBuffer.Close()

	fallbackEngine := NewFallbackEngine(identityMgr.GetNodeID())

	// 3. gRPC Client for Controller Streaming
	grpcCfg := GrpcClientConfig{
		ServerAddress:   *controllerAddr,
		HeartbeatPeriod: 3 * time.Second,
		MaxBatchSize:    100,
	}
	controllerClient := NewControllerClient(grpcCfg, identityMgr, offlineBuffer)
	controllerClient.SetFallbackEngine(fallbackEngine)

	// 4. File Offsets & Whitelist
	finalOffsetPath := *offsetFilePath
	if err := os.MkdirAll(filepath.Dir(finalOffsetPath), 0750); err != nil {
		finalOffsetPath = "./offsets.json"
	}

	finalWhitelistPath := *whitelistPath
	if _, err := os.Stat(finalWhitelistPath); os.IsNotExist(err) {
		fallback := "../config/whitelist.json"
		if _, err := os.Stat(fallback); err == nil {
			finalWhitelistPath = fallback
		}
	}

	sources := []LogSourceConfig{
		{Source: "nginx", Path: *nginxLogPath},
		{Source: "auth", Path: *authLogPath},
		{Source: "syslog", Path: *syslogPath},
		{Source: "suricata", Path: *suricataLogPath},
		{Source: "snort", Path: *snortLogPath},
		{Source: "audit", Path: *auditLogPath},
	}

	collector := NewMultiLogCollector(sources, finalOffsetPath, finalWhitelistPath, controllerClient)
	fallbackEngine.SetWhitelistFilter(collector.GetFilter(), finalWhitelistPath)

	// 5. Start Defensive Subsystems (FIM, Tarpit, Honeypot, YARA, Integrity Guard, DNS Sinkhole)
	fimEngine := healing.GetDefaultFIMEngine()
	go fimEngine.StartWatchLoop(ctx, 5*time.Second)

	tarpitEngine := tarpit.GetDefaultTarpit()
	go func() {
		_ = tarpitEngine.Start(ctx)
	}()
	defer tarpitEngine.Close()

	honeypotEngine := honeypot.GetDefaultShadowHoneypot()
	honeypotEngine.SetEventHandler(func(interaction honeypot.HoneypotInteraction) {
		if controllerClient != nil {
			ev := &copsecproto.LogEvent{
				Source:           "honeypot",
				RawLine:          fmt.Sprintf("[HONEYPOT_DECEPTION: %s] %s (is_honeypot=true)", interaction.TrapType, interaction.PayloadSummary),
				ClientIp:         interaction.ClientIP,
				ThreatScore:      95,
				RuleId:           fmt.Sprintf("honeypot_%s", strings.ToLower(interaction.TrapType)),
				MitreTechniqueId: interaction.MitreTechniqueID,
				TimestampMs:      interaction.TimestampMs,
			}
			controllerClient.Submit(ev)
		}
	})
	go func() {
		_ = honeypotEngine.Start(ctx)
	}()
	defer honeypotEngine.Close()

	_ = ebpf.GetDefaultIntegrityGuard()
	_ = dns.GetDefaultSinkhole()
	_ = yara.GetDefaultScanner()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Signal %v received. Initiating graceful collector shutdown...", sig)
		cancel()
	}()

	collector.Start(ctx)
}
