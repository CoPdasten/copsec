package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/copsec/collector/pkg/p2p"
)

func main() {
	controllerAddr := flag.String("controller", "127.0.0.1:50051", "Controller gRPC host:port address (over Tailscale / LAN)")
	nodeIdentityPath := flag.String("node-identity", "/etc/copsec/node.json", "Path to node identity file")
	bufferDbPath := flag.String("buffer-db", "/var/lib/copsec/buffer.db", "Path to offline SQLite / buffer queue database")
	nginxLogPath := flag.String("nginx-log", "/var/log/nginx/access.log", "Path to Nginx access log file")
	authLogPath := flag.String("auth-log", "/var/log/auth.log", "Path to SSH / Auth log file")
	syslogPath := flag.String("syslog", "/var/log/syslog", "Path to system syslog file")
	suricataLogPath := flag.String("suricata-log", "/var/log/suricata/eve.json", "Path to Suricata EVE JSON log file")
	auditLogPath := flag.String("audit-log", "/var/log/audit/audit.log", "Path to Linux auditd log file")
	offsetFilePath := flag.String("offset-file", "/var/lib/copsec/offsets.json", "Path to save/load file offsets")
	whitelistPath := flag.String("whitelist", "/etc/copsec/whitelist.json", "Path to whitelist configuration JSON")
	fallbackTgToken := flag.String("fallback-telegram-token", "", "Optional Telegram Bot Token for direct offline edge emergency alerts")
	fallbackTgChat := flag.String("fallback-telegram-chat", "", "Optional Telegram Chat ID for direct offline edge emergency alerts")
	p2pBind := flag.String("p2p-bind", ":7946", "P2P Gossip mesh bind address (UDP)")
	p2pJoin := flag.String("p2p-join", "", "Comma-separated bootstrap peers to join (e.g. 10.0.0.1:7946)")
	p2pSecret := flag.String("p2p-secret", "copsec-zero-trust-mesh-secret", "Cluster secret for signed P2P gossip")
	flag.Parse()

	log.Println("[INFO] CoPSeC Phase 3 Edge Multi-Log Collector initializing (5 Core Sensors + P2P Mesh)...")

	// 1. Identity & Auto-Enrollment
	identityMgr, err := LoadOrCreateIdentity(*nodeIdentityPath)
	if err != nil {
		log.Fatalf("[FATAL] Identity initialization failed: %v", err)
	}

	// 2. P2P Gossip Threat Intelligence Mesh
	var peers []string
	if *p2pJoin != "" {
		for _, p := range strings.Split(*p2pJoin, ",") {
			if strings.TrimSpace(p) != "" {
				peers = append(peers, strings.TrimSpace(p))
			}
		}
	}

	meshCfg := p2p.MeshConfig{
		NodeID:         identityMgr.GetNodeID(),
		BindAddr:       *p2pBind,
		BootstrapPeers: peers,
		ClusterSecret:  *p2pSecret,
	}

	mesh := p2p.NewGossipMesh(meshCfg, func(tb p2p.ThreatBroadcast) {
		// When receiving gossiped threat from peer, enforce instant local mitigation
		_ = ExecuteInstantBan(tb.TargetIP)
	}, func(entry p2p.CRDTBanEntry) {
		// On CRDT ban sync, ensure local XDP and iptables drop
		_ = ExecuteInstantBan(entry.TargetIP)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mesh.Start(ctx); err != nil {
		log.Printf("[WARN] P2P Mesh failed to start on %s: %v (continuing in standalone mode)", *p2pBind, err)
	}
	defer mesh.Close()

	// 3. Offline Buffering & Autonomous Fallback Engine
	finalBufferPath := *bufferDbPath
	if err := os.MkdirAll(filepath.Dir(finalBufferPath), 0750); err != nil {
		finalBufferPath = "./buffer.db"
	}
	offlineBuffer, err := NewOfflineBuffer(finalBufferPath)
	if err != nil {
		log.Fatalf("[FATAL] Offline buffer initialization failed: %v", err)
	}
	defer offlineBuffer.Close()

	fallbackEngine := NewFallbackEngine(identityMgr.GetNodeID(), *fallbackTgToken, *fallbackTgChat)
	fallbackEngine.SetP2PMesh(mesh)

	// 4. gRPC Client for Controller Streaming
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
		{Source: "audit", Path: *auditLogPath},
	}

	collector := NewMultiLogCollector(sources, finalOffsetPath, finalWhitelistPath, controllerClient)
	fallbackEngine.SetWhitelistFilter(collector.GetFilter(), finalWhitelistPath)

	var wg sync.WaitGroup
	wg.Add(1)
	go fallbackEngine.StartTelegramPolling(ctx, &wg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Signal %v received. Initiating graceful collector shutdown...", sig)
		cancel()
	}()

	collector.Start(ctx)
	wg.Wait()
}
