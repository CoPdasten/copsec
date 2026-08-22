package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	controllerAddr := flag.String("controller", "127.0.0.1:50051", "Controller gRPC host:port address (over Tailscale / LAN)")
	nodeIdentityPath := flag.String("node-identity", "/etc/copsec/node.json", "Path to node identity file")
	bufferDbPath := flag.String("buffer-db", "/var/lib/copsec/buffer.db", "Path to offline SQLite / buffer queue database")
	nginxLogPath := flag.String("nginx-log", "/var/log/nginx/access.log", "Path to Nginx access log file")
	authLogPath := flag.String("auth-log", "/var/log/auth.log", "Path to SSH / Auth log file")
	syslogPath := flag.String("syslog", "/var/log/syslog", "Path to system syslog file")
	offsetFilePath := flag.String("offset-file", "/var/lib/copsec/offsets.json", "Path to save/load file offsets")
	whitelistPath := flag.String("whitelist", "/etc/copsec/whitelist.json", "Path to whitelist configuration JSON")
	flag.Parse()

	log.Println("[INFO] CoPSeC Phase 3 Edge Multi-Log Collector initializing...")

	// 1. Identity & Auto-Enrollment
	identityMgr, err := LoadOrCreateIdentity(*nodeIdentityPath)
	if err != nil {
		log.Fatalf("[FATAL] Identity initialization failed: %v", err)
	}

	// 2. Offline Buffering
	finalBufferPath := *bufferDbPath
	if err := os.MkdirAll(filepath.Dir(finalBufferPath), 0750); err != nil {
		finalBufferPath = "./buffer.db"
	}
	offlineBuffer, err := NewOfflineBuffer(finalBufferPath)
	if err != nil {
		log.Fatalf("[FATAL] Offline buffer initialization failed: %v", err)
	}
	defer offlineBuffer.Close()

	// 3. gRPC Client for Controller Streaming
	grpcCfg := GrpcClientConfig{
		ServerAddress:   *controllerAddr,
		HeartbeatPeriod: 3 * time.Second,
		MaxBatchSize:    100,
	}
	controllerClient := NewControllerClient(grpcCfg, identityMgr, offlineBuffer)

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
		{Source: "ssh", Path: *authLogPath},
		{Source: "syslog", Path: *syslogPath},
	}

	collector := NewMultiLogCollector(sources, finalOffsetPath, finalWhitelistPath, controllerClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Signal %v received. Initiating graceful collector shutdown...", sig)
		cancel()
	}()

	collector.Start(ctx)
}
