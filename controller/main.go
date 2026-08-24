package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func main() {
	grpcAddrFlag := flag.String("grpc-addr", "", "gRPC listen address (e.g. 0.0.0.0:8443)")
	grpcPortFlag := flag.Int("grpc-port", 8443, "gRPC listen port")
	webAddrFlag := flag.String("web-addr", "", "Embedded Web SOC listen address (e.g. 0.0.0.0:8080)")
	webPortFlag := flag.Int("web-port", 8080, "Embedded Web SOC listen port")
	honeypotSSHAddrFlag := flag.String("honeypot-ssh", "", "Fake SSH Honeypot listen address (e.g. :2222)")
	sshTrapPortFlag := flag.Int("ssh-trap-port", 2222, "Fake SSH Honeypot trap port")

	rulesPath := flag.String("rules", "../config/rules.json", "Rules JSON path")
	sigmaDir := flag.String("sigma-dir", "/etc/copsec/sigma", "SigmaHQ detection rules directory")
	dbPath := flag.String("db", "./data/copsec.db", "SQLite DB path")
	tgToken := flag.String("telegram-token", os.Getenv("COPSEC_TELEGRAM_BOT_TOKEN"), "Telegram Bot Token")
	tgChat := flag.String("telegram-chat", os.Getenv("COPSEC_TELEGRAM_CHAT_ID"), "Telegram Chat ID")
	autoBan := flag.Bool("auto-ban", true, "Enable autonomous SOAR auto-ban")
	autoBanThreshold := flag.Int("auto-ban-threshold", 50, "Threat score threshold for auto-ban")
	flag.Parse()

	// Resolve effective addresses and ports
	grpcAddr := fmt.Sprintf("0.0.0.0:%d", *grpcPortFlag)
	if *grpcAddrFlag != "" {
		grpcAddr = *grpcAddrFlag
	}

	webAddr := fmt.Sprintf("0.0.0.0:%d", *webPortFlag)
	if *webAddrFlag != "" {
		webAddr = *webAddrFlag
	}

	honeypotSSHAddr := fmt.Sprintf(":%d", *sshTrapPortFlag)
	if *honeypotSSHAddrFlag != "" {
		honeypotSSHAddr = *honeypotSSHAddrFlag
	}

	log.Println("[INFO] ⚡ CoPSeC Central Controller daemon initializing...")

	// 1. Embedded Timeseries Storage (WAL-mode SQLite)
	finalDbPath := *dbPath
	if err := os.MkdirAll(filepath.Dir(finalDbPath), 0750); err != nil {
		finalDbPath = "./copsec.db"
	}
	storage, err := NewStorageEngine(finalDbPath)
	if err != nil {
		log.Fatalf("[FATAL] Storage engine initialization failed: %v", err)
	}
	defer storage.Close()

	// 2. Rule Engine & SigmaHQ Detection-as-Code Engine
	finalRulesPath := *rulesPath
	if _, err := os.Stat(finalRulesPath); os.IsNotExist(err) {
		fallback := "/etc/copsec/rules.json"
		if _, err := os.Stat(fallback); err == nil {
			finalRulesPath = fallback
		}
	}
	analyzer := NewRuleEngine(finalRulesPath)

	finalSigmaDir := *sigmaDir
	if _, err := os.Stat(finalSigmaDir); os.IsNotExist(err) {
		fallback := "./sigma"
		if _, err := os.Stat(fallback); err == nil {
			finalSigmaDir = fallback
		} else {
			finalSigmaDir = ""
		}
	}
	sigmaEngine := NewSigmaEngine(finalSigmaDir)

	// 3. Central gRPC Server & WebSocket Hub
	centralServer := NewCentralServer(storage, analyzer)
	centralServer.SetSigmaEngine(sigmaEngine)
	centralServer.SetAutoBanPolicy(*autoBan, *autoBanThreshold)

	wsHub := NewWSHub()
	centralServer.SetWSHub(wsHub)

	// 4. SOAR Multi-Layer Mitigation & Dynamic TTL Ban Manager
	ttlManager := NewTTLBanManager(storage, centralServer)
	centralServer.SetTTLManager(ttlManager)
	defer ttlManager.Stop()

	// Hook TTL ban changes into WebSocket broadcast hub
	ttlManager.SetOnBanChangeCallback(func(ban *DetailedBanRecord, action string) {
		wsHub.Broadcast("ban_change", map[string]interface{}{
			"action": action,
			"ban":    ban,
		})
	})

	// 5. Embedded Deception & Rate-Limiting Traps
	deceptionRouter := NewHoneyDeceptionRouter(centralServer, ttlManager, storage)
	rateLimiter := NewTokenBucketRateLimiter(25.0, 50.0, centralServer, ttlManager)

	honeypotSSH := NewHoneypotSSHServer(honeypotSSHAddr, centralServer, ttlManager, storage)
	if honeypotSSH != nil {
		if err := honeypotSSH.Start(); err != nil {
			log.Printf("[WARN] Fake SSH honeypot startup on %s failed: %v", honeypotSSHAddr, err)
		} else {
			defer honeypotSSH.Stop()
		}
	}

	// 6. Telegram SOAR Bot
	tgCfg := TelegramBotConfig{
		BotToken: *tgToken,
		ChatID:   *tgChat,
	}
	tgBot := NewTelegramSOARBot(tgCfg, centralServer)
	centralServer.SetTelegramBot(tgBot)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	tgBot.Start(ctx, &wg)

	// 7. Embedded Web SOC Server (Single-Binary Web Console)
	webServer := NewWebSOCServer(
		webAddr,
		centralServer,
		storage,
		ttlManager,
		sigmaEngine,
		wsHub,
		deceptionRouter,
		rateLimiter,
		honeypotSSH,
	)
	if err := webServer.Start(); err != nil {
		log.Printf("[WARN] Web SOC server initialization failed: %v", err)
	}

	// 8. Start gRPC Ingestion Server in background
	go func() {
		grpcServer, err := StartGRPCServer(grpcAddr, centralServer)
		if err != nil {
			log.Fatalf("[FATAL] gRPC server binding failed: %v", err)
		}
		defer grpcServer.GracefulStop()
		<-ctx.Done()
	}()

	log.Printf("[INFO] ⚡ CoPSeC Central Controller daemon initialized successfully.")
	log.Printf("       • Web SOC Console : http://%s", webAddr)
	log.Printf("       • gRPC Ingestion  : %s", grpcAddr)
	log.Printf("       • SSH Honeypot    : %s", honeypotSSHAddr)
	log.Printf("       • Autonomous SOAR : Auto-Ban=%v (Threshold: %d)", *autoBan, *autoBanThreshold)

	// Block on OS termination signals for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[INFO] Gracefully shutting down CoPSeC Controller & flushing SQLite WAL...")
	cancel()
	wg.Wait()
	time.Sleep(150 * time.Millisecond)
}
