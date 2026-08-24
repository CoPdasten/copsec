package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	grpcAddr := flag.String("grpc-addr", "0.0.0.0:8443", "gRPC listen address")
	webAddr := flag.String("web-addr", "0.0.0.0:8080", "Embedded Web SOC listen address")
	honeypotSSHAddr := flag.String("honeypot-ssh", ":2222", "Fake SSH Honeypot listen address")
	rulesPath := flag.String("rules", "../config/rules.json", "Rules JSON path")
	sigmaDir := flag.String("sigma-dir", "/etc/copsec/sigma", "SigmaHQ detection rules directory")
	dbPath := flag.String("db", "./data/copsec.db", "SQLite DB path")
	tgToken := flag.String("telegram-token", os.Getenv("COPSEC_TELEGRAM_BOT_TOKEN"), "Telegram Bot Token")
	tgChat := flag.String("telegram-chat", os.Getenv("COPSEC_TELEGRAM_CHAT_ID"), "Telegram Chat ID")
	autoBan := flag.Bool("auto-ban", true, "Enable autonomous SOAR auto-ban")
	autoBanThreshold := flag.Int("auto-ban-threshold", 50, "Threat score threshold for auto-ban")
	headless := flag.Bool("headless", false, "Run in headless daemon mode without TUI dashboard")
	flag.Parse()

	log.Println("[INFO] ⚡ CoPSeC Distributed Micro-SIEM / Autonomous SOAR Matrix initializing...")

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
	rateLimiter := NewTokenBucketRateLimiter(25.0, 50.0, centralServer, ttlManager) // 25 req/s, burst 50

	honeypotSSH := NewHoneypotSSHServer(*honeypotSSHAddr, centralServer, ttlManager, storage)
	if honeypotSSH != nil {
		if err := honeypotSSH.Start(); err != nil {
			log.Printf("[WARN] Fake SSH honeypot startup on %s failed: %v", *honeypotSSHAddr, err)
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

	// 7. Embedded Web SOC Server
	webServer := NewWebSOCServer(
		*webAddr,
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
		grpcServer, err := StartGRPCServer(*grpcAddr, centralServer)
		if err != nil {
			log.Fatalf("[FATAL] gRPC server binding failed: %v", err)
		}
		defer grpcServer.GracefulStop()
		<-ctx.Done()
	}()

	// Handle OS shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if *headless {
		log.Printf("[INFO] ⚡ CoPSeC Controller running in Headless Mode on gRPC %s, Web SOC http://%s. Auto-Ban: %v (Threshold: %d). Press Ctrl+C to stop.",
			*grpcAddr, *webAddr, *autoBan, *autoBanThreshold)
		<-sigChan
		log.Println("[INFO] Shutting down Controller gracefully...")
		cancel()
		wg.Wait()
		return
	}

	// 9. Matrix Cyberpunk TUI Dashboard (Bubbletea)
	logFile, err := os.OpenFile("/tmp/copsec_controller.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	model := NewSIEMModel(centralServer, storage)
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	centralServer.SetTeaProgram(p)

	go func() {
		<-sigChan
		p.Quit()
		cancel()
	}()

	if _, err := p.Run(); err != nil {
		log.Fatalf("[FATAL] TUI execution failed: %v", err)
	}

	cancel()
	wg.Wait()
}
