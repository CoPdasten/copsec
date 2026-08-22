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
	rulesPath := flag.String("rules", "../config/rules.json", "Rules JSON path")
	dbPath := flag.String("db", "./data/copsec.db", "SQLite DB path")
	tgToken := flag.String("telegram-token", os.Getenv("COPSEC_TELEGRAM_BOT_TOKEN"), "Telegram Bot Token")
	tgChat := flag.String("telegram-chat", os.Getenv("COPSEC_TELEGRAM_CHAT_ID"), "Telegram Chat ID")
	autoBan := flag.Bool("auto-ban", true, "Enable autonomous SOAR auto-ban")
	autoBanThreshold := flag.Int("auto-ban-threshold", 85, "Threat score threshold for auto-ban")
	headless := flag.Bool("headless", false, "Run in headless daemon mode without TUI dashboard")
	flag.Parse()

	log.Println("[INFO] CoPSeC Distributed Micro-SIEM/SOAR Central Controller initializing...")

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

	// 2. Rule Engine & Deep Inspection
	finalRulesPath := *rulesPath
	if _, err := os.Stat(finalRulesPath); os.IsNotExist(err) {
		fallback := "/etc/copsec/rules.json"
		if _, err := os.Stat(fallback); err == nil {
			finalRulesPath = fallback
		}
	}
	analyzer := NewRuleEngine(finalRulesPath)

	// 3. Central gRPC Server, Autonomous SOAR & Node Registry
	centralServer := NewCentralServer(storage, analyzer)
	centralServer.SetAutoBanPolicy(*autoBan, *autoBanThreshold)

	grpcServer, err := StartGRPCServer(*grpcAddr, centralServer)
	if err != nil {
		log.Fatalf("[FATAL] gRPC server binding failed: %v", err)
	}
	defer grpcServer.GracefulStop()

	// 4. Telegram SOAR Bot
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

	// Handle OS shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if *headless {
		log.Printf("[INFO] Controller running in Headless Mode on %s. Auto-Ban: %v (Threshold: %d). Press Ctrl+C to stop.",
			*grpcAddr, *autoBan, *autoBanThreshold)
		<-sigChan
		log.Println("[INFO] Shutting down Controller gracefully...")
		cancel()
		wg.Wait()
		return
	}

	// 5. Matrix Cyberpunk TUI Dashboard (Bubbletea)
	// Redirect logger to avoid breaking the TUI display
	logFile, err := os.OpenFile("/tmp/copsec_controller.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	model := NewSIEMModel(centralServer, storage)
	p := tea.NewProgram(model, tea.WithAltScreen())

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
