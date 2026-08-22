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
	grpcAddr := flag.String("grpc-addr", "0.0.0.0:50051", "gRPC listen host:port for edge nodes")
	dbPath := flag.String("db", "/var/lib/copsec/copsec_controller.db", "Path to SQLite/DuckDB timeseries database")
	rulesPath := flag.String("rules", "/etc/copsec/rules.json", "Path to detection rules JSON")
	botToken := flag.String("telegram-token", os.Getenv("COPSEC_TELEGRAM_BOT_TOKEN"), "Telegram Bot Token for SOAR alerts")
	chatID := flag.String("telegram-chat", os.Getenv("COPSEC_TELEGRAM_CHAT_ID"), "Telegram Chat ID for SOAR alerts")
	headless := flag.Bool("headless", false, "Run in headless daemon mode without TUI dashboard")
	flag.Parse()

	log.Println("[INFO] CoPSeC Distributed Micro-SIEM/SOAR Central Controller initializing...")

	// 1. Embedded Timeseries Storage (WAL-mode SQLite)
	finalDbPath := *dbPath
	if err := os.MkdirAll(filepath.Dir(finalDbPath), 0750); err != nil {
		finalDbPath = "./copsec_controller.db"
	}
	storage, err := NewStorageEngine(finalDbPath)
	if err != nil {
		log.Fatalf("[FATAL] Storage engine initialization failed: %v", err)
	}
	defer storage.Close()

	// 2. Rule Engine & Deep Inspection
	finalRulesPath := *rulesPath
	if _, err := os.Stat(finalRulesPath); os.IsNotExist(err) {
		fallback := "../config/rules.json"
		if _, err := os.Stat(fallback); err == nil {
			finalRulesPath = fallback
		}
	}
	analyzer := NewRuleEngine(finalRulesPath)

	// 3. Central gRPC Server & Node Registry
	centralServer := NewCentralServer(storage, analyzer)
	grpcServer, err := StartGRPCServer(*grpcAddr, centralServer)
	if err != nil {
		log.Fatalf("[FATAL] gRPC server binding failed: %v", err)
	}
	defer grpcServer.GracefulStop()

	// 4. Telegram SOAR Bot
	tgCfg := TelegramBotConfig{
		BotToken: *botToken,
		ChatID:   *chatID,
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
		log.Printf("[INFO] Controller running in Headless Mode on %s. Press Ctrl+C to stop.", *grpcAddr)
		<-sigChan
		log.Println("[INFO] Shutting down Controller gracefully...")
		cancel()
		wg.Wait()
		return
	}

	// 5. Matrix Cyberpunk TUI Dashboard (Bubbletea)
	model := NewSIEMModel(centralServer, storage)
	p := tea.NewProgram(model, tea.WithAltScreen())

	go func() {
		<-sigChan
		p.Quit()
		cancel()
	}()

	if _, err := p.Run(); err != nil {
		log.Fatalf("[FATAL] TUI error: %v", err)
	}

	cancel()
	wg.Wait()
}
