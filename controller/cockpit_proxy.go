package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// runCockpitProxyMode launches the Central SOC Cockpit in pure analyst mode.
// It serves the embedded UI and reverse-proxies telemetry/REST/WS requests to the remote vault.
func runCockpitProxyMode(remoteVault string, webAddr string, allowExternal bool) {
	cleanRemote := strings.TrimSpace(remoteVault)
	cleanRemote = strings.TrimPrefix(cleanRemote, "http://")
	cleanRemote = strings.TrimPrefix(cleanRemote, "https://")

	host := cleanRemote
	port := "8080"
	if strings.Contains(cleanRemote, ":") {
		parts := strings.Split(cleanRemote, ":")
		host = parts[0]
		// If remote address was given with gRPC port (50051), map to default REST API port (8080)
		if parts[1] == "50051" {
			port = "8080"
		} else {
			port = parts[1]
		}
	}
	targetURLStr := fmt.Sprintf("http://%s:%s", host, port)
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		log.Fatalf("[FATAL] Invalid remote vault address %q: %v", remoteVault, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-Copsec-Cockpit-Proxy", "true")
	}

	mux := http.NewServeMux()

	// 1. Serve embedded web UI for root and static HTML requests
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "/index.html" {
			content, err := embeddedWebFS.ReadFile("web/index.html")
			if err != nil {
				http.Error(w, "Web SOC UI asset not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
			return
		}
		// Proxy all remaining requests to the remote vault
		proxy.ServeHTTP(w, r)
	})

	// 2. Explicitly route /api/, /ws/, and /health to the remote vault
	mux.Handle("/api/", proxy)
	mux.Handle("/ws/", proxy)
	mux.Handle("/health", proxy)

	listenAddr := webAddr
	if strings.HasPrefix(listenAddr, "0.0.0.0:") && !allowExternal {
		listenAddr = "127.0.0.1:" + strings.TrimPrefix(listenAddr, "0.0.0.0:")
	}

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	fmt.Printf(`
================================================================================
  CoPSeC CENTRAL SOC COCKPIT (TIERED DEFENSE ANALYST CONTROLLER)
  Cockpit Web UI   : http://%s
  Remote Vault     : %s (Proxy Target: %s)
  Local Storage    : NONE (Zero-Database Pure Analyst Mode)
================================================================================
`, listenAddr, remoteVault, targetURLStr)

	log.Printf("[INFO] ⚡ CoPSeC Central Cockpit active on %s (Connected to Vault at %s)", listenAddr, targetURLStr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Cockpit HTTP server listener failed: %v", err)
		}
	}()

	sig := <-sigChan
	log.Printf("[INFO] Signal %v received. Shutting down Central Cockpit...", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	os.Exit(0)
}
