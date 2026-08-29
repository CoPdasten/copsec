package honeypot

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HoneypotInteraction represents an attacker interaction within shadow honeypot traps.
type HoneypotInteraction struct {
	ID               string `json:"id"`
	TrapType         string `json:"trap_type"` // SSH_HONEYPOT, HTTP_HONEYPOT
	ClientIP         string `json:"client_ip"`
	Port             int    `json:"port"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	PayloadSummary   string `json:"payload_summary"`
	MitreTechniqueID string `json:"mitre_technique_id"`
	TimestampMs      int64  `json:"timestamp_ms"`
	IsHoneypot       bool   `json:"is_honeypot"`
}

// ShadowHoneypot manages internal isolated decoy honeypot daemons (SSH port 2222, HTTP port 8088).
type ShadowHoneypot struct {
	mu            sync.RWMutex
	sshBindAddr   string
	httpBindAddr  string
	sshListener   net.Listener
	httpServer    *http.Server
	sshHits       uint64
	httpHits      uint64
	onEvent       func(interaction HoneypotInteraction)
	stopChan      chan struct{}
	redirectedIPs sync.Map
}

var (
	defaultHoneypot *ShadowHoneypot
	honeypotOnce    sync.Once
)

// GetDefaultShadowHoneypot returns the singleton shadow honeypot instance.
func GetDefaultShadowHoneypot() *ShadowHoneypot {
	honeypotOnce.Do(func() {
		defaultHoneypot = NewShadowHoneypot("127.0.0.1:2222", "127.0.0.1:8088", nil)
	})
	return defaultHoneypot
}

// NewShadowHoneypot creates a new shadow honeypot listener.
func NewShadowHoneypot(sshAddr, httpAddr string, onEvent func(HoneypotInteraction)) *ShadowHoneypot {
	if sshAddr == "" {
		sshAddr = "127.0.0.1:2222"
	}
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8088"
	}
	return &ShadowHoneypot{
		sshBindAddr:  sshAddr,
		httpBindAddr: httpAddr,
		onEvent:      onEvent,
		stopChan:     make(chan struct{}),
	}
}

// SetEventHandler configures the telemetry callback for trapped interactions.
func (h *ShadowHoneypot) SetEventHandler(handler func(HoneypotInteraction)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onEvent = handler
}

// Start launches the SSH and HTTP shadow decoy services.
func (h *ShadowHoneypot) Start(ctx context.Context) error {
	// 1. SSH Decoy Listener (Port 2222)
	l, err := net.Listen("tcp", h.sshBindAddr)
	if err != nil {
		log.Printf("[HONEYPOT] ⚠️ Failed to bind SSH honeypot on %s: %v", h.sshBindAddr, err)
	} else {
		h.sshListener = l
		log.Printf("[HONEYPOT] 🍯 Shadow SSH Honeypot listening on %s (Decoy Port 2222)", h.sshBindAddr)
		go h.acceptSSHLoop(ctx)
	}

	// 2. HTTP Decoy Listener (Port 8088)
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleHTTPDecoy)
	h.httpServer = &http.Server{
		Addr:    h.httpBindAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("[HONEYPOT] 🍯 Shadow HTTP/WAF Honeypot listening on %s (Decoy Port 8088)", h.httpBindAddr)
		if err := h.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HONEYPOT] HTTP honeypot stopped: %v", err)
		}
	}()

	return nil
}

func (h *ShadowHoneypot) acceptSSHLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopChan:
			return
		default:
		}

		conn, err := h.sshListener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		atomic.AddUint64(&h.sshHits, 1)
		go h.handleSSHConn(conn)
	}
}

func (h *ShadowHoneypot) handleSSHConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	remoteAddr := conn.RemoteAddr().String()
	host, portStr, _ := net.SplitHostPort(remoteAddr)
	port, _ := strconv.Atoi(portStr)

	// Send OpenSSH banner
	_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"))

	reader := bufio.NewReader(conn)
	clientBanner, _ := reader.ReadString('\n')
	clientBanner = strings.TrimSpace(clientBanner)

	interaction := HoneypotInteraction{
		ID:               fmt.Sprintf("hp-ssh-%s-%d", host, time.Now().UnixNano()),
		TrapType:         "SSH_HONEYPOT",
		ClientIP:         host,
		Port:             port,
		PayloadSummary:   fmt.Sprintf("SSH Probe: client_banner=%s", clientBanner),
		MitreTechniqueID: "T1110.001", // Password Guessing / Brute Force
		TimestampMs:      time.Now().UnixMilli(),
		IsHoneypot:       true,
	}

	log.Printf("[HONEYPOT] 🍯 Decoy SSH Trap triggered by %s:%d (Banner: %s) [MITRE: T1110.001]", host, port, clientBanner)

	h.mu.RLock()
	cb := h.onEvent
	h.mu.RUnlock()
	if cb != nil {
		cb(interaction)
	}
}

func (h *ShadowHoneypot) handleHTTPDecoy(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&h.httpHits, 1)
	clientIP, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	port, _ := strconv.Atoi(portStr)

	urlPath := r.URL.String()
	userAgent := r.UserAgent()

	// Classify MITRE technique based on URI probe
	mitreID := "T1595.002" // Vulnerability Scanning
	if strings.Contains(urlPath, "admin") || strings.Contains(urlPath, "login") || strings.Contains(urlPath, "wp-login") {
		mitreID = "T1078" // Valid Accounts / Credential Access
	} else if strings.Contains(urlPath, "shell") || strings.Contains(urlPath, "cgi-bin") || strings.Contains(urlPath, "eval") {
		mitreID = "T1059.004" // Command and Scripting Interpreter
	} else if strings.Contains(urlPath, ".env") || strings.Contains(urlPath, "config") || strings.Contains(urlPath, "id_rsa") {
		mitreID = "T1552.001" // Credentials in Files
	}

	interaction := HoneypotInteraction{
		ID:               fmt.Sprintf("hp-http-%s-%d", clientIP, time.Now().UnixNano()),
		TrapType:         "HTTP_HONEYPOT",
		ClientIP:         clientIP,
		Port:             port,
		PayloadSummary:   fmt.Sprintf("%s %s (UA: %s)", r.Method, urlPath, userAgent),
		MitreTechniqueID: mitreID,
		TimestampMs:      time.Now().UnixMilli(),
		IsHoneypot:       true,
	}

	log.Printf("[HONEYPOT] 🍯 Decoy HTTP Trap triggered by %s -> %s %s [MITRE: %s]", clientIP, r.Method, urlPath, mitreID)

	h.mu.RLock()
	cb := h.onEvent
	h.mu.RUnlock()
	if cb != nil {
		cb(interaction)
	}

	// Respond with fake admin portal login page
	w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Administrative Management Portal</title></head><body style="background:#111;color:#eee;font-family:sans-serif;text-align:center;padding-top:100px;"><h2>Internal Portal Login</h2><form method="POST" action="/login"><input type="text" name="user" placeholder="Username" /><br/><br/><input type="password" name="pass" placeholder="Password" /><br/><br/><input type="submit" value="Sign In" /></form></body></html>`))
}

// RedirectAttackerToHoneypot configures kernel iptables PREROUTING redirect targeting the shadow honeypot.
func (h *ShadowHoneypot) RedirectAttackerToHoneypot(ip string, serviceType string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || cleanIP == "127.0.0.1" || cleanIP == "::1" {
		return fmt.Errorf("invalid ip for honeypot redirection: %s", cleanIP)
	}

	h.redirectedIPs.Store(cleanIP, serviceType)

	// 1. Flush any conflicting DROP rules for this IP to allow honeypot capture
	_ = exec.Command("sudo", "iptables", "-t", "raw", "-D", "PREROUTING", "-s", cleanIP, "-j", "DROP").Run()
	_ = exec.Command("sudo", "iptables", "-D", "INPUT", "-s", cleanIP, "-j", "DROP").Run()

	// 2. Redirect SSH (22) -> Decoy Port 2222 and HTTP (80/443) -> Decoy Port 8088
	_ = exec.Command("sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-p", "tcp", "-s", cleanIP, "--dport", "22", "-j", "REDIRECT", "--to-ports", "2222").Run()
	_ = exec.Command("sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-p", "tcp", "-s", cleanIP, "--dport", "80", "-j", "REDIRECT", "--to-ports", "8088").Run()
	_ = exec.Command("sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-p", "tcp", "-s", cleanIP, "--dport", "443", "-j", "REDIRECT", "--to-ports", "8088").Run()

	log.Printf("[HONEYPOT] 🪤 Configured Kernel PREROUTING Deception Redirection for %s -> Decoys (2222/8088)", cleanIP)
	return nil
}

// RemoveRedirection tears down iptables deception redirection.
func (h *ShadowHoneypot) RemoveRedirection(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	h.redirectedIPs.Delete(cleanIP)

	_ = exec.Command("sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", cleanIP, "--dport", "22", "-j", "REDIRECT", "--to-ports", "2222").Run()
	_ = exec.Command("sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", cleanIP, "--dport", "80", "-j", "REDIRECT", "--to-ports", "8088").Run()
	_ = exec.Command("sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", cleanIP, "--dport", "443", "-j", "REDIRECT", "--to-ports", "8088").Run()
	return nil
}

// GetStats returns telemetry counters for the honeypot subsystem.
func (h *ShadowHoneypot) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	activeRedirs := 0
	h.redirectedIPs.Range(func(key, value interface{}) bool {
		activeRedirs++
		return true
	})

	return map[string]interface{}{
		"ssh_decoy_hits":   atomic.LoadUint64(&h.sshHits),
		"http_decoy_hits":  atomic.LoadUint64(&h.httpHits),
		"active_redirects": activeRedirs,
		"ssh_bind_port":    2222,
		"http_bind_port":   8088,
	}
}

// Close gracefully terminates honeypot listeners.
func (h *ShadowHoneypot) Close() error {
	close(h.stopChan)
	if h.sshListener != nil {
		_ = h.sshListener.Close()
	}
	if h.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.httpServer.Shutdown(ctx)
	}
	return nil
}
