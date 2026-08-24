package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// HoneypotEvent represents an intercepted intrusion attempt on deception traps.
type HoneypotEvent struct {
	ID             int64  `json:"id"`
	TrapType       string `json:"trap_type"` // "SSH", "HONEY_URL", "RATE_LIMIT"
	ClientIP       string `json:"client_ip"`
	Port           int    `json:"port"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	ClientVersion  string `json:"client_version,omitempty"`
	RequestedURL   string `json:"requested_url,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	PayloadSummary string `json:"payload_summary,omitempty"`
	TimestampMs    int64  `json:"timestamp_ms"`
	AutoBanned     bool   `json:"auto_banned"`
	CountryCode    string `json:"country_code,omitempty"`
	CountryName    string `json:"country_name,omitempty"`
	City           string `json:"city,omitempty"`
	ASN            string `json:"asn,omitempty"`
	FlagEmoji      string `json:"flag_emoji,omitempty"`
}

// HoneypotSSHServer runs an embedded, zero-dependency SSH deception listener.
type HoneypotSSHServer struct {
	mu           sync.Mutex
	listenAddr   string
	listener     net.Listener
	sshConfig    *ssh.ServerConfig
	server       *CentralServer
	ttlManager   *TTLBanManager
	storage      *StorageEngine
	stopChan     chan struct{}
	running      bool
	attemptCount map[string]int
}

// NewHoneypotSSHServer creates the fake SSH deception listener.
func NewHoneypotSSHServer(listenAddr string, server *CentralServer, ttlManager *TTLBanManager, storage *StorageEngine) *HoneypotSSHServer {
	hp := &HoneypotSSHServer{
		listenAddr:   listenAddr,
		server:       server,
		ttlManager:   ttlManager,
		storage:      storage,
		stopChan:     make(chan struct{}),
		attemptCount: make(map[string]int),
	}

	config, err := hp.buildSSHConfig()
	if err != nil {
		log.Printf("[WARN] Failed to configure fake SSH listener: %v", err)
		return nil
	}
	hp.sshConfig = config

	return hp
}

// buildSSHConfig initializes the SSH server configuration with dynamic RSA host keys and credential interceptors.
func (hp *HoneypotSSHServer) buildSSHConfig() (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		NoClientAuth:  false,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			clientIP, port := parseRemoteAddr(conn.RemoteAddr().String())
			username := conn.User()
			passStr := string(password)
			clientVer := string(conn.ClientVersion())

			hp.handleSSHAttempt(clientIP, port, username, passStr, "", clientVer)

			// Always reject password to keep adversary trying or profile attempts
			return nil, fmt.Errorf("permission denied (password)")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			clientIP, port := parseRemoteAddr(conn.RemoteAddr().String())
			username := conn.User()
			clientVer := string(conn.ClientVersion())
			fingerprint := ssh.FingerprintSHA256(key)

			hp.handleSSHAttempt(clientIP, port, username, "", fingerprint, clientVer)

			return nil, fmt.Errorf("permission denied (publickey)")
		},
	}

	// Generate transient RSA host key in memory
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	signer, err := ssh.ParsePrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}
	config.AddHostKey(signer)

	return config, nil
}

func (hp *HoneypotSSHServer) handleSSHAttempt(clientIP string, port int, username, password, keyFingerprint, clientVer string) {
	nowMs := time.Now().UnixMilli()

	hp.mu.Lock()
	hp.attemptCount[clientIP]++
	count := hp.attemptCount[clientIP]
	hp.mu.Unlock()

	log.Printf("[HONEYPOT_SSH] 🍯 Intercepted Probe from %s:%d | User: %s | Pass: %s | Fingerprint: %s | Client: %s (Attempts: %d)",
		clientIP, port, username, password, keyFingerprint, clientVer, count)

	ev := &HoneypotEvent{
		TrapType:       "SSH",
		ClientIP:       clientIP,
		Port:           port,
		Username:       username,
		Password:       password,
		KeyFingerprint: keyFingerprint,
		ClientVersion:  clientVer,
		TimestampMs:    nowMs,
		AutoBanned:     true,
	}

	// 1. Record in DB
	if hp.storage != nil {
		_ = hp.storage.RecordHoneypotEvent(ev)
	}

	// 2. Dispatch SIEM StoredEvent
	rawLine := fmt.Sprintf("HONEYPOT_SSH: Unauthorized auth probe from %s:%d (user: %s, pass: %s, client: %s)", clientIP, port, username, password, clientVer)
	siemEvent := &StoredEvent{
		NodeID:           "controller-honeypot",
		Source:           "honeypot-ssh",
		RawLine:          rawLine,
		ClientIP:         clientIP,
		StatusCode:       401,
		TimestampMs:      nowMs,
		RuleID:           "honeypot-ssh-auth-bruteforce",
		MitreTechniqueID: "T1110.001",
		ThreatScore:      90,
		AIAnalysis:       fmt.Sprintf("• Intent: SSH Credential Brute-Forcing\n• Root Cause: Honeypot trap triggered\n• Mitigation: Instant L3/L4/L7 kernel quarantine"),
	}

	if hp.server != nil {
		_ = hp.server.storage.InsertEvent(siemEvent)
		select {
		case hp.server.eventSubChan <- siemEvent:
		default:
		}
	}

	// 3. Autonomous Instant Ban via SOAR TTL Manager
	if hp.ttlManager != nil && !isProtectedIP(clientIP) {
		banReason := fmt.Sprintf("Honeypot Trap Triggered: Fake SSH brute-force (user: %s)", username)
		_, _ = hp.ttlManager.BanIP(clientIP, banReason, 86400, TierExtendedQuarantine)
	}
}

// Start launches the Honeypot SSH server.
func (hp *HoneypotSSHServer) Start() error {
	if hp.sshConfig == nil {
		return fmt.Errorf("ssh config not initialized")
	}

	lis, err := net.Listen("tcp", hp.listenAddr)
	if err != nil {
		return fmt.Errorf("honeypot ssh bind failed on %s: %w", hp.listenAddr, err)
	}

	hp.mu.Lock()
	hp.listener = lis
	hp.running = true
	hp.mu.Unlock()

	log.Printf("[INFO] 🍯 Fake SSH Honeypot Listener active on %s", hp.listenAddr)

	go func() {
		for {
			tcpConn, err := lis.Accept()
			if err != nil {
				select {
				case <-hp.stopChan:
					return
				default:
					continue
				}
			}

			go hp.handleConn(tcpConn)
		}
	}()

	return nil
}

func (hp *HoneypotSSHServer) handleConn(tcpConn net.Conn) {
	defer tcpConn.Close()

	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))

	// SSH Handshake
	_, _, reqs, err := ssh.NewServerConn(tcpConn, hp.sshConfig)
	if err != nil {
		// Normal because PasswordCallback returns error to reject
		return
	}

	// Discard any SSH channel requests
	go ssh.DiscardRequests(reqs)
}

// Stop gracefully stops the Honeypot listener.
func (hp *HoneypotSSHServer) Stop() {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if hp.running {
		close(hp.stopChan)
		if hp.listener != nil {
			_ = hp.listener.Close()
		}
		hp.running = false
	}
}

func parseRemoteAddr(addr string) (ip string, port int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p := 0
	fmt.Sscanf(portStr, "%d", &p)
	return host, p
}

// HoneyDeceptionRouter provides deception routes (Honey-URLs).
type HoneyDeceptionRouter struct {
	server     *CentralServer
	ttlManager *TTLBanManager
	storage    *StorageEngine
	honeyURLs  map[string]bool
}

// NewHoneyDeceptionRouter initializes honey-URL detection.
func NewHoneyDeceptionRouter(server *CentralServer, ttlManager *TTLBanManager, storage *StorageEngine) *HoneyDeceptionRouter {
	hdr := &HoneyDeceptionRouter{
		server:     server,
		ttlManager: ttlManager,
		storage:    storage,
		honeyURLs:  make(map[string]bool),
	}

	traps := []string{
		"/admin",
		"/admin/config.php",
		"/.env",
		"/.git/config",
		"/wp-login.php",
		"/wp-admin",
		"/phpmyadmin",
		"/pma",
		"/actuator/health",
		"/actuator/gateway/routes",
		"/api/v1/debug",
		"/shell.php",
		"/c99.php",
		"/xmlrpc.php",
		"/solr/admin/info/system",
		"/cgi-bin/test.cgi",
	}

	for _, t := range traps {
		hdr.honeyURLs[strings.ToLower(t)] = true
	}

	return hdr
}

// IsHoneyURL returns true if the given path is a deception trap.
func (hdr *HoneyDeceptionRouter) IsHoneyURL(path string) bool {
	clean := strings.ToLower(strings.TrimSpace(path))
	if hdr.honeyURLs[clean] {
		return true
	}
	for trap := range hdr.honeyURLs {
		if strings.HasPrefix(clean, trap) {
			return true
		}
	}
	return false
}

// HandleHoneyProbe executes deception response and instant quarantine.
func (hdr *HoneyDeceptionRouter) HandleHoneyProbe(w http.ResponseWriter, r *http.Request) {
	clientIP, _ := parseRemoteAddr(r.RemoteAddr)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		clientIP = strings.TrimSpace(parts[0])
	}

	nowMs := time.Now().UnixMilli()
	userAgent := r.UserAgent()
	requestedURL := r.URL.String()

	log.Printf("[HONEYPOT_WEB] 🍯 Honey-URL Triggered: %s from %s (UA: %s)", requestedURL, clientIP, userAgent)

	ev := &HoneypotEvent{
		TrapType:       "HONEY_URL",
		ClientIP:       clientIP,
		RequestedURL:   requestedURL,
		UserAgent:      userAgent,
		PayloadSummary: fmt.Sprintf("Method: %s, Query: %s", r.Method, r.URL.RawQuery),
		TimestampMs:    nowMs,
		AutoBanned:     true,
	}

	if hdr.storage != nil {
		_ = hdr.storage.RecordHoneypotEvent(ev)
	}

	siemEvent := &StoredEvent{
		NodeID:           "controller-honeypot",
		Source:           "honeypot-web",
		RawLine:          fmt.Sprintf("%s %s %s User-Agent: %s", r.Method, requestedURL, r.Proto, userAgent),
		ClientIP:         clientIP,
		StatusCode:       403,
		TimestampMs:      nowMs,
		RuleID:           "honeypot-honey-url-trap",
		MitreTechniqueID: "T1595.002",
		ThreatScore:      95,
		AIAnalysis:       fmt.Sprintf("• Intent: Web Reconnaissance & Vulnerability Probing\n• Root Cause: High-interaction Honey-URL trap triggered\n• Mitigation: Immediate fleet isolation across L3/L4/L7"),
	}

	if hdr.server != nil {
		_ = hdr.server.storage.InsertEvent(siemEvent)
		select {
		case hdr.server.eventSubChan <- siemEvent:
		default:
		}
	}

	// Instant Multi-layer Ban
	if hdr.ttlManager != nil && !isProtectedIP(clientIP) {
		banReason := fmt.Sprintf("Honey-URL Deception Triggered: %s", requestedURL)
		_, _ = hdr.ttlManager.BanIP(clientIP, banReason, 86400, TierExtendedQuarantine)
	}

	// Simulated deceptive response
	w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
	w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>403 Forbidden</title></head><body>
<h1>Forbidden</h1><p>You don't have permission to access this resource.</p>
</body></html>`))
}

// TokenBucketRateLimiter enforces high-throughput per-IP token bucket rate limiting.
type TokenBucketRateLimiter struct {
	mu         sync.RWMutex
	rate       float64 // Tokens added per second
	capacity   float64 // Maximum burst capacity
	buckets    map[string]*clientBucket
	lastPrune  time.Time
	server     *CentralServer
	ttlManager *TTLBanManager
}

type clientBucket struct {
	tokens     float64
	lastRefill time.Time
	violations int
}

// NewTokenBucketRateLimiter initializes the token-bucket anti-DDoS filter.
func NewTokenBucketRateLimiter(rate, capacity float64, server *CentralServer, ttlManager *TTLBanManager) *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		rate:       rate,
		capacity:   capacity,
		buckets:    make(map[string]*clientBucket),
		lastPrune:  time.Now(),
		server:     server,
		ttlManager: ttlManager,
	}
}

// Allow checks if the request is within rate limits.
func (rl *TokenBucketRateLimiter) Allow(ip string) (bool, int) {
	if isProtectedIP(ip) {
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Prune idle entries every 60 seconds
	if now.Sub(rl.lastPrune) > 60*time.Second {
		for k, b := range rl.buckets {
			if now.Sub(b.lastRefill) > 5*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.lastPrune = now
	}

	b, exists := rl.buckets[ip]
	if !exists {
		b = &clientBucket{
			tokens:     rl.capacity - 1.0,
			lastRefill: now,
		}
		rl.buckets[ip] = b
		return true, 0
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = b.tokens + elapsed*rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true, 0
	}

	// Rate limit exceeded (Violation)
	b.violations++
	violations := b.violations

	// Trigger rate limit event asynchronously
	go rl.handleViolation(ip, violations)

	return false, 5 // Retry-After 5s
}

func (rl *TokenBucketRateLimiter) handleViolation(clientIP string, violations int) {
	if violations%5 != 1 {
		return
	}

	log.Printf("[RATE_LIMIT] ⚠️ Rate limit exceeded for IP: %s (Violations: %d)", clientIP, violations)

	if rl.ttlManager != nil && violations >= 10 && !isProtectedIP(clientIP) {
		banReason := fmt.Sprintf("Anti-DDoS / Rate Limit Flood (%d rapid requests)", violations)
		_, _ = rl.ttlManager.BanIP(clientIP, banReason, 300, TierRateLimit)
	}
}
