package tarpit

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TarpitSession tracks an active held connection draining attacker sockets.
type TarpitSession struct {
	ID               string `json:"id"`
	RemoteIP         string `json:"remote_ip"`
	RemotePort       int    `json:"remote_port"`
	Service          string `json:"service"` // SSH, HTTP, RAW_TCP
	ConnectedAtMs    int64  `json:"connected_at_ms"`
	DurationSec      int64  `json:"duration_sec"`
	BytesTransferred uint64 `json:"bytes_transferred"`
	Status           string `json:"status"` // TRAPPED, RELEASED, TIMED_OUT
}

// TarpitEngine traps automated botnets, port scanners, and brute-force tools into infinite wait states.
type TarpitEngine struct {
	mu              sync.RWMutex
	bindAddr        string
	listener        net.Listener
	activeSessions  map[string]*TarpitSession
	connectionsHold uint64
	totalBytesSent  uint64
	secondsDrained  uint64
	stopChan        chan struct{}
	onTrap          func(session TarpitSession)
}

var (
	defaultTarpit *TarpitEngine
	tarpitOnce    sync.Once
)

// GetDefaultTarpit returns the singleton tarpit instance.
func GetDefaultTarpit() *TarpitEngine {
	tarpitOnce.Do(func() {
		defaultTarpit = NewTarpitEngine(":2223", nil)
	})
	return defaultTarpit
}

// NewTarpitEngine creates a new TCP Zero-Window / Slow-Response Tarpit.
func NewTarpitEngine(bindAddr string, onTrap func(session TarpitSession)) *TarpitEngine {
	if bindAddr == "" {
		bindAddr = ":2223"
	}
	return &TarpitEngine{
		bindAddr:       bindAddr,
		activeSessions: make(map[string]*TarpitSession),
		stopChan:       make(chan struct{}),
		onTrap:         onTrap,
	}
}

// Start launches the tarpit TCP server.
func (t *TarpitEngine) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", t.bindAddr)
	if err != nil {
		return fmt.Errorf("failed to bind tarpit listener on %s: %w", t.bindAddr, err)
	}
	t.listener = l
	log.Printf("[TARPIT] 🕸️ TCP Zero-Window & Deception Tarpit listening on %s", t.bindAddr)

	go t.acceptLoop(ctx)
	go t.statsTicker(ctx)
	return nil
}

func (t *TarpitEngine) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopChan:
			return
		default:
		}

		conn, err := t.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		go t.TrapConnection(conn, "SSH_DECEPTION")
	}
}

// TrapConnection handles an inbound attacking TCP socket, holding it in an ultra-slow byte stream.
func (t *TarpitEngine) TrapConnection(conn net.Conn, service string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	host, portStr, _ := net.SplitHostPort(remoteAddr)
	port, _ := strconv.Atoi(portStr)

	sessionID := fmt.Sprintf("tarpit-%s-%d", host, time.Now().UnixNano())
	session := &TarpitSession{
		ID:            sessionID,
		RemoteIP:      host,
		RemotePort:    port,
		Service:       service,
		ConnectedAtMs: time.Now().UnixMilli(),
		Status:        "TRAPPED",
	}

	t.mu.Lock()
	t.activeSessions[sessionID] = session
	t.mu.Unlock()

	atomic.AddUint64(&t.connectionsHold, 1)
	log.Printf("[TARPIT] 🪤 Trapped attacking socket from %s:%d (Holding in Zero-Window Tarpit)", host, port)

	if t.onTrap != nil {
		go t.onTrap(*session)
	}

	// Fake banners to tease scanners
	var banner string
	if service == "SSH_DECEPTION" || service == "SSH" {
		banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
	} else {
		banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"
	}

	// Send 1 byte every 15-30 seconds to prevent TCP RST/timeout while tying up attacker thread
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	bannerBytes := []byte(banner)
	byteIdx := 0

	for {
		select {
		case <-ticker.C:
			var sendByte byte = '.'
			if byteIdx < len(bannerBytes) {
				sendByte = bannerBytes[byteIdx]
				byteIdx++
			}

			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write([]byte{sendByte})
			if err != nil {
				// Attacker aborted socket
				t.mu.Lock()
				session.Status = "RELEASED"
				session.DurationSec = (time.Now().UnixMilli() - session.ConnectedAtMs) / 1000
				delete(t.activeSessions, sessionID)
				t.mu.Unlock()
				return
			}

			atomic.AddUint64(&t.totalBytesSent, 1)
			atomic.AddUint64(&t.secondsDrained, 15)
			session.BytesTransferred++
			session.DurationSec = (time.Now().UnixMilli() - session.ConnectedAtMs) / 1000

		case <-t.stopChan:
			return
		}
	}
}

func (t *TarpitEngine) statsTicker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now().UnixMilli()
			for _, s := range t.activeSessions {
				s.DurationSec = (now - s.ConnectedAtMs) / 1000
			}
			t.mu.Unlock()
		}
	}
}

// GetActiveSessions returns current trapped connection records.
func (t *TarpitEngine) GetActiveSessions() []TarpitSession {
	t.mu.RLock()
	defer t.mu.RUnlock()

	res := make([]TarpitSession, 0, len(t.activeSessions))
	for _, s := range t.activeSessions {
		res = append(res, *s)
	}
	return res
}

// GetStats returns telemetry metrics for the Tarpit engine.
func (t *TarpitEngine) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"active_trapped_sockets": len(t.activeSessions),
		"total_connections_held": atomic.LoadUint64(&t.connectionsHold),
		"total_bytes_drained":    atomic.LoadUint64(&t.totalBytesSent),
		"total_seconds_drained":  atomic.LoadUint64(&t.secondsDrained),
	}
}

// Close terminates the tarpit listener.
func (t *TarpitEngine) Close() error {
	close(t.stopChan)
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}
