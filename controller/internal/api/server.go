package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultLocalhostBind = "127.0.0.1"
	DefaultCockpitPort   = 8080
)

// ServerConfig specifies the Zero-Trust listener configuration.
type ServerConfig struct {
	BindAddr      string        // Explicit IP (Default: "127.0.0.1", strictly never "0.0.0.0")
	BindInterface string        // Network interface name (e.g. "tailscale0", "wg0", "lo")
	Port          int           // Cockpit port (Default: 8080)
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
}

// ZeroTrustServer manages the cloaked Web SOC Cockpit HTTP listener.
type ZeroTrustServer struct {
	httpServer   *http.Server
	listener     net.Listener
	resolvedAddr string
}

// ResolveListenerAddress dynamically resolves the primary IPv4 address adhering to Zero-Trust rules.
func ResolveListenerAddress(cfg ServerConfig) (string, error) {
	port := cfg.Port
	if port <= 0 || port > 65535 {
		port = DefaultCockpitPort
	}

	// 1. Interface-Specific Auto-Resolution (e.g., tailscale0, wg0)
	targetIface := strings.TrimSpace(cfg.BindInterface)
	if targetIface == "" {
		targetIface = strings.TrimSpace(os.Getenv("COPSEC_BIND_INTERFACE"))
	}

	if targetIface != "" {
		iface, err := net.InterfaceByName(targetIface)
		if err != nil {
			return "", fmt.Errorf("zero-trust fail-closed: interface '%s' not found: %w", targetIface, err)
		}

		if (iface.Flags & net.FlagUp) == 0 {
			return "", fmt.Errorf("zero-trust fail-closed: interface '%s' is down", targetIface)
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("failed to query addresses for interface '%s': %w", targetIface, err)
		}

		var selectedIPv4 net.IP
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil {
				selectedIPv4 = ip.To4()
				break
			}
		}

		if selectedIPv4 == nil {
			return "", fmt.Errorf("zero-trust fail-closed: interface '%s' has no valid IPv4 address assigned", targetIface)
		}

		resolved := net.JoinHostPort(selectedIPv4.String(), strconv.Itoa(port))
		log.Printf("[ZERO_TRUST] 🔒 Bound strictly to interface '%s' -> %s", targetIface, resolved)
		return resolved, nil
	}

	// 2. Explicit IP Binding Resolution
	bindAddr := strings.TrimSpace(cfg.BindAddr)
	if bindAddr == "" {
		bindAddr = strings.TrimSpace(os.Getenv("COPSEC_BIND_ADDR"))
	}
	if bindAddr == "" {
		bindAddr = DefaultLocalhostBind
	}

	// Zero-Trust Enforcer: Prohibit Wildcard 0.0.0.0 Binding
	if bindAddr == "0.0.0.0" || strings.HasPrefix(bindAddr, "0.0.0.0:") || bindAddr == "::" {
		return "", errors.New("zero-trust policy violation: wildcard binding (0.0.0.0) is strictly prohibited. Bind to 127.0.0.1 or a management VPN interface (tailscale0)")
	}

	var hostPart string
	if strings.Contains(bindAddr, ":") {
		h, p, err := net.SplitHostPort(bindAddr)
		if err == nil {
			hostPart = h
			if customPort, pErr := strconv.Atoi(p); pErr == nil && customPort > 0 {
				port = customPort
			}
		} else {
			hostPart = bindAddr
		}
	} else {
		hostPart = bindAddr
	}

	if hostPart == "0.0.0.0" || hostPart == "" {
		return "", errors.New("zero-trust policy violation: host cannot be 0.0.0.0 or empty")
	}

	parsedIP := net.ParseIP(hostPart)
	if parsedIP == nil && hostPart != "localhost" {
		return "", fmt.Errorf("invalid bind IP address: %s", hostPart)
	}

	resolved := net.JoinHostPort(hostPart, strconv.Itoa(port))
	log.Printf("[ZERO_TRUST] 🔒 Cloaked Web SOC Cockpit listening on %s (External Scanners Receive ZERO TCP Response)", resolved)
	return resolved, nil
}

// NewZeroTrustServer instantiates and binds the hardened Web SOC Cockpit HTTP server.
func NewZeroTrustServer(cfg ServerConfig, handler http.Handler) (*ZeroTrustServer, error) {
	resolvedAddr, err := ResolveListenerAddress(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Zero-Trust binding: %w", err)
	}

	// Bind TCP listener immediately to verify socket ownership
	listener, err := net.Listen("tcp", resolvedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind TCP socket on %s: %w", resolvedAddr, err)
	}

	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 10 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 15 * time.Second
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	return &ZeroTrustServer{
		httpServer:   srv,
		listener:     listener,
		resolvedAddr: resolvedAddr,
	}, nil
}

// Start initiates non-blocking HTTP serving.
func (s *ZeroTrustServer) Start() error {
	go func() {
		if err := s.httpServer.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[FATAL] Zero-Trust Web Cockpit terminated unexpectedly: %v", err)
			os.Exit(1)
		}
	}()
	return nil
}

// GetListenAddr returns the active listening address.
func (s *ZeroTrustServer) GetListenAddr() string {
	return s.resolvedAddr
}

// Shutdown gracefully terminates the HTTP server.
func (s *ZeroTrustServer) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
