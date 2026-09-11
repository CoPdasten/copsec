package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/copsec/collector/internal/dpi"
)

/*
====================================================================================================
TRANSPARENT REVERSE-PROXY / TLS DECRYPTION MIRRORING SPECIFICATION & CONFIGURATION RECIPES
====================================================================================================

Architecture Overview:
----------------------
In modern enterprise environments, TLS traffic is typically terminated at an edge reverse-proxy
(Nginx, HAProxy, Envoy, or Cloudflare Tunnel) before reaching upstream microservices.
Because hardware-accelerated eBPF / XDP operates at Layer 3/4 on the raw NIC wire, payload inspection
on ciphertext would see encrypted TLS records.

CoPSeC provides zero-overhead Decryption Mirroring:
The reverse-proxy terminates TLS, generates a mirror copy of the decrypted plaintext HTTP request,
and tees it over a high-throughput Unix Domain Socket (/run/copsec/mirror.sock) straight into the
Layer 7 DPI & Machine Learning engine.

Originating Client IP Attribution:
----------------------------------
Originating real client IPs are preserved via:
1. PROXY Protocol v2 (Binary 16-byte signature + IPv4/IPv6 address block)
2. PROXY Protocol v1 (Textual: "PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n")
3. Standard HTTP Headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, True-Client-IP)

If an exploit is detected in the decrypted mirror:
The real client IP is IMMEDIATELY banned in the host kernel eBPF xdp_drop_map, causing instant
line-rate NIC driver drop (XDP_DROP) for all subsequent frames from that IP before TLS handshakes.

----------------------------------------------------------------------------------------------------
1. NGINX PRODUCTION MIRROR CONFIGURATION (/etc/nginx/conf.d/copsec_mirror.conf)
----------------------------------------------------------------------------------------------------
http {
    upstream copsec_unix_mirror {
        server unix:/run/copsec/mirror.sock;
    }

    server {
        listen 443 ssl http2;
        server_name api.corporate.banking;

        ssl_certificate     /etc/ssl/certs/corporate.crt;
        ssl_certificate_key /etc/ssl/private/corporate.key;

        location / {
            # Mirror inbound request body and headers to CoPSeC DPI engine
            mirror /mirror_copsec;
            mirror_request_body on;

            proxy_pass http://backend_cluster;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /mirror_copsec {
            internal;
            proxy_pass http://copsec_unix_mirror;
            proxy_pass_request_body on;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_connect_timeout 50ms;
            proxy_read_timeout 50ms;
        }
    }
}

----------------------------------------------------------------------------------------------------
2. HAPROXY PRODUCTION SPOE / MIRROR CONFIGURATION (/etc/haproxy/haproxy.cfg)
----------------------------------------------------------------------------------------------------
frontend https_in
    bind :443 ssl crt /etc/ssl/certs/bundle.pem
    mode http
    option forwardfor
    # Mirror decrypted payload via tee to UNIX socket
    http-request send-spoe-group copsec-dpi copsec-req-group
    default_backend web_cluster

----------------------------------------------------------------------------------------------------
3. ENVOY TAP FILTER MIRROR CONFIGURATION (envoy.yaml)
----------------------------------------------------------------------------------------------------
http_filters:
  - name: envoy.filters.http.tap
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.tap.v3.Tap
      common_config:
        static_config:
          match_config:
            any_match: true
          output_config:
            sinks:
              - format: JSON_BODY_AS_BYTES
                streaming_admin: {}
====================================================================================================
*/

const (
	// DefaultMirrorSocketPath is the primary Unix Domain Socket for proxy mirroring.
	DefaultMirrorSocketPath = "/run/copsec/mirror.sock"
	// FallbackMirrorSocketPath is the fallback path if /run is unprivileged.
	FallbackMirrorSocketPath = "/tmp/copsec_mirror.sock"
)

// TLSMirrorServer receives decrypted HTTP traffic mirrored from reverse-proxies via Unix sockets.
type TLSMirrorServer struct {
	mu                sync.RWMutex
	socketPath        string
	listener          net.Listener
	inspector         *dpi.DPIInspector
	stopChan          chan struct{}
	running           bool
	packetsProcessed  uint64
	threatsDetected   uint64
	customInspectHook func(payload []byte, clientIP string) dpi.InspectionResult
}

// NewTLSMirrorServer creates a new decryption mirror ingress listener.
func NewTLSMirrorServer(socketPath string, inspector ...*dpi.DPIInspector) *TLSMirrorServer {
	if socketPath == "" {
		socketPath = DefaultMirrorSocketPath
	}

	var insp *dpi.DPIInspector
	if len(inspector) > 0 && inspector[0] != nil {
		insp = inspector[0]
	} else {
		insp = dpi.GetDefaultInspector()
	}

	return &TLSMirrorServer{
		socketPath: socketPath,
		inspector:  insp,
		stopChan:   make(chan struct{}),
	}
}

// Start opens the Unix domain socket and begins receiving mirrored plaintext streams.
func (s *TLSMirrorServer) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}

	cleanPath := s.socketPath
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		cleanPath = FallbackMirrorSocketPath
		s.socketPath = cleanPath
		_ = os.MkdirAll(filepath.Dir(cleanPath), 0755)
	}

	// Remove stale socket file if present
	_ = os.Remove(cleanPath)

	l, err := net.Listen("unix", cleanPath)
	if err != nil {
		// Fallback to /tmp if permission denied on /run
		cleanPath = FallbackMirrorSocketPath
		s.socketPath = cleanPath
		_ = os.Remove(cleanPath)
		l, err = net.Listen("unix", cleanPath)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to bind TLS mirror socket at %s: %w", cleanPath, err)
		}
	}

	// Set socket file permissions so proxy workers (www-data, nginx, haproxy) can write
	_ = os.Chmod(cleanPath, 0666)

	s.listener = l
	s.running = true
	s.mu.Unlock()

	log.Printf("[DPI_MIRROR] 🪞 Decryption Mirror Ingress listening on UNIX socket: %s (Mode: 0666)", cleanPath)

	go s.acceptLoop(ctx)
	return nil
}

// Stop cleanly terminates the mirror socket listener.
func (s *TLSMirrorServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}

	s.running = false
	close(s.stopChan)
	if s.listener != nil {
		_ = s.listener.Close()
		_ = os.Remove(s.socketPath)
	}
	return nil
}

func (s *TLSMirrorServer) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			_ = s.Stop()
			return
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			case <-ctx.Done():
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		go s.handleMirrorConnection(conn)
	}
}

// handleMirrorConnection processes a mirrored connection from the proxy.
func (s *TLSMirrorServer) handleMirrorConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	bufReader := bufio.NewReader(conn)
	rawBuffer := make([]byte, 0, 4096)
	temp := make([]byte, 4096)

	for {
		n, err := bufReader.Read(temp)
		if n > 0 {
			rawBuffer = append(rawBuffer, temp[:n]...)
			// Cap max inspection buffer to 64KB
			if len(rawBuffer) >= 65536 {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		// If read less than buffer capacity, we have the complete HTTP request
		if n < len(temp) {
			break
		}
	}

	if len(rawBuffer) == 0 {
		return
	}

	atomic.AddUint64(&s.packetsProcessed, 1)

	// 1. Extract Real Originating Client IP
	realClientIP, payload := ExtractClientIPAndPayload(rawBuffer)

	// 2. Feed Mirrored Decrypted Payload into Layer 7 DPI Engine
	var result dpi.InspectionResult
	if s.customInspectHook != nil {
		result = s.customInspectHook(payload, realClientIP)
	} else if s.inspector != nil {
		result = s.inspector.InspectPacketWithIP(payload, realClientIP)
	}

	if result.Verdict == dpi.VerdictDrop || result.Verdict == dpi.VerdictTarpit {
		atomic.AddUint64(&s.threatsDetected, 1)
		log.Printf("[DPI_MIRROR] 🚨 Exploit detected in decrypted TLS mirror from %s! Verdict: %s (Reason: %s, Score: %.2f)",
			realClientIP, result.Verdict, result.Reason, result.Score)
	}
}

// ExtractClientIPAndPayload extracts the originating client IP from PROXY v1/v2 headers
// or standard HTTP forwarding headers (X-Forwarded-For, X-Real-IP).
func ExtractClientIPAndPayload(buffer []byte) (string, []byte) {
	if len(buffer) == 0 {
		return "192.168.1.100", buffer
	}

	// 1. Check PROXY Protocol v2 Binary Header
	// Header signature: \x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a
	v2Sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if len(buffer) >= 16 && bytes.HasPrefix(buffer, v2Sig) {
		cmdAndFamily := buffer[12]
		transportAndProto := buffer[13]
		addrLen := binary.BigEndian.Uint16(buffer[14:16])

		// Verify command is PROXY (0x21) or LOCAL
		if (cmdAndFamily & 0x0F) == 0x01 { // PROXY command
			family := transportAndProto & 0xF0
			if family == 0x10 && addrLen >= 12 && len(buffer) >= int(16+addrLen) { // IPv4
				srcIP := net.IP(buffer[16:20]).String()
				payload := buffer[16+addrLen:]
				return srcIP, payload
			} else if family == 0x20 && addrLen >= 36 && len(buffer) >= int(16+addrLen) { // IPv6
				srcIP := net.IP(buffer[16:32]).String()
				payload := buffer[16+addrLen:]
				return srcIP, payload
			}
		}
		if len(buffer) >= int(16+addrLen) {
			buffer = buffer[16+addrLen:]
		}
	}

	// 2. Check PROXY Protocol v1 Text Header ("PROXY TCP4 ...")
	if bytes.HasPrefix(buffer, []byte("PROXY ")) {
		crlfIdx := bytes.Index(buffer, []byte("\r\n"))
		if crlfIdx > 0 {
			line := string(buffer[:crlfIdx])
			parts := strings.Split(line, " ")
			if len(parts) >= 6 && (parts[1] == "TCP4" || parts[1] == "TCP6") {
				parsedIP := net.ParseIP(parts[2])
				if parsedIP != nil {
					return parts[2], buffer[crlfIdx+2:]
				}
			}
			buffer = buffer[crlfIdx+2:]
		}
	}

	// 3. Check Standard HTTP Forwarding Headers
	clientIP := extractHTTPHeaderIP(buffer)
	if clientIP != "" {
		return clientIP, buffer
	}

	return "192.168.1.100", buffer
}

// extractHTTPHeaderIP scans HTTP headers for X-Forwarded-For, X-Real-IP, CF-Connecting-IP, True-Client-IP.
func extractHTTPHeaderIP(data []byte) string {
	headerLimit := bytes.Index(data, []byte("\r\n\r\n"))
	if headerLimit == -1 {
		headerLimit = len(data)
	}
	headers := string(data[:headerLimit])

	candidates := []string{
		"x-forwarded-for:",
		"x-real-ip:",
		"cf-connecting-ip:",
		"true-client-ip:",
	}

	for _, cand := range candidates {
		idx := strings.Index(strings.ToLower(headers), cand)
		if idx >= 0 {
			lineEnd := strings.Index(headers[idx:], "\r\n")
			var rawVal string
			if lineEnd >= 0 {
				rawVal = headers[idx+len(cand) : idx+lineEnd]
			} else {
				rawVal = headers[idx+len(cand):]
			}

			// In X-Forwarded-For, comma-separated list; first entry is the real client
			for _, part := range strings.Split(rawVal, ",") {
				clean := strings.TrimSpace(part)
				parsed := net.ParseIP(clean)
				if parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
					return clean
				}
			}
		}
	}

	return ""
}

// GetStats returns telemetry counters for the decryption mirror ingress.
func (s *TLSMirrorServer) GetStats() (uint64, uint64) {
	return atomic.LoadUint64(&s.packetsProcessed), atomic.LoadUint64(&s.threatsDetected)
}

// SetInspectHook allows test suites to mock DPI inspection.
func (s *TLSMirrorServer) SetInspectHook(hook func(payload []byte, clientIP string) dpi.InspectionResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customInspectHook = hook
}
