package management

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	managementproto "github.com/copsec/collector/proto/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// DefaultManagementAddress binds to loopback interface to prevent unauthorized network exposure.
	DefaultManagementAddress = "127.0.0.1:50052"
	// DefaultManagementSocketPath is the standard Unix Domain Socket path for local IPC management.
	DefaultManagementSocketPath = "/var/run/copsec/mgmt.sock"
	// EnvManagementKey is the environment variable for the authoritative management secret.
	EnvManagementKey = "COPSEC_MGMT_KEY"
)

// Config holds runtime configuration for the hardened management gRPC endpoint.
type Config struct {
	// ListenAddr is the TCP address or Unix socket to listen on (default: 127.0.0.1:50052).
	ListenAddr string
	// SocketPath specifies an explicit Unix Domain Socket path if listening over UDS.
	SocketPath string
	// EnableRemoteMgmt explicitly permits binding to non-loopback / remote network interfaces.
	// Binding to 0.0.0.0 or public interfaces is strictly rejected unless this flag is true.
	EnableRemoteMgmt bool
	// AuthSecret is the authoritative pre-shared key or Bearer token.
	// If empty, it will be loaded from the COPSEC_MGMT_KEY environment variable.
	AuthSecret string
	// TLSCertFile is the path to the server TLS certificate PEM file.
	TLSCertFile string
	// TLSKeyFile is the path to the server TLS private key PEM file.
	TLSKeyFile string
	// ClientCAFile is the path to the trusted CA bundle for mutual TLS (mTLS) client verification.
	ClientCAFile string
	// RequireClientCert enforces mutual TLS (mTLS) where connecting clients must provide a valid certificate.
	RequireClientCert bool
}

// DefaultConfig returns safe production defaults restricted to the local loopback interface.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       DefaultManagementAddress,
		EnableRemoteMgmt: false,
		AuthSecret:       os.Getenv(EnvManagementKey),
	}
}

// IsLoopbackAddress evaluates whether a given address string is strictly bound to loopback or UDS.
func IsLoopbackAddress(addr string) bool {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "unix://") || strings.HasPrefix(trimmed, "/") {
		return true
	}

	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		host = trimmed
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback()
}

// ValidateConfig verifies that the management server configuration complies with zero-trust network boundaries.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("management config cannot be nil")
	}

	// Resolve auth secret from environment if not explicitly set
	if cfg.AuthSecret == "" {
		cfg.AuthSecret = strings.TrimSpace(os.Getenv(EnvManagementKey))
	}

	isUDS := cfg.SocketPath != "" || strings.HasPrefix(cfg.ListenAddr, "unix://") || strings.HasPrefix(cfg.ListenAddr, "/")
	isLoopback := isUDS || IsLoopbackAddress(cfg.ListenAddr)

	// Action 1: Disallow binding to 0.0.0.0, [::], or any non-loopback interface unless --enable-remote-mgmt is explicitly set.
	if !isLoopback && !cfg.EnableRemoteMgmt {
		return fmt.Errorf("binding management service to non-loopback address %q is rejected for security: "+
			"management port :50052 must not be exposed without explicit --enable-remote-mgmt", cfg.ListenAddr)
	}

	// Action 3: Enforce TLS 1.3 for all non-loopback management connections
	if !isLoopback && cfg.EnableRemoteMgmt {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return fmt.Errorf("remote management enabled on %q but TLS certificates not configured: "+
				"all non-loopback management connections strictly require TLS 1.3 (--mgmt-tls-cert and --mgmt-tls-key)", cfg.ListenAddr)
		}
	}

	return nil
}

// NewAuthInterceptor builds gRPC Unary and Stream server interceptors that enforce Bearer token / PSK authentication.
func NewAuthInterceptor(authSecret string) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	secretBytes := []byte(authSecret)

	validateToken := func(ctx context.Context) error {
		if len(secretBytes) == 0 {
			// If no secret configured, reject all calls to avoid unauthenticated access
			return status.Errorf(codes.Unauthenticated, "management authentication failed: no authoritative secret configured on server")
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Errorf(codes.Unauthenticated, "management authentication failed: missing request metadata")
		}

		// Check 'authorization' header (Bearer <token>)
		var providedToken string
		if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
			raw := strings.TrimSpace(authHeaders[0])
			if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
				providedToken = strings.TrimSpace(raw[7:])
			} else {
				providedToken = raw
			}
		}

		// Fallback to 'x-mgmt-token' or 'copsec-mgmt-secret'
		if providedToken == "" {
			if tokens := md.Get("x-mgmt-token"); len(tokens) > 0 {
				providedToken = strings.TrimSpace(tokens[0])
			} else if secrets := md.Get("copsec-mgmt-secret"); len(secrets) > 0 {
				providedToken = strings.TrimSpace(secrets[0])
			}
		}

		if providedToken == "" {
			return status.Errorf(codes.Unauthenticated, "management authentication failed: missing Bearer token or management secret")
		}

		// Constant-time comparison to prevent timing side-channel attacks
		if subtle.ConstantTimeCompare([]byte(providedToken), secretBytes) != 1 {
			return status.Errorf(codes.Unauthenticated, "management authentication failed: invalid management credentials")
		}

		return nil
	}

	unaryInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := validateToken(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}

	streamInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateToken(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}

	return unaryInterceptor, streamInterceptor
}

// NewUnaryAuthInterceptor builds a dedicated gRPC UnaryServerInterceptor enforcing pre-shared Bearer token authentication.
func NewUnaryAuthInterceptor(authSecret string) grpc.UnaryServerInterceptor {
	unary, _ := NewAuthInterceptor(authSecret)
	return unary
}

// NewTLSConfig constructs a hardened TLS 1.3 configuration with optional mutual TLS (mTLS) client validation.
func NewTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, errors.New("TLS certificate or private key path is empty")
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Enforce TLS 1.3 as absolute minimum and maximum baseline
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	// Configure mutual TLS (mTLS) client verification if Client CA provided
	if cfg.ClientCAFile != "" || cfg.RequireClientCert {
		if cfg.ClientCAFile == "" {
			return nil, errors.New("mTLS client verification requested but client CA file (--mgmt-tls-ca) was not provided")
		}

		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("failed to parse valid CA certificates from client CA file")
		}

		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// Server encapsulates the hardened gRPC SensorManagementService server.
type Server struct {
	grpcServer   *grpc.Server
	listener     net.Listener
	cfg          *Config
	isUnixSocket bool
	sockPath     string
	stopOnce     sync.Once
}

// CreateListener allocates the network listener adhering to strict loopback / UDS / remote management boundaries.
func CreateListener(cfg *Config) (net.Listener, bool, string, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, false, "", err
	}

	// 1. Unix Domain Socket
	if cfg.SocketPath != "" || strings.HasPrefix(cfg.ListenAddr, "unix://") || strings.HasPrefix(cfg.ListenAddr, "/") {
		sockPath := cfg.SocketPath
		if sockPath == "" {
			sockPath = strings.TrimPrefix(cfg.ListenAddr, "unix://")
		}

		if err := os.MkdirAll(filepath.Dir(sockPath), 0750); err != nil {
			return nil, true, sockPath, fmt.Errorf("failed to create socket directory: %w", err)
		}

		// Clean up existing socket file if present
		if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
			return nil, true, sockPath, fmt.Errorf("failed to remove existing socket file %q: %w", sockPath, err)
		}

		lis, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, true, sockPath, fmt.Errorf("failed to listen on unix socket %q: %w", sockPath, err)
		}

		// Restrict socket file permissions to owner only (0600)
		if err := os.Chmod(sockPath, 0600); err != nil {
			_ = lis.Close()
			return nil, true, sockPath, fmt.Errorf("failed to restrict socket file permissions: %w", err)
		}

		return lis, true, sockPath, nil
	}

	// 2. TCP Listener
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, false, "", fmt.Errorf("failed to listen on tcp %q: %w", cfg.ListenAddr, err)
	}

	return lis, false, "", nil
}

// NewServer initializes a hardened SensorManagementService gRPC server.
func NewServer(cfg *Config, srv managementproto.SensorManagementServiceServer, extraOpts ...grpc.ServerOption) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid management configuration: %w", err)
	}

	lis, isUDS, sockPath, err := CreateListener(cfg)
	if err != nil {
		return nil, err
	}

	var serverOpts []grpc.ServerOption

	// Apply TLS 1.3 credentials if configured or required
	isLoopback := isUDS || IsLoopbackAddress(cfg.ListenAddr)
	if !isLoopback || cfg.TLSCertFile != "" {
		tlsConfig, err := NewTLSConfig(cfg)
		if err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("failed to configure TLS 1.3: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Apply token authentication interceptors
	unaryAuth, streamAuth := NewAuthInterceptor(cfg.AuthSecret)
	serverOpts = append(serverOpts, grpc.UnaryInterceptor(unaryAuth), grpc.StreamInterceptor(streamAuth))

	// Append caller options
	serverOpts = append(serverOpts, extraOpts...)

	grpcServer := grpc.NewServer(serverOpts...)
	managementproto.RegisterSensorManagementServiceServer(grpcServer, srv)

	return &Server{
		grpcServer:   grpcServer,
		listener:     lis,
		cfg:          cfg,
		isUnixSocket: isUDS,
		sockPath:     sockPath,
	}, nil
}

// Start spawns the gRPC server in a background goroutine.
func (s *Server) Start() {
	go func() {
		log.Printf("[MANAGEMENT_GRPC] Hardened SensorManagementService actively serving on %s (TLS: %v, Auth: Enabled)",
			s.listener.Addr(), s.cfg.TLSCertFile != "")
		if err := s.grpcServer.Serve(s.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[MANAGEMENT_GRPC] Server exited with error: %v", err)
		}
	}()
}

// Stop gracefully terminates the management gRPC server and purges socket files if applicable.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.grpcServer != nil {
			s.grpcServer.Stop()
		}
		if s.isUnixSocket && s.sockPath != "" {
			_ = os.Remove(s.sockPath)
		}
	})
}

// GracefulStop gracefully drains existing connections before stopping.
func (s *Server) GracefulStop() {
	s.stopOnce.Do(func() {
		if s.grpcServer != nil {
			s.grpcServer.GracefulStop()
		}
		if s.isUnixSocket && s.sockPath != "" {
			_ = os.Remove(s.sockPath)
		}
	})
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// GRPCServer returns the underlying grpc.Server instance.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}
