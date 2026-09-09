package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// TLSConfig defines the client-side mTLS mutual authentication assets.
type TLSConfig struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	ServerName     string // Optional SNI override
}

// BuildSecureClientConn constructs a hardened, mTLS-secured gRPC connection.
// It enforces TLS 1.3 minimum, validates the Root CA trust chain, and presents
// node-specific client certificates for mutual cryptographic identity.
func BuildSecureClientConn(
	ctx context.Context,
	targetEndpoint string,
	tlsCfg TLSConfig,
	perRPCCreds credentials.PerRPCCredentials,
) (*grpc.ClientConn, error) {
	cleanEndpoint := strings.TrimSpace(targetEndpoint)
	if cleanEndpoint == "" {
		return nil, fmt.Errorf("gRPC target endpoint cannot be empty")
	}

	// 1. Load Trusted Root CA Certificate Pool
	if tlsCfg.CACertPath == "" {
		return nil, fmt.Errorf("missing CA certificate path in TLSConfig")
	}
	caPEM, err := os.ReadFile(tlsCfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Root CA cert from %s: %w", tlsCfg.CACertPath, err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse valid PEM certificates from Root CA %s", tlsCfg.CACertPath)
	}

	// 2. Load Node-Specific Client X.509 Keypair (Mutual Authentication)
	if tlsCfg.ClientCertPath == "" || tlsCfg.ClientKeyPath == "" {
		return nil, fmt.Errorf("missing client certificate or private key path in TLSConfig")
	}
	clientCert, err := tls.LoadX509KeyPair(tlsCfg.ClientCertPath, tlsCfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client keypair (%s, %s): %w", tlsCfg.ClientCertPath, tlsCfg.ClientKeyPath, err)
	}

	// 3. Configure Strict TLS 1.3 Client Security Profile
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   tlsCfg.ServerName,
	}

	transportCreds := credentials.NewTLS(tlsConfig)

	// 4. Production Keepalive & Heartbeat Parameters
	keepaliveOpts := grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10 * time.Second, // Send ping every 10s if no activity
		Timeout:             3 * time.Second,  // Wait 3s for ping ack before disconnecting
		PermitWithoutStream: true,             // Allow pings even without active RPC streams
	})

	// 5. Assemble gRPC Dial Options
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		keepaliveOpts,
		grpc.WithBlock(),
	}

	if perRPCCreds != nil {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(perRPCCreds))
	}

	// Dial with context-bounded timeout
	conn, err := grpc.DialContext(ctx, cleanEndpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to establish secure mTLS gRPC connection to %s: %w", cleanEndpoint, err)
	}

	return conn, nil
}
