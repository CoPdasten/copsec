package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NodeIdentity represents the persistent cryptographic identity of the edge agent.
type NodeIdentity struct {
	NodeID    string `json:"node_id"`
	APIKey    string `json:"api_key"`
	Hostname  string `json:"hostname,omitempty"`
	Group     string `json:"group,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// IdentityManager manages agent auto-enrollment and gRPC auth metadata credentials.
type IdentityManager struct {
	mu       sync.RWMutex
	filePath string
	identity NodeIdentity
}

// LoadOrCreateIdentity initializes or auto-enrolls the agent identity with 0600 permissions.
func LoadOrCreateIdentity(path string) (*IdentityManager, error) {
	mgr := &IdentityManager{filePath: path}

	// Try loading existing identity
	data, err := os.ReadFile(path)
	if err == nil {
		var id NodeIdentity
		if err := json.Unmarshal(data, &id); err == nil && id.NodeID != "" && id.APIKey != "" {
			if id.Group == "" {
				id.Group = "DEFAULT_EDGE"
			}
			mgr.identity = id
			log.Printf("[INFO] Loaded existing agent identity: NodeID=%s Group=%s", id.NodeID, id.Group)
			return mgr, nil
		}
	}

	// Generate new random cryptographic identity
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	nodeID := fmt.Sprintf("node-vps-%s", hex.EncodeToString(randBytes))

	keyBytes := make([]byte, 24)
	_, _ = rand.Read(keyBytes)
	apiKey := fmt.Sprintf("cps_live_%s", hex.EncodeToString(keyBytes))

	hostname, _ := os.Hostname()

	mgr.identity = NodeIdentity{
		NodeID:    nodeID,
		APIKey:    apiKey,
		Hostname:  hostname,
		Group:     "DEFAULT_EDGE",
		CreatedAt: time.Now().UnixMilli(),
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		// Fallback to local ./node.json if system directory cannot be created
		path = "./node.json"
		mgr.filePath = path
	}

	payload, err := json.MarshalIndent(mgr.identity, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node identity: %w", err)
	}

	// Save with strict 0600 file permissions
	if err := os.WriteFile(path, payload, 0600); err != nil {
		return nil, fmt.Errorf("failed to write identity file %s: %w", path, err)
	}

	log.Printf("[INFO] Auto-enrolled new node identity: NodeID=%s, File=%s (Mode: 0600)", nodeID, path)
	return mgr, nil
}

// GetNodeID returns the active node identifier.
func (m *IdentityManager) GetNodeID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.identity.NodeID
}

// GetAPIKey returns the active node API authentication key.
func (m *IdentityManager) GetAPIKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.identity.APIKey
}

// GetGroup returns the fleet cluster group name.
func (m *IdentityManager) GetGroup() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.identity.Group == "" {
		return "DEFAULT_EDGE"
	}
	return m.identity.Group
}

// GetRequestMetadata implements grpc credentials.PerRPCCredentials interface.
func (m *IdentityManager) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]string{
		"x-node-id":    m.identity.NodeID,
		"x-api-key":    m.identity.APIKey,
		"x-node-group": m.GetGroup(),
	}, nil
}

// RequireTransportSecurity implements grpc credentials.PerRPCCredentials interface.
func (m *IdentityManager) RequireTransportSecurity() bool {
	return false // Allows secure Tailscale VPN transport without requiring mandatory TLS
}
