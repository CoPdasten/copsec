package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// EdgeMitigationProvider defines the pluggable interface for upstream SDN and edge perimeter routers.
type EdgeMitigationProvider interface {
	Name() string
	EnforceEdgeDrop(ctx context.Context, ip string, durationSeconds int64) error
	ReleaseEdgeDrop(ctx context.Context, ip string) error
}

// BGPFlowspecDriver programs Linux kernel IP routing blackholes and BGP Flowspec entries.
type BGPFlowspecDriver struct {
	mu sync.RWMutex
}

// NewBGPFlowspecDriver creates a driver using Linux IP-Route blackhole routing.
func NewBGPFlowspecDriver() *BGPFlowspecDriver {
	return &BGPFlowspecDriver{}
}

func (d *BGPFlowspecDriver) Name() string {
	return "BGP_FLOWSPEC_LINUX_IPROUTE"
}

func (d *BGPFlowspecDriver) EnforceEdgeDrop(ctx context.Context, ip string, durationSeconds int64) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || isProtectedIP(cleanIP) {
		return fmt.Errorf("invalid or protected ip: %s", cleanIP)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Linux Kernel Route Blackholing: `ip route add blackhole <ip>/32`
	cidr := cleanIP
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Delete pre-existing route if present to avoid EEXIST
	_ = exec.CommandContext(ctx, "sudo", "ip", "route", "del", "blackhole", cidr).Run()

	cmd := exec.CommandContext(ctx, "sudo", "ip", "route", "add", "blackhole", cidr)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		log.Printf("[SDN_ROUTER] ⚠️ IP-Route blackhole command output: %s (err: %v)", string(out), err)
		return err
	}

	log.Printf("[SDN_ROUTER] ⚡ BGP/IP-Route Blackhole Enforced on %s (Duration: %ds)", cidr, durationSeconds)
	return nil
}

func (d *BGPFlowspecDriver) ReleaseEdgeDrop(ctx context.Context, ip string) error {
	cleanIP := strings.TrimSpace(ip)
	d.mu.Lock()
	defer d.mu.Unlock()

	cidr := cleanIP
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	_ = exec.CommandContext(ctx, "sudo", "ip", "route", "del", "blackhole", cidr).Run()
	log.Printf("[SDN_ROUTER] 🟢 BGP/IP-Route Blackhole Released for %s", cidr)
	return nil
}

// CloudEdgeSecurityGroupDriver dispatches perimeter drops to upstream Cloud Firewall / SDN endpoints.
type CloudEdgeSecurityGroupDriver struct {
	endpointURL string
	apiKey      string
	httpClient  *http.Client
	mu          sync.RWMutex
}

// NewCloudEdgeSecurityGroupDriver creates a driver that dispatches drops to an upstream REST edge API.
func NewCloudEdgeSecurityGroupDriver(endpointURL, apiKey string) *CloudEdgeSecurityGroupDriver {
	return &CloudEdgeSecurityGroupDriver{
		endpointURL: endpointURL,
		apiKey:      apiKey,
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

func (c *CloudEdgeSecurityGroupDriver) Name() string {
	return "CLOUD_EDGE_SECURITY_GROUP"
}

func (c *CloudEdgeSecurityGroupDriver) EnforceEdgeDrop(ctx context.Context, ip string, durationSeconds int64) error {
	cleanIP := strings.TrimSpace(ip)
	if c.endpointURL == "" {
		// Mock / Simulation mode when URL is not configured
		log.Printf("[SDN_ROUTER] ☁️ [MOCK] Cloud Edge Security Group rule dispatched: DROP %s (Duration: %ds)", cleanIP, durationSeconds)
		return nil
	}

	payload := map[string]interface{}{
		"action":           "BLOCK_IP",
		"target_ip":        cleanIP,
		"duration_seconds": durationSeconds,
		"rule_name":        "CoPSeC-Autonomous-SDN-Drop",
		"timestamp_ms":     time.Now().UnixMilli(),
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpointURL+"/api/v1/firewall/rules", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[SDN_ROUTER] ⚠️ Upstream Edge SDN dispatch error: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("upstream edge responded with HTTP %d", resp.StatusCode)
	}

	log.Printf("[SDN_ROUTER] ☁️ Cloud Edge Security Group drop successfully synced: %s", cleanIP)
	return nil
}

func (c *CloudEdgeSecurityGroupDriver) ReleaseEdgeDrop(ctx context.Context, ip string) error {
	cleanIP := strings.TrimSpace(ip)
	if c.endpointURL == "" {
		log.Printf("[SDN_ROUTER] ☁️ [MOCK] Cloud Edge Security Group release dispatched: ALLOW %s", cleanIP)
		return nil
	}

	payload := map[string]interface{}{
		"action":       "UNBLOCK_IP",
		"target_ip":    cleanIP,
		"timestamp_ms": time.Now().UnixMilli(),
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpointURL+"/api/v1/firewall/rules/release", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// SDNRouter orchestrates multi-driver upstream edge and BGP blackhole programming.
type SDNRouter struct {
	mu        sync.RWMutex
	providers []EdgeMitigationProvider
}

var (
	defaultSDNRouter *SDNRouter
	sdnOnce          sync.Once
)

// GetDefaultSDNRouter returns the singleton SDN router.
func GetDefaultSDNRouter() *SDNRouter {
	sdnOnce.Do(func() {
		defaultSDNRouter = NewSDNRouter()
		defaultSDNRouter.RegisterProvider(NewBGPFlowspecDriver())
		defaultSDNRouter.RegisterProvider(NewCloudEdgeSecurityGroupDriver("", ""))
	})
	return defaultSDNRouter
}

// NewSDNRouter creates a new SDNRouter coordinator.
func NewSDNRouter() *SDNRouter {
	return &SDNRouter{
		providers: make([]EdgeMitigationProvider, 0),
	}
}

// RegisterProvider registers an edge SDN driver.
func (r *SDNRouter) RegisterProvider(provider EdgeMitigationProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, provider)
}

// EnforceEdgeDrop broadcasts the drop requirement to all registered upstream SDN drivers.
func (r *SDNRouter) EnforceEdgeDrop(ctx context.Context, ip string, durationSeconds int64) error {
	r.mu.RLock()
	drivers := append([]EdgeMitigationProvider(nil), r.providers...)
	r.mu.RUnlock()

	var lastErr error
	for _, driver := range drivers {
		if err := driver.EnforceEdgeDrop(ctx, ip, durationSeconds); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// ReleaseEdgeDrop broadcasts the unban requirement to all registered upstream SDN drivers.
func (r *SDNRouter) ReleaseEdgeDrop(ctx context.Context, ip string) error {
	r.mu.RLock()
	drivers := append([]EdgeMitigationProvider(nil), r.providers...)
	r.mu.RUnlock()

	var lastErr error
	for _, driver := range drivers {
		if err := driver.ReleaseEdgeDrop(ctx, ip); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
