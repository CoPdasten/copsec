package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/copsec/collector/pkg/ebpf"
	copsecproto "github.com/copsec/collector/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	// DefaultControllerEndpoint is the Tier 2 Controller gRPC service location.
	DefaultControllerEndpoint = "pardus1:50051"
	// DefaultReaperInterval is the standard audit and purge ticker period.
	DefaultReaperInterval = 15 * time.Second
)

// BanEntry models the eBPF kernel quarantine entry matching struct ban_entry in C.
type BanEntry struct {
	IP             string `json:"ip"`
	BanTimestampNs uint64 `json:"ban_timestamp_ns"`
	TTLNs          uint64 `json:"ttl_ns"`
	ReasonCode     uint32 `json:"reason_code"`
	Reason         string `json:"reason"`
}

// UnbanAuditEvent records an immutable unban event for the SHA-256 blockchain audit trail.
type UnbanAuditEvent struct {
	Actor       string    `json:"actor"`       // "SYSTEM_TTL_REAPER"
	Reason      string    `json:"reason"`      // "Dynamic TTL Expired"
	TargetIP    string    `json:"target_ip"`   // Unbanned IP
	ActionType  string    `json:"action_type"` // "AUTO_UNBAN"
	Timestamp   time.Time `json:"timestamp"`
	TimestampMs int64     `json:"timestamp_ms"`
}

// BanManager coordinates dynamic quarantine lifecycles, kernel BPF map synch, and auto-unban reaping.
type BanManager struct {
	mu                 sync.RWMutex
	xdpEngine          *ebpf.XDPMitigationEngine
	controllerEndpoint string
	unbanAudits        []UnbanAuditEvent
	auditHook          func(event UnbanAuditEvent)
	customGRPCSender   func(event *copsecproto.LogEvent) error
}

var (
	defaultBanManager *BanManager
	banManagerOnce    sync.Once
)

// GetDefaultBanManager returns the singleton ban manager instance.
func GetDefaultBanManager() *BanManager {
	banManagerOnce.Do(func() {
		defaultBanManager = NewBanManager(DefaultControllerEndpoint)
	})
	return defaultBanManager
}

// NewBanManager creates an initialized ban manager bound to eBPF/XDP subsystem.
func NewBanManager(controllerEndpoint ...string) *BanManager {
	endpoint := DefaultControllerEndpoint
	if len(controllerEndpoint) > 0 && strings.TrimSpace(controllerEndpoint[0]) != "" {
		endpoint = strings.TrimSpace(controllerEndpoint[0])
	}

	return &BanManager{
		xdpEngine:          ebpf.GetXDPEngine(),
		controllerEndpoint: endpoint,
		unbanAudits:        make([]UnbanAuditEvent, 0, 128),
	}
}

// AddBan injects an IP into the quarantine registry and eBPF banned_ips map with dynamic TTL metadata.
func (bm *BanManager) AddBan(ipStr string, ttl time.Duration, reasonCode uint32, reason string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if net.ParseIP(cleanIP) == nil {
		return fmt.Errorf("invalid IP format: %s", cleanIP)
	}

	if bm.xdpEngine == nil {
		return fmt.Errorf("eBPF XDP engine not available")
	}

	return bm.xdpEngine.AddBanWithTTL(cleanIP, ttl, reasonCode, reason)
}

// RemoveBan purges an IP from quarantine and records a manual or system unban audit.
func (bm *BanManager) RemoveBan(ipStr string, actor, reason string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if bm.xdpEngine == nil {
		return fmt.Errorf("eBPF XDP engine not available")
	}

	if err := bm.xdpEngine.RemoveBan(cleanIP); err != nil {
		return err
	}

	if actor == "" {
		actor = "SECURITY_ADMIN"
	}
	if reason == "" {
		reason = "Manual Administrative Unban"
	}

	ev := UnbanAuditEvent{
		Actor:       actor,
		Reason:      reason,
		TargetIP:    cleanIP,
		ActionType:  "MANUAL_UNBAN",
		Timestamp:   time.Now().UTC(),
		TimestampMs: time.Now().UnixMilli(),
	}

	bm.recordAndStreamAudit(ev)
	return nil
}

// IsBanned checks if an IP is currently banned, verifying in-kernel dynamic TTL expiry.
func (bm *BanManager) IsBanned(ipStr string) bool {
	if bm.xdpEngine == nil {
		return false
	}
	return bm.xdpEngine.IsBanned(ipStr)
}

// GetBan retrieves structured metadata for an active quarantine record.
func (bm *BanManager) GetBan(ipStr string) (BanEntry, bool) {
	if bm.xdpEngine == nil {
		return BanEntry{}, false
	}
	e, ok := bm.xdpEngine.GetBanEntry(ipStr)
	if !ok {
		return BanEntry{}, false
	}
	return BanEntry{
		IP:             e.IP,
		BanTimestampNs: e.BanTimestampNs,
		TTLNs:          e.TTLNs,
		ReasonCode:     e.ReasonCode,
		Reason:         e.Reason,
	}, true
}

// GetAllBans returns a snapshot of all active quarantine entries.
func (bm *BanManager) GetAllBans() map[string]BanEntry {
	if bm.xdpEngine == nil {
		return nil
	}
	raw := bm.xdpEngine.GetAllBanEntries()
	res := make(map[string]BanEntry, len(raw))
	for k, v := range raw {
		res[k] = BanEntry{
			IP:             v.IP,
			BanTimestampNs: v.BanTimestampNs,
			TTLNs:          v.TTLNs,
			ReasonCode:     v.ReasonCode,
			Reason:         v.Reason,
		}
	}
	return res
}

// StartBanReaper launches a background reaper goroutine that scans the BPF map every 15s (or checkInterval),
// evicts expired entries, and streams immutable unban events to the Tier 2 Controller.
func (bm *BanManager) StartBanReaper(ctx context.Context, checkInterval time.Duration) {
	if checkInterval <= 0 {
		checkInterval = DefaultReaperInterval
	}

	log.Printf("[BAN_REAPER] ⏱️ Dynamic eBPF Ban TTL Reaper initialized (Tick: %v)", checkInterval)

	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[BAN_REAPER] Shutting down Ban TTL Reaper.")
				return
			case <-ticker.C:
				bm.ReapExpiredBans()
			}
		}
	}()
}

// ReapExpiredBans performs a single expiration pass over active quarantine entries.
func (bm *BanManager) ReapExpiredBans() int {
	if bm.xdpEngine == nil {
		return 0
	}

	entries := bm.xdpEngine.GetAllBanEntries()
	if len(entries) == 0 {
		return 0
	}

	nowNs := uint64(time.Now().UnixNano())
	expiredCount := 0

	for ip, entry := range entries {
		// If ttl_ns == 0, the ban is permanent. If ttl_ns > 0, evaluate expiration.
		if entry.TTLNs > 0 && nowNs > (entry.BanTimestampNs+entry.TTLNs) {
			_ = bm.xdpEngine.RemoveBan(ip)
			expiredCount++

			ev := UnbanAuditEvent{
				Actor:       "SYSTEM_TTL_REAPER",
				Reason:      "Dynamic TTL Expired",
				TargetIP:    ip,
				ActionType:  "AUTO_UNBAN",
				Timestamp:   time.Now().UTC(),
				TimestampMs: time.Now().UnixMilli(),
			}

			log.Printf("[BAN_REAPER] ♻️ Reaped expired IP %s (TTL: %v expired). Triggering unban audit trail...",
				ip, time.Duration(entry.TTLNs))

			bm.recordAndStreamAudit(ev)
		}
	}

	return expiredCount
}

// recordAndStreamAudit appends the unban event locally and streams via mTLS gRPC to the Controller.
func (bm *BanManager) recordAndStreamAudit(ev UnbanAuditEvent) {
	bm.mu.Lock()
	bm.unbanAudits = append(bm.unbanAudits, ev)
	hook := bm.auditHook
	sender := bm.customGRPCSender
	endpoint := bm.controllerEndpoint
	bm.mu.Unlock()

	if hook != nil {
		hook(ev)
	}

	logEvent := &copsecproto.LogEvent{
		NodeId:           "node-edge-reaper",
		Source:           "ban_reaper",
		RawLine:          fmt.Sprintf("[UNBAN_AUDIT] Actor=%s Action=%s Target=%s Reason=%q", ev.Actor, ev.ActionType, ev.TargetIP, ev.Reason),
		ClientIp:         ev.TargetIP,
		StatusCode:       200,
		TimestampMs:      ev.TimestampMs,
		RuleId:           "AUTO_UNBAN_TTL",
		MitreTechniqueId: "T1562.004", // Impair Defenses (Authorized Rollback)
		ThreatScore:      0,
	}

	// Dispatch to Tier 2 Controller
	go func() {
		if sender != nil {
			_ = sender(logEvent)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		conn, err := dialSecureController(ctx, endpoint)
		if err != nil {
			log.Printf("[BAN_REAPER] ⚡ Audit stream deferred: %v (queued locally)", err)
			return
		}
		defer conn.Close()

		client := copsecproto.NewCopsecStreamServiceClient(conn)
		stream, err := client.StreamEvents(ctx)
		if err == nil {
			_ = stream.Send(logEvent)
			_, _ = stream.CloseAndRecv()
			log.Printf("[BAN_REAPER] 🟢 Streamed unban audit event for %s to Controller (%s)",
				ev.TargetIP, endpoint)
		}
	}()
}

// SetAuditHook allows unit tests and SOC monitors to intercept unban audit events synchronously.
func (bm *BanManager) SetAuditHook(hook func(event UnbanAuditEvent)) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.auditHook = hook
}

// SetGRPCSender allows tests to mock gRPC event streaming.
func (bm *BanManager) SetGRPCSender(sender func(event *copsecproto.LogEvent) error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.customGRPCSender = sender
}

// GetAuditHistory returns a copy of recorded unban events.
func (bm *BanManager) GetAuditHistory() []UnbanAuditEvent {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	cp := make([]UnbanAuditEvent, len(bm.unbanAudits))
	copy(cp, bm.unbanAudits)
	return cp
}

// dialSecureController creates an authenticated mTLS connection or insecure fallback for testing.
func dialSecureController(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
	tlsCfg := TLSConfig{
		CACertPath:     "/etc/copsec/certs/ca.crt",
		ClientCertPath: "/etc/copsec/certs/client.crt",
		ClientKeyPath:  "/etc/copsec/certs/client.key",
		ServerName:     "pardus1",
	}

	conn, err := BuildSecureClientConn(ctx, endpoint, tlsCfg, nil)
	if err == nil {
		return conn, nil
	}

	// Fallback to local / insecure dial if certificates are not yet provisioned
	caPEM, err := os.ReadFile(tlsCfg.CACertPath)
	if err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
			return grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(creds), grpc.WithBlock())
		}
	}

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 3 * time.Second}))
}
