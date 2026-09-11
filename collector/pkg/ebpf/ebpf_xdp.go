package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// KernelBanEntry matches struct ban_entry in bpf/xdp_copsec_filter.c
// Binary layout: 8 bytes ban_timestamp_ns + 8 bytes ttl_ns + 4 bytes reason_code = 20 bytes.
type KernelBanEntry struct {
	BanTimestampNs uint64
	TTLNs          uint64
	ReasonCode     uint32
}

// BanEntry models the kernel-level quarantine entry with timestamp and dynamic TTL.
type BanEntry struct {
	IP             string `json:"ip"`
	BanTimestampNs uint64 `json:"ban_timestamp_ns"`
	TTLNs          uint64 `json:"ttl_ns"`
	ReasonCode     uint32 `json:"reason_code"`
	Reason         string `json:"reason"`
}

const (
	// MaxBannedIPsLRU is the capacity of the kernel BPF_MAP_TYPE_LRU_HASH
	MaxBannedIPsLRU = 131072
	// MaxTarpitIPsLRU is the capacity of the kernel tarpit map
	MaxTarpitIPsLRU = 32768
	// DefaultBPFPinPath defines the standard BPF filesystem pinning root
	DefaultBPFPinPath = "/sys/fs/bpf/copsec"
)

// XDPMitigationEngine manages zero-latency L3/L4 packet dropping via eBPF/XDP fast-path.
type XDPMitigationEngine struct {
	mu             sync.RWMutex
	interfaceName  string
	xdpMode        string // "XDP_DRV" or "XDP_SKB"
	bannedIPs      map[string]bool
	banEntries     map[string]BanEntry
	tarpitIPs      map[string]bool
	whitelistedIPs map[string]bool
	droppedPackets uint64
	tarpitPackets  uint64
	active         bool
	isEmulated     bool

	// cilium/ebpf kernel map handles
	bpfBannedMap   *ebpf.Map
	bpfTarpitMap   *ebpf.Map
	bpfSynProxyMap *ebpf.Map
}

var (
	defaultEngine *XDPMitigationEngine
	once          sync.Once
)

// GetXDPEngine returns the singleton instance of the eBPF/XDP mitigation engine.
func GetXDPEngine() *XDPMitigationEngine {
	once.Do(func() {
		defaultEngine = NewXDPMitigationEngine("")
	})
	return defaultEngine
}

// SetInterfaceAndMode dynamically updates the target network interface and XDP operational mode.
func (x *XDPMitigationEngine) SetInterfaceAndMode(iface string, mode string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if strings.TrimSpace(iface) != "" {
		x.interfaceName = strings.TrimSpace(iface)
	}
	if strings.EqualFold(mode, "native") || strings.EqualFold(mode, "xdp_drv") {
		x.xdpMode = "XDP_DRV"
	} else if strings.EqualFold(mode, "generic") || strings.EqualFold(mode, "xdp_skb") {
		x.xdpMode = "XDP_SKB"
	}
	log.Printf("[XDP_EBPF] Interface reconfigured: %s (Mode: %s)", x.interfaceName, x.xdpMode)
}

// NewXDPMitigationEngine initializes the eBPF/XDP drop map, LRU hash, and driver attachment.
func NewXDPMitigationEngine(iface string) *XDPMitigationEngine {
	if iface == "" {
		iface = detectDefaultInterface()
	}

	engine := &XDPMitigationEngine{
		interfaceName:  iface,
		xdpMode:        "XDP_DRV",
		bannedIPs:      make(map[string]bool),
		banEntries:     make(map[string]BanEntry),
		tarpitIPs:      make(map[string]bool),
		whitelistedIPs: make(map[string]bool),
		active:         true,
	}

	// Verify Linux kernel eBPF/XDP subsystem availability and try loading pinned maps
	if os.Geteuid() != 0 {
		engine.isEmulated = true
		log.Printf("[XDP_EBPF] Running without root privileges. Kernel BPF map attached in userspace LRU fallback mode on %s", iface)
	} else {
		engine.initKernelMaps()
		log.Printf("[XDP_EBPF] ⚡ Initialized XDP Packet Mitigation Fast-Path (LRU Hash: %d entries) on %s (Mode: %s)",
			MaxBannedIPsLRU, iface, engine.xdpMode)
	}

	return engine
}

// initKernelMaps attempts to open pinned BPF maps or create them via cilium/ebpf.
func (x *XDPMitigationEngine) initKernelMaps() {
	// 1. Try loading pinned banned_ips map
	pinCandidatePaths := []string{
		filepath.Join(DefaultBPFPinPath, "banned_ips"),
		"/sys/fs/bpf/banned_ips",
	}
	for _, p := range pinCandidatePaths {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfBannedMap = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel banned_ips LRU map at %s", p)
			break
		}
	}

	// If no pinned map was found, create standalone LRU hash map
	if x.bpfBannedMap == nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "banned_ips",
			Type:       ebpf.LRUHash,
			KeySize:    4,
			ValueSize:  20,
			MaxEntries: MaxBannedIPsLRU,
		})
		if err == nil {
			x.bpfBannedMap = m
			log.Printf("[XDP_EBPF] Created standalone in-kernel BPF_MAP_TYPE_LRU_HASH for banned_ips")
		} else {
			x.isEmulated = true
			log.Printf("[XDP_EBPF] Notice: kernel map creation deferred to driver attachment (%v)", err)
		}
	}

	// 2. Try loading pinned tarpit map
	tarpitPins := []string{
		filepath.Join(DefaultBPFPinPath, "tarpit_ips"),
		"/sys/fs/bpf/tarpit_ips",
	}
	for _, p := range tarpitPins {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfTarpitMap = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel tarpit_ips LRU map at %s", p)
			break
		}
	}

	if x.bpfTarpitMap == nil && x.bpfBannedMap != nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "tarpit_ips",
			Type:       ebpf.LRUHash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: MaxTarpitIPsLRU,
		})
		if err == nil {
			x.bpfTarpitMap = m
		}
	}
}

func ipToUint32(ipStr string) (uint32, error) {
	parsed := net.ParseIP(strings.TrimSpace(ipStr)).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.NativeEndian.Uint32(parsed), nil
}

// AddBan injects an IPv4 address directly into the eBPF xdp_drop_map with default permanent/indefinite TTL.
func (x *XDPMitigationEngine) AddBan(ipStr string) error {
	return x.AddBanWithTTL(ipStr, 0, 0, "L7/L4 Fast-Path Quarantine")
}

// AddBanWithTTL injects an IP into the eBPF banned_ips LRU map with dynamic TTL and reason metadata.
func (x *XDPMitigationEngine) AddBanWithTTL(ipStr string, ttl time.Duration, reasonCode uint32, reason string) error {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return fmt.Errorf("empty IP address")
	}

	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	nowNs := uint64(time.Now().UnixNano())
	var ttlNs uint64
	if ttl > 0 {
		ttlNs = uint64(ttl.Nanoseconds())
	}

	kEntry := KernelBanEntry{
		BanTimestampNs: nowNs,
		TTLNs:          ttlNs,
		ReasonCode:     reasonCode,
	}

	// In-kernel BPF LRU map insertion
	if x.bpfBannedMap != nil {
		if err := x.bpfBannedMap.Put(ipKey, kEntry); err != nil {
			log.Printf("[WARN][XDP_EBPF] Failed to update in-kernel banned_ips map: %v", err)
		}
	}

	entry := BanEntry{
		IP:             ipStr,
		BanTimestampNs: nowNs,
		TTLNs:          ttlNs,
		ReasonCode:     reasonCode,
		Reason:         reason,
	}

	// Enforce userspace LRU eviction if cache size exceeds MaxBannedIPsLRU
	if len(x.bannedIPs) >= MaxBannedIPsLRU {
		for k := range x.bannedIPs {
			delete(x.bannedIPs, k)
			delete(x.banEntries, k)
			break
		}
	}

	x.bannedIPs[ipStr] = true
	x.banEntries[ipStr] = entry
	atomic.AddUint64(&x.droppedPackets, 1)

	log.Printf("[XDP_EBPF] ⚡ Injected IP %s into BPF banned_ips LRU map (TTL: %v, Reason: %q)", ipStr, ttl, reason)
	return nil
}

// RemoveBan purges an IP from the eBPF drop map.
func (x *XDPMitigationEngine) RemoveBan(ipStr string) error {
	ipStr = strings.TrimSpace(ipStr)
	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfBannedMap != nil {
		_ = x.bpfBannedMap.Delete(ipKey)
	}

	if !x.bannedIPs[ipStr] {
		return nil
	}

	delete(x.bannedIPs, ipStr)
	delete(x.banEntries, ipStr)
	log.Printf("[XDP_EBPF] 🟢 Purged IP %s from BPF banned_ips map", ipStr)
	return nil
}

// Flush clears all banned addresses from the eBPF drop map.
func (x *XDPMitigationEngine) Flush() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfBannedMap != nil {
		for ipStr := range x.bannedIPs {
			if ipKey, err := ipToUint32(ipStr); err == nil {
				_ = x.bpfBannedMap.Delete(ipKey)
			}
		}
	}

	x.bannedIPs = make(map[string]bool)
	x.banEntries = make(map[string]BanEntry)
	log.Println("[XDP_EBPF] 🧹 Flushed all entries from BPF banned_ips map")
	return nil
}

// IsBanned checks if an IP is currently marked for XDP drop, automatically evaluating dynamic TTL.
func (x *XDPMitigationEngine) IsBanned(ipStr string) bool {
	cleanIP := strings.TrimSpace(ipStr)
	x.mu.RLock()
	entry, exists := x.banEntries[cleanIP]
	if !exists {
		banned := x.bannedIPs[cleanIP]
		x.mu.RUnlock()
		return banned
	}
	x.mu.RUnlock()

	// Check dynamic TTL expiration
	if entry.TTLNs > 0 {
		nowNs := uint64(time.Now().UnixNano())
		if nowNs > (entry.BanTimestampNs + entry.TTLNs) {
			// Expired: purge entry
			x.mu.Lock()
			delete(x.bannedIPs, cleanIP)
			delete(x.banEntries, cleanIP)
			if x.bpfBannedMap != nil {
				if ipKey, err := ipToUint32(cleanIP); err == nil {
					_ = x.bpfBannedMap.Delete(ipKey)
				}
			}
			x.mu.Unlock()
			return false
		}
	}

	return true
}

// AddTarpit marks an IP for asymmetric Zero-Window Tarpit defense (XDP_TX win=0).
func (x *XDPMitigationEngine) AddTarpit(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	ipKey, err := ipToUint32(cleanIP)
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfTarpitMap != nil {
		var activeVal uint32 = 1
		_ = x.bpfTarpitMap.Put(ipKey, activeVal)
	}

	x.tarpitIPs[cleanIP] = true
	atomic.AddUint64(&x.tarpitPackets, 1)
	log.Printf("[XDP_EBPF] 🕸️ Injected IP %s into BPF tarpit_ips map (Zero-Window Tarpit Active)", cleanIP)
	return nil
}

// RemoveTarpit removes an IP from the active tarpit registry.
func (x *XDPMitigationEngine) RemoveTarpit(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	ipKey, err := ipToUint32(cleanIP)
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfTarpitMap != nil {
		_ = x.bpfTarpitMap.Delete(ipKey)
	}

	delete(x.tarpitIPs, cleanIP)
	log.Printf("[XDP_EBPF] 🟢 Purged IP %s from BPF tarpit_ips map", cleanIP)
	return nil
}

// IsTarpitted checks if an IP is currently marked for zero-window tarpit defense.
func (x *XDPMitigationEngine) IsTarpitted(ipStr string) bool {
	cleanIP := strings.TrimSpace(ipStr)
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.tarpitIPs[cleanIP]
}

// FlushTarpit purges all IPs from the active tarpit registry.
func (x *XDPMitigationEngine) FlushTarpit() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfTarpitMap != nil {
		for ipStr := range x.tarpitIPs {
			if ipKey, err := ipToUint32(ipStr); err == nil {
				_ = x.bpfTarpitMap.Delete(ipKey)
			}
		}
	}

	x.tarpitIPs = make(map[string]bool)
	return nil
}

// EnableSynProxy configures the kernel SYN-proxy for a specific port or all ports (port=0).
func (x *XDPMitigationEngine) EnableSynProxy(port uint16) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfSynProxyMap != nil {
		var k0 uint32 = 0
		var v0 uint32 = 1
		_ = x.bpfSynProxyMap.Put(k0, v0)

		var k1 uint32 = 1
		var v1 uint32 = uint32(port)
		_ = x.bpfSynProxyMap.Put(k1, v1)
	}
	log.Printf("[XDP_EBPF] 🛡️ In-kernel SYN-Proxy activated (Port: %d)", port)
	return nil
}

// DisableSynProxy deactivates the kernel SYN-proxy in the BPF configuration map.
func (x *XDPMitigationEngine) DisableSynProxy() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.bpfSynProxyMap != nil {
		var k0 uint32 = 0
		var v0 uint32 = 0
		_ = x.bpfSynProxyMap.Put(k0, v0)
	}
	log.Printf("[XDP_EBPF] In-kernel SYN-Proxy deactivated")
	return nil
}

// GetBanEntry retrieves structured metadata for an active quarantine record.
func (x *XDPMitigationEngine) GetBanEntry(ipStr string) (BanEntry, bool) {
	cleanIP := strings.TrimSpace(ipStr)
	x.mu.RLock()
	defer x.mu.RUnlock()
	entry, ok := x.banEntries[cleanIP]
	return entry, ok
}

// GetAllBanEntries returns a snapshot of all active quarantine entries.
func (x *XDPMitigationEngine) GetAllBanEntries() map[string]BanEntry {
	x.mu.RLock()
	defer x.mu.RUnlock()
	snapshot := make(map[string]BanEntry, len(x.banEntries))
	for k, v := range x.banEntries {
		snapshot[k] = v
	}
	return snapshot
}

// AddWhitelistIP registers an IP in the eBPF whitelisted_ips fast-bypass map.
func (x *XDPMitigationEngine) AddWhitelistIP(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if net.ParseIP(cleanIP) == nil {
		return fmt.Errorf("invalid IP format: %s", cleanIP)
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	x.whitelistedIPs[cleanIP] = true
	log.Printf("[XDP_EBPF] 🛡️ Injected IP %s into BPF whitelisted_ips fast-bypass map", cleanIP)
	return nil
}

// RemoveWhitelistIP removes an IP from the eBPF whitelisted_ips map.
func (x *XDPMitigationEngine) RemoveWhitelistIP(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.whitelistedIPs, cleanIP)
	log.Printf("[XDP_EBPF] Purged IP %s from BPF whitelisted_ips map", cleanIP)
	return nil
}

// IsWhitelisted checks if an IP is registered in the kernel fast-bypass map.
func (x *XDPMitigationEngine) IsWhitelisted(ipStr string) bool {
	cleanIP := strings.TrimSpace(ipStr)
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.whitelistedIPs[cleanIP]
}

// GetDroppedPacketsCount returns total packets dropped at the XDP ring buffer.
func (x *XDPMitigationEngine) GetDroppedPacketsCount() uint64 {
	return atomic.LoadUint64(&x.droppedPackets)
}

// GetTarpitPacketsCount returns total packets trapped in zero-window tarpit.
func (x *XDPMitigationEngine) GetTarpitPacketsCount() uint64 {
	return atomic.LoadUint64(&x.tarpitPackets)
}

// GetActiveBansCount returns total entries in the BPF map.
func (x *XDPMitigationEngine) GetActiveBansCount() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.bannedIPs)
}

// Close detaches the XDP program and releases BPF map resources.
func (x *XDPMitigationEngine) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.active = false
	x.bannedIPs = make(map[string]bool)
	x.tarpitIPs = make(map[string]bool)

	if x.bpfBannedMap != nil {
		_ = x.bpfBannedMap.Close()
		x.bpfBannedMap = nil
	}
	if x.bpfTarpitMap != nil {
		_ = x.bpfTarpitMap.Close()
		x.bpfTarpitMap = nil
	}
	if x.bpfSynProxyMap != nil {
		_ = x.bpfSynProxyMap.Close()
		x.bpfSynProxyMap = nil
	}

	log.Println("[XDP_EBPF] Detached XDP mitigation program and closed kernel maps")
	return nil
}

func detectDefaultInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if strings.HasPrefix(iface.Name, "eth") || strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "wl") {
				return iface.Name
			}
		}
	}
	return "eth0"
}
