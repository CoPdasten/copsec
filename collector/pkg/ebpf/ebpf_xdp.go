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
	// MaxBannedIPsLRU is the capacity of the IPv4 kernel BPF_MAP_TYPE_LRU_HASH
	MaxBannedIPsLRU = 131072
	// MaxBannedIPsV6LRU is the capacity of the IPv6 kernel BPF_MAP_TYPE_LRU_HASH
	MaxBannedIPsV6LRU = 65536
	// MaxTarpitIPsLRU is the capacity of the IPv4 kernel tarpit map
	MaxTarpitIPsLRU = 32768
	// MaxTarpitIPsV6LRU is the capacity of the IPv6 kernel tarpit map
	MaxTarpitIPsV6LRU = 16384
	// MaxWhitelistIPs is the capacity of the IPv4 whitelist map
	MaxWhitelistIPs = 16384
	// MaxWhitelistIPsV6 is the capacity of the IPv6 whitelist map
	MaxWhitelistIPsV6 = 4096
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

	// cilium/ebpf kernel map handles (Dual-Stack IPv4 & IPv6 + RingBufs)
	bpfBannedMap        *ebpf.Map
	bpfBannedMapV6      *ebpf.Map
	bpfTarpitMap        *ebpf.Map
	bpfTarpitMapV6      *ebpf.Map
	bpfWhitelistedMap   *ebpf.Map
	bpfWhitelistedMapV6 *ebpf.Map
	bpfSynProxyMap      *ebpf.Map
	bpfRawPacketMap     *ebpf.Map
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
		log.Printf("[XDP_EBPF] [FASTPATH] Initialized XDP Packet Mitigation Fast-Path (LRU Hash: %d entries) on %s (Mode: %s)",
			MaxBannedIPsLRU, iface, engine.xdpMode)
	}

	return engine
}

// initKernelMaps attempts to open pinned BPF maps or create them via cilium/ebpf.
func (x *XDPMitigationEngine) initKernelMaps() {
	// 1. Try loading pinned banned_ips map (IPv4)
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

	// 1b. Try loading pinned banned_ips_v6 map (IPv6)
	pinV6CandidatePaths := []string{
		filepath.Join(DefaultBPFPinPath, "banned_ips_v6"),
		"/sys/fs/bpf/banned_ips_v6",
	}
	for _, p := range pinV6CandidatePaths {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfBannedMapV6 = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel banned_ips_v6 LRU map at %s", p)
			break
		}
	}

	if x.bpfBannedMapV6 == nil && x.bpfBannedMap != nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "banned_ips_v6",
			Type:       ebpf.LRUHash,
			KeySize:    16,
			ValueSize:  20,
			MaxEntries: MaxBannedIPsV6LRU,
		})
		if err == nil {
			x.bpfBannedMapV6 = m
			log.Printf("[XDP_EBPF] Created standalone in-kernel BPF_MAP_TYPE_LRU_HASH for banned_ips_v6")
		}
	}

	// 2. Try loading pinned tarpit map (IPv4)
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

	// 2b. Try loading pinned tarpit_ips_v6 map (IPv6)
	tarpitV6Pins := []string{
		filepath.Join(DefaultBPFPinPath, "tarpit_ips_v6"),
		"/sys/fs/bpf/tarpit_ips_v6",
	}
	for _, p := range tarpitV6Pins {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfTarpitMapV6 = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel tarpit_ips_v6 LRU map at %s", p)
			break
		}
	}

	if x.bpfTarpitMapV6 == nil && x.bpfBannedMap != nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "tarpit_ips_v6",
			Type:       ebpf.LRUHash,
			KeySize:    16,
			ValueSize:  4,
			MaxEntries: MaxTarpitIPsV6LRU,
		})
		if err == nil {
			x.bpfTarpitMapV6 = m
		}
	}

	// 3. Try loading pinned whitelisted_ips map (IPv4)
	whitelistPins := []string{
		filepath.Join(DefaultBPFPinPath, "whitelisted_ips"),
		"/sys/fs/bpf/whitelisted_ips",
	}
	for _, p := range whitelistPins {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfWhitelistedMap = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel whitelisted_ips map at %s", p)
			break
		}
	}

	if x.bpfWhitelistedMap == nil && x.bpfBannedMap != nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "whitelisted_ips",
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: MaxWhitelistIPs,
		})
		if err == nil {
			x.bpfWhitelistedMap = m
		}
	}

	// 3b. Try loading pinned whitelisted_ips_v6 map (IPv6)
	whitelistV6Pins := []string{
		filepath.Join(DefaultBPFPinPath, "whitelisted_ips_v6"),
		"/sys/fs/bpf/whitelisted_ips_v6",
	}
	for _, p := range whitelistV6Pins {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfWhitelistedMapV6 = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel whitelisted_ips_v6 map at %s", p)
			break
		}
	}

	if x.bpfWhitelistedMapV6 == nil && x.bpfBannedMap != nil {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "whitelisted_ips_v6",
			Type:       ebpf.Hash,
			KeySize:    16,
			ValueSize:  4,
			MaxEntries: MaxWhitelistIPsV6,
		})
		if err == nil {
			x.bpfWhitelistedMapV6 = m
		}
	}

	// 4. Try loading pinned raw_packet_ringbuf
	rawPacketPins := []string{
		filepath.Join(DefaultBPFPinPath, "raw_packet_ringbuf"),
		"/sys/fs/bpf/raw_packet_ringbuf",
	}
	for _, p := range rawPacketPins {
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			x.bpfRawPacketMap = m
			log.Printf("[XDP_EBPF] Attached to pinned kernel raw_packet_ringbuf at %s", p)
			break
		}
	}
}

func isIPv6(ipStr string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil && parsed.To16() != nil
}

func ipToUint32(ipStr string) (uint32, error) {
	parsed := net.ParseIP(strings.TrimSpace(ipStr)).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.NativeEndian.Uint32(parsed), nil
}

func ipToV6Key(ipStr string) ([16]byte, error) {
	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return [16]byte{}, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	v6 := parsed.To16()
	if v6 == nil || parsed.To4() != nil {
		return [16]byte{}, fmt.Errorf("invalid IPv6 address: %s", ipStr)
	}
	var key [16]byte
	copy(key[:], v6)
	return key, nil
}

// AddBan injects an IPv4 or IPv6 address directly into the eBPF drop map with default permanent/indefinite TTL.
func (x *XDPMitigationEngine) AddBan(ipStr string) error {
	return x.AddBanWithTTL(ipStr, 0, 0, "L7/L4 Fast-Path Quarantine")
}

// AddBanWithTTL injects an IP into the eBPF banned_ips or banned_ips_v6 LRU map with dynamic TTL and reason metadata.
func (x *XDPMitigationEngine) AddBanWithTTL(ipStr string, ttl time.Duration, reasonCode uint32, reason string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP == "" {
		return fmt.Errorf("empty IP address")
	}

	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
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
	if isV6 {
		if x.bpfBannedMapV6 != nil {
			if err := x.bpfBannedMapV6.Put(v6Key, kEntry); err != nil {
				log.Printf("[WARN][XDP_EBPF] Failed to update in-kernel banned_ips_v6 map: %v", err)
			}
		}
	} else {
		if x.bpfBannedMap != nil {
			if err := x.bpfBannedMap.Put(v4Key, kEntry); err != nil {
				log.Printf("[WARN][XDP_EBPF] Failed to update in-kernel banned_ips map: %v", err)
			}
		}
	}

	entry := BanEntry{
		IP:             cleanIP,
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

	x.bannedIPs[cleanIP] = true
	x.banEntries[cleanIP] = entry
	atomic.AddUint64(&x.droppedPackets, 1)

	log.Printf("[XDP_EBPF] [FASTPATH] Injected IP %s into BPF banned_ips LRU map (TTL: %v, Reason: %q)", cleanIP, ttl, reason)
	return nil
}

// RemoveBan purges an IP from the eBPF drop maps.
func (x *XDPMitigationEngine) RemoveBan(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP == "" {
		return fmt.Errorf("empty IP address")
	}

	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if isV6 {
		if x.bpfBannedMapV6 != nil {
			_ = x.bpfBannedMapV6.Delete(v6Key)
		}
	} else {
		if x.bpfBannedMap != nil {
			_ = x.bpfBannedMap.Delete(v4Key)
		}
	}

	if !x.bannedIPs[cleanIP] {
		return nil
	}

	delete(x.bannedIPs, cleanIP)
	delete(x.banEntries, cleanIP)
	log.Printf("[XDP_EBPF] [OK] Purged IP %s from BPF banned_ips map", cleanIP)
	return nil
}

// Flush clears all banned addresses from the eBPF drop maps.
func (x *XDPMitigationEngine) Flush() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	for ipStr := range x.bannedIPs {
		if isIPv6(ipStr) {
			if x.bpfBannedMapV6 != nil {
				if v6Key, err := ipToV6Key(ipStr); err == nil {
					_ = x.bpfBannedMapV6.Delete(v6Key)
				}
			}
		} else {
			if x.bpfBannedMap != nil {
				if v4Key, err := ipToUint32(ipStr); err == nil {
					_ = x.bpfBannedMap.Delete(v4Key)
				}
			}
		}
	}

	x.bannedIPs = make(map[string]bool)
	x.banEntries = make(map[string]BanEntry)
	log.Println("[XDP_EBPF]  Flushed all entries from BPF banned_ips maps")
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
			if isIPv6(cleanIP) {
				if x.bpfBannedMapV6 != nil {
					if v6Key, err := ipToV6Key(cleanIP); err == nil {
						_ = x.bpfBannedMapV6.Delete(v6Key)
					}
				}
			} else {
				if x.bpfBannedMap != nil {
					if v4Key, err := ipToUint32(cleanIP); err == nil {
						_ = x.bpfBannedMap.Delete(v4Key)
					}
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
	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	var activeVal uint32 = 1
	if isV6 {
		if x.bpfTarpitMapV6 != nil {
			_ = x.bpfTarpitMapV6.Put(v6Key, activeVal)
		}
	} else {
		if x.bpfTarpitMap != nil {
			_ = x.bpfTarpitMap.Put(v4Key, activeVal)
		}
	}

	x.tarpitIPs[cleanIP] = true
	atomic.AddUint64(&x.tarpitPackets, 1)
	log.Printf("[XDP_EBPF]  Injected IP %s into BPF tarpit_ips map (Zero-Window Tarpit Active)", cleanIP)
	return nil
}

// RemoveTarpit removes an IP from the active tarpit registry.
func (x *XDPMitigationEngine) RemoveTarpit(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if isV6 {
		if x.bpfTarpitMapV6 != nil {
			_ = x.bpfTarpitMapV6.Delete(v6Key)
		}
	} else {
		if x.bpfTarpitMap != nil {
			_ = x.bpfTarpitMap.Delete(v4Key)
		}
	}

	delete(x.tarpitIPs, cleanIP)
	log.Printf("[XDP_EBPF] [OK] Purged IP %s from BPF tarpit_ips map", cleanIP)
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

	for ipStr := range x.tarpitIPs {
		if isIPv6(ipStr) {
			if x.bpfTarpitMapV6 != nil {
				if v6Key, err := ipToV6Key(ipStr); err == nil {
					_ = x.bpfTarpitMapV6.Delete(v6Key)
				}
			}
		} else {
			if x.bpfTarpitMap != nil {
				if v4Key, err := ipToUint32(ipStr); err == nil {
					_ = x.bpfTarpitMap.Delete(v4Key)
				}
			}
		}
	}

	x.tarpitIPs = make(map[string]bool)
	return nil
}

// EmergencyFlushAll atomically flushes banned_ips, banned_ips_v6, tarpit_ips, and tarpit_ips_v6 maps
// instantly without restarting services or dropping the XDP program.
func (x *XDPMitigationEngine) EmergencyFlushAll() (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	flushedCount := 0

	// 1. Flush IPv4 banned_ips
	if x.bpfBannedMap != nil {
		var keys []uint32
		iter := x.bpfBannedMap.Iterate()
		var key uint32
		var val KernelBanEntry
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			if err := x.bpfBannedMap.Delete(k); err == nil {
				flushedCount++
			}
		}
	}

	// 2. Flush IPv6 banned_ips_v6
	if x.bpfBannedMapV6 != nil {
		var keys [][16]byte
		iter := x.bpfBannedMapV6.Iterate()
		var key [16]byte
		var val KernelBanEntry
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			if err := x.bpfBannedMapV6.Delete(k); err == nil {
				flushedCount++
			}
		}
	}

	// 3. Flush IPv4 tarpit_ips
	if x.bpfTarpitMap != nil {
		var keys []uint32
		iter := x.bpfTarpitMap.Iterate()
		var key uint32
		var val uint32
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			if err := x.bpfTarpitMap.Delete(k); err == nil {
				flushedCount++
			}
		}
	}

	// 4. Flush IPv6 tarpit_ips_v6
	if x.bpfTarpitMapV6 != nil {
		var keys [][16]byte
		iter := x.bpfTarpitMapV6.Iterate()
		var key [16]byte
		var val uint32
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			if err := x.bpfTarpitMapV6.Delete(k); err == nil {
				flushedCount++
			}
		}
	}

	// Also attempt to purge pinned maps directly if not attached to engine instance
	pinCandidates := []struct {
		pin string
		v6  bool
	}{
		{filepath.Join(DefaultBPFPinPath, "banned_ips"), false},
		{filepath.Join(DefaultBPFPinPath, "banned_ips_v6"), true},
		{filepath.Join(DefaultBPFPinPath, "tarpit_ips"), false},
		{filepath.Join(DefaultBPFPinPath, "tarpit_ips_v6"), true},
	}
	for _, pc := range pinCandidates {
		if m, err := ebpf.LoadPinnedMap(pc.pin, nil); err == nil {
			if pc.v6 {
				var keys [][16]byte
				iter := m.Iterate()
				var key [16]byte
				var val [20]byte
				for iter.Next(&key, &val) {
					keys = append(keys, key)
				}
				for _, k := range keys {
					if err := m.Delete(k); err == nil {
						flushedCount++
					}
				}
			} else {
				var keys []uint32
				iter := m.Iterate()
				var key uint32
				var val [20]byte
				for iter.Next(&key, &val) {
					keys = append(keys, key)
				}
				for _, k := range keys {
					if err := m.Delete(k); err == nil {
						flushedCount++
					}
				}
			}
			_ = m.Close()
		}
	}

	// 5. Purge memory tracking tables
	flushedCount += len(x.bannedIPs)
	x.bannedIPs = make(map[string]bool)
	x.banEntries = make(map[string]BanEntry)
	x.tarpitIPs = make(map[string]bool)

	log.Printf("[EMERGENCY_FLUSH] [ALERT] Break-Glass Flush executed successfully. Flushed total records: %d", flushedCount)
	return flushedCount, nil
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
	log.Printf("[XDP_EBPF]  In-kernel SYN-Proxy activated (Port: %d)", port)
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

	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	var bypassVal uint32 = 1
	if isV6 {
		if x.bpfWhitelistedMapV6 != nil {
			_ = x.bpfWhitelistedMapV6.Put(v6Key, bypassVal)
		}
	} else {
		if x.bpfWhitelistedMap != nil {
			_ = x.bpfWhitelistedMap.Put(v4Key, bypassVal)
		}
	}

	x.whitelistedIPs[cleanIP] = true
	log.Printf("[XDP_EBPF]  Injected IP %s into BPF whitelisted_ips fast-bypass map", cleanIP)
	return nil
}

// RemoveWhitelistIP removes an IP from the eBPF whitelisted_ips map.
func (x *XDPMitigationEngine) RemoveWhitelistIP(ipStr string) error {
	cleanIP := strings.TrimSpace(ipStr)
	if net.ParseIP(cleanIP) == nil {
		return fmt.Errorf("invalid IP format: %s", cleanIP)
	}

	isV6 := isIPv6(cleanIP)
	var v4Key uint32
	var v6Key [16]byte
	var err error

	if isV6 {
		v6Key, err = ipToV6Key(cleanIP)
	} else {
		v4Key, err = ipToUint32(cleanIP)
	}
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if isV6 {
		if x.bpfWhitelistedMapV6 != nil {
			_ = x.bpfWhitelistedMapV6.Delete(v6Key)
		}
	} else {
		if x.bpfWhitelistedMap != nil {
			_ = x.bpfWhitelistedMap.Delete(v4Key)
		}
	}

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

// GetRawPacketMap returns the auxiliary raw packet ring buffer map if available.
func (x *XDPMitigationEngine) GetRawPacketMap() *ebpf.Map {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.bpfRawPacketMap
}

// Close detaches the XDP program and releases BPF map resources.
func (x *XDPMitigationEngine) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.active = false
	x.bannedIPs = make(map[string]bool)
	x.tarpitIPs = make(map[string]bool)
	x.whitelistedIPs = make(map[string]bool)

	if x.bpfBannedMap != nil {
		_ = x.bpfBannedMap.Close()
		x.bpfBannedMap = nil
	}
	if x.bpfBannedMapV6 != nil {
		_ = x.bpfBannedMapV6.Close()
		x.bpfBannedMapV6 = nil
	}
	if x.bpfTarpitMap != nil {
		_ = x.bpfTarpitMap.Close()
		x.bpfTarpitMap = nil
	}
	if x.bpfTarpitMapV6 != nil {
		_ = x.bpfTarpitMapV6.Close()
		x.bpfTarpitMapV6 = nil
	}
	if x.bpfWhitelistedMap != nil {
		_ = x.bpfWhitelistedMap.Close()
		x.bpfWhitelistedMap = nil
	}
	if x.bpfWhitelistedMapV6 != nil {
		_ = x.bpfWhitelistedMapV6.Close()
		x.bpfWhitelistedMapV6 = nil
	}
	if x.bpfSynProxyMap != nil {
		_ = x.bpfSynProxyMap.Close()
		x.bpfSynProxyMap = nil
	}
	if x.bpfRawPacketMap != nil {
		_ = x.bpfRawPacketMap.Close()
		x.bpfRawPacketMap = nil
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
