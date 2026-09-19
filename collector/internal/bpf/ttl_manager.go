package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// BanEntry models kernel struct ban_entry_t in bpf/copsec_advanced.bpf.c.
// Layout: 8 bytes expire_at_ns + 4 bytes reason + 4 bytes padding (16 bytes total, 64-bit aligned).
type BanEntry struct {
	ExpireAtNs uint64
	Reason     uint32
}

// TTLBanManager manages kernel-level IP ban lifecycles in the eBPF dynamic_ttl_ban_map.
type TTLBanManager struct {
	mu          sync.RWMutex
	banMap      *ebpf.Map
	closeOnExit bool
}

// NewTTLBanManager initializes a TTLBanManager using an existing *ebpf.Map pointer.
func NewTTLBanManager(m *ebpf.Map) (*TTLBanManager, error) {
	if m == nil {
		return nil, errors.New("dynamic_ttl_ban_map pointer cannot be nil")
	}
	return &TTLBanManager{
		banMap:      m,
		closeOnExit: false,
	}, nil
}

// NewTTLBanManagerFromPin attaches to an eBPF dynamic_ttl_ban_map pinned in the BPF filesystem.
func NewTTLBanManagerFromPin(pinPath string) (*TTLBanManager, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned dynamic_ttl_ban_map at %s: %w", pinPath, err)
	}
	return &TTLBanManager{
		banMap:      m,
		closeOnExit: true,
	}, nil
}

// BanIP converts duration to nanoseconds relative to time.Now().UnixNano() and writes
// the quarantine record directly into the kernel eBPF LRU hash map.
func (m *TTLBanManager) BanIP(ip net.IP, duration time.Duration, reasonCode uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.banMap == nil {
		return errors.New("dynamic_ttl_ban_map is uninitialized")
	}

	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("unsupported IP address (only IPv4 supported): %v", ip)
	}

	key := binary.NativeEndian.Uint32(v4)
	expireAt := uint64(time.Now().UnixNano() + duration.Nanoseconds())

	entry := BanEntry{
		ExpireAtNs: expireAt,
		Reason:     reasonCode,
	}

	if err := m.banMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to insert IP %s into dynamic_ttl_ban_map: %w", ip, err)
	}

	return nil
}

// UnbanIP explicitly removes a banned IP entry from the eBPF map on demand.
func (m *TTLBanManager) UnbanIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.banMap == nil {
		return errors.New("dynamic_ttl_ban_map is uninitialized")
	}

	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("unsupported IP address (only IPv4 supported): %v", ip)
	}

	key := binary.NativeEndian.Uint32(v4)
	err := m.banMap.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil // Idempotent: already evicted or expired
	}
	if err != nil {
		return fmt.Errorf("failed to delete IP %s from dynamic_ttl_ban_map: %w", ip, err)
	}

	return nil
}

// IsBanned checks whether an IP is currently registered and unexpired in the BPF map.
func (m *TTLBanManager) IsBanned(ip net.IP) (bool, *BanEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.banMap == nil {
		return false, nil, errors.New("dynamic_ttl_ban_map is uninitialized")
	}

	v4 := ip.To4()
	if v4 == nil {
		return false, nil, fmt.Errorf("unsupported IP address: %v", ip)
	}

	key := binary.NativeEndian.Uint32(v4)
	var entry BanEntry
	if err := m.banMap.Lookup(key, &entry); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil, nil
		}
		return false, nil, err
	}

	now := uint64(time.Now().UnixNano())
	if now >= entry.ExpireAtNs {
		return false, &entry, nil // Expired
	}

	return true, &entry, nil
}

// GetActiveBans returns a snapshot of all active, unexpired IP bans currently stored in kernel memory.
func (m *TTLBanManager) GetActiveBans() (map[string]BanEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.banMap == nil {
		return nil, errors.New("dynamic_ttl_ban_map is uninitialized")
	}

	active := make(map[string]BanEntry)
	now := uint64(time.Now().UnixNano())

	var key uint32
	var val BanEntry
	iter := m.banMap.Iterate()
	for iter.Next(&key, &val) {
		if now < val.ExpireAtNs {
			var b [4]byte
			binary.NativeEndian.PutUint32(b[:], key)
			ipStr := net.IPv4(b[0], b[1], b[2], b[3]).String()
			active[ipStr] = val
		}
	}

	if err := iter.Err(); err != nil {
		return active, fmt.Errorf("failed iterating dynamic_ttl_ban_map: %w", err)
	}

	return active, nil
}

// Map returns the underlying *ebpf.Map pointer.
func (m *TTLBanManager) Map() *ebpf.Map {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.banMap
}

// Close releases the underlying BPF map resources if owned by the manager.
func (m *TTLBanManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closeOnExit && m.banMap != nil {
		err := m.banMap.Close()
		m.banMap = nil
		return err
	}
	return nil
}
