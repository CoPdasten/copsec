package whitelist

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Entry represents a persistent or memory whitelist record.
type Entry struct {
	ID          int64  `json:"id"`
	CIDROrIP    string `json:"cidr_or_ip"`
	Description string `json:"description"`
	AddedBy     string `json:"added_by"`
	CreatedAtMs int64  `json:"created_at_ms"`
}

// StorageProvider provides the persistence contract needed by the whitelist engine.
type StorageProvider interface {
	GetAllWhitelistEntries() ([]Entry, error)
	AddWhitelistEntry(cidrOrIP, description, addedBy string, createdAtMs int64) (int64, error)
	DeleteWhitelistEntry(id int64, cidrOrIP string) error
}

// Engine maintains an atomic, thread-safe in-memory cache of IP addresses and CIDR subnets
// backed by persistent SQLite storage.
type Engine struct {
	mu          sync.RWMutex
	exactIPs    map[string]bool
	subnets     []*net.IPNet
	entries     []Entry
	storage     StorageProvider
	initialized bool
}

var (
	defaultEngine *Engine
	once          sync.Once
)

// GetDefaultEngine returns the global singleton whitelist engine.
func GetDefaultEngine() *Engine {
	once.Do(func() {
		defaultEngine = NewEngine(nil)
	})
	return defaultEngine
}

// NewEngine creates a new Whitelist Engine.
func NewEngine(storage StorageProvider) *Engine {
	e := &Engine{
		exactIPs: make(map[string]bool),
		subnets:  make([]*net.IPNet, 0),
		entries:  make([]Entry, 0),
		storage:  storage,
	}
	return e
}

// SetStorage connects persistent storage and triggers an initial seed/load.
func (e *Engine) SetStorage(s StorageProvider) {
	e.mu.Lock()
	e.storage = s
	e.mu.Unlock()

	_ = e.ReloadAndSeed()
}

// IsWhitelisted evaluates an incoming IP against the fast exact-match table ($O(1)$)
// and iterates through parsed net.IPNet subnets. Returns true if trusted.
func (e *Engine) IsWhitelisted(ipStr string) bool {
	clean := strings.TrimSpace(ipStr)
	if clean == "" || clean == "-" || clean == "localhost" || clean == "local" {
		return true
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. Fast exact map check O(1)
	if e.exactIPs[clean] {
		return true
	}

	// 2. Parse IP and test subnets
	parsed := net.ParseIP(clean)
	if parsed == nil {
		return false
	}

	// Immediate loopback & private zero-leak check
	if parsed.IsLoopback() {
		return true
	}

	for _, subnet := range e.subnets {
		if subnet.Contains(parsed) {
			return true
		}
	}

	return false
}

// ReloadAndSeed syncs the in-memory cache from persistent storage and seeds mandatory
// self-lockout prevention ranges (loopback, host interfaces, gateway).
func (e *Engine) ReloadAndSeed() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var dbEntries []Entry
	if e.storage != nil {
		var err error
		dbEntries, err = e.storage.GetAllWhitelistEntries()
		if err != nil {
			log.Printf("[WHITELIST] ⚠️ Failed to query whitelist from storage: %v", err)
		}
	}

	// Build map of already persisted items
	existing := make(map[string]bool)
	for _, item := range dbEntries {
		existing[item.CIDROrIP] = true
	}

	// 1. Guardrails & Auto-Seeding (Zero Self-Lockout)
	// Mandatory non-removable defaults
	defaults := []struct {
		target string
		desc   string
	}{
		{"127.0.0.1/32", "Loopback IPv4 System Defense"},
		{"::1/128", "Loopback IPv6 System Defense"},
	}

	// Detect host active IP addresses and default gateway
	localIPs := detectLocalHostIPs()
	for _, ip := range localIPs {
		cidr := ip + "/32"
		if strings.Contains(ip, ":") {
			cidr = ip + "/128"
		}
		defaults = append(defaults, struct {
			target string
			desc   string
		}{cidr, "Host Local Interface IP (Self-Lockout Guard)"})
	}

	gatewayIP := detectDefaultGateway()
	if gatewayIP != "" {
		cidr := gatewayIP + "/32"
		if strings.Contains(gatewayIP, ":") {
			cidr = gatewayIP + "/128"
		}
		defaults = append(defaults, struct {
			target string
			desc   string
		}{cidr, "Default Gateway Subnet Anchor"})
	}

	nowMs := time.Now().UnixMilli()
	for _, def := range defaults {
		if !existing[def.target] {
			if e.storage != nil {
				id, err := e.storage.AddWhitelistEntry(def.target, def.desc, "SYSTEM_SEED", nowMs)
				if err == nil {
					dbEntries = append(dbEntries, Entry{
						ID:          id,
						CIDROrIP:    def.target,
						Description: def.desc,
						AddedBy:     "SYSTEM_SEED",
						CreatedAtMs: nowMs,
					})
					existing[def.target] = true
					log.Printf("[WHITELIST] 🌱 Auto-seeded critical safeguard: %s (%s)", def.target, def.desc)
				}
			} else {
				dbEntries = append(dbEntries, Entry{
					CIDROrIP:    def.target,
					Description: def.desc,
					AddedBy:     "SYSTEM_SEED",
					CreatedAtMs: nowMs,
				})
				existing[def.target] = true
			}
		}
	}

	// Rebuild in-memory radix/CIDR cache atomically
	newExact := make(map[string]bool)
	var newSubnets []*net.IPNet

	for _, entry := range dbEntries {
		target := strings.TrimSpace(entry.CIDROrIP)
		if target == "" {
			continue
		}

		if strings.Contains(target, "/") {
			_, ipNet, err := net.ParseCIDR(target)
			if err == nil && ipNet != nil {
				newSubnets = append(newSubnets, ipNet)
				// Also add the network/host IP directly if single host (/32 or /128)
				ones, bits := ipNet.Mask.Size()
				if ones == bits {
					newExact[ipNet.IP.String()] = true
				}
			}
		} else {
			if ip := net.ParseIP(target); ip != nil {
				newExact[ip.String()] = true
				if ip.To4() != nil {
					_, ipNet, _ := net.ParseCIDR(target + "/32")
					if ipNet != nil {
						newSubnets = append(newSubnets, ipNet)
					}
				} else {
					_, ipNet, _ := net.ParseCIDR(target + "/128")
					if ipNet != nil {
						newSubnets = append(newSubnets, ipNet)
					}
				}
			}
		}
	}

	e.exactIPs = newExact
	e.subnets = newSubnets
	e.entries = dbEntries
	e.initialized = true

	log.Printf("[WHITELIST] ⚡ Cache reloaded: %d entries (%d exact IPs, %d subnets)",
		len(dbEntries), len(newExact), len(newSubnets))
	return nil
}

// AddEntry validates and persists a new CIDR or IP, atomically updating the in-memory cache.
func (e *Engine) AddEntry(cidrOrIP, description, addedBy string) (*Entry, error) {
	clean := strings.TrimSpace(cidrOrIP)
	if clean == "" {
		return nil, fmt.Errorf("empty CIDR or IP")
	}

	// Validate syntax: ParseCIDR or fallback to ParseIP
	normalized := clean
	if _, ipNet, err := net.ParseCIDR(clean); err == nil {
		normalized = ipNet.String()
	} else if ip := net.ParseIP(clean); ip != nil {
		if ip.To4() != nil {
			normalized = ip.String() + "/32"
		} else {
			normalized = ip.String() + "/128"
		}
	} else {
		return nil, fmt.Errorf("invalid CIDR or IP syntax: %s", clean)
	}

	if addedBy == "" {
		addedBy = "OPERATOR"
	}
	nowMs := time.Now().UnixMilli()

	var id int64
	if e.storage != nil {
		var err error
		id, err = e.storage.AddWhitelistEntry(normalized, description, addedBy, nowMs)
		if err != nil {
			return nil, fmt.Errorf("failed to persist whitelist entry: %w", err)
		}
	}

	entry := Entry{
		ID:          id,
		CIDROrIP:    normalized,
		Description: description,
		AddedBy:     addedBy,
		CreatedAtMs: nowMs,
	}

	_ = e.ReloadAndSeed()
	return &entry, nil
}

// DeleteEntry removes an entry by ID or CIDR/IP string. Prevents deletion of loopback (127.0.0.1, ::1).
func (e *Engine) DeleteEntry(id int64, cidrOrIP string) error {
	clean := strings.TrimSpace(cidrOrIP)

	// Guard: Prevent deletion of loopback
	if clean == "127.0.0.1" || clean == "127.0.0.1/32" || clean == "::1" || clean == "::1/128" {
		return fmt.Errorf("deletion rejected: loopback (%s) is a protected system safeguard", clean)
	}

	e.mu.RLock()
	if id > 0 {
		for _, item := range e.entries {
			if item.ID == id {
				if item.CIDROrIP == "127.0.0.1/32" || item.CIDROrIP == "::1/128" || item.CIDROrIP == "127.0.0.1" || item.CIDROrIP == "::1" {
					e.mu.RUnlock()
					return fmt.Errorf("deletion rejected: loopback is a protected system safeguard")
				}
				clean = item.CIDROrIP
				break
			}
		}
	}
	e.mu.RUnlock()

	if e.storage != nil {
		if err := e.storage.DeleteWhitelistEntry(id, clean); err != nil {
			return err
		}
	}

	_ = e.ReloadAndSeed()
	return nil
}

// ListEntries returns all active entries.
func (e *Engine) ListEntries() []Entry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]Entry, len(e.entries))
	copy(res, e.entries)
	return res
}

// Helper: Detect active host IP addresses
func detectLocalHostIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				if ip4 := ip.To4(); ip4 != nil {
					ips = append(ips, ip4.String())
				}
			}
		}
	}
	return ips
}

// Helper: Detect default gateway IP
func detectDefaultGateway() string {
	// Attempt dial out to common public endpoint without sending packets
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 100*time.Millisecond)
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			ip := localAddr.IP.To4()
			if ip != nil {
				// Commonly gateway is .1 in same /24
				gw := net.IPv4(ip[0], ip[1], ip[2], 1)
				return gw.String()
			}
		}
	}
	return ""
}
