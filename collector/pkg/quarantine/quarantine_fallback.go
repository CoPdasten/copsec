//go:build !linux && !windows

package quarantine

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// FallbackQuarantineDriver provides an in-memory mock quarantine for unsupported operating systems (e.g. Darwin, BSD).
type FallbackQuarantineDriver struct {
	mu         sync.RWMutex
	blockedIPs map[string]string
}

func init() {
	SetDefaultDriver(NewFallbackQuarantineDriver())
}

func NewFallbackQuarantineDriver() *FallbackQuarantineDriver {
	return &FallbackQuarantineDriver{
		blockedIPs: make(map[string]string),
	}
}

func (d *FallbackQuarantineDriver) IsSupported() bool {
	return false
}

func (d *FallbackQuarantineDriver) BlockIP(ip string, reason string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return fmt.Errorf("empty IP")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockedIPs[cleanIP] = reason
	log.Printf("[QUARANTINE_FALLBACK] In-memory isolation registered for IP %s (Reason: %s)", cleanIP, reason)
	return nil
}

func (d *FallbackQuarantineDriver) UnblockIP(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.blockedIPs, cleanIP)
	log.Printf("[QUARANTINE_FALLBACK] In-memory isolation removed for IP %s", cleanIP)
	return nil
}

func (d *FallbackQuarantineDriver) ListBlocked() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]string, 0, len(d.blockedIPs))
	for ip := range d.blockedIPs {
		res = append(res, ip)
	}
	return res, nil
}
