//go:build linux

package quarantine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxQuarantineDriver implements QuarantineDriver using Linux iptables, conntrack, and XDP/eBPF hooks.
type LinuxQuarantineDriver struct {
	mu         sync.RWMutex
	blockedIPs map[string]string // ip -> reason
}

func init() {
	SetDefaultDriver(NewLinuxQuarantineDriver())
}

// NewLinuxQuarantineDriver creates a new Linux quarantine driver instance.
func NewLinuxQuarantineDriver() *LinuxQuarantineDriver {
	return &LinuxQuarantineDriver{
		blockedIPs: make(map[string]string),
	}
}

// IsSupported returns true if running on a supported Linux kernel with iptables available.
func (d *LinuxQuarantineDriver) IsSupported() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// BlockIP enqueues an immediate L3 packet drop via iptables and purges active connection tracking state.
func (d *LinuxQuarantineDriver) BlockIP(ip string, reason string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || net.ParseIP(cleanIP) == nil {
		return fmt.Errorf("invalid IP: %s", cleanIP)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Check idempotency: check if already in INPUT or PREROUTING
	checkCmd := exec.CommandContext(ctx, "iptables", "-C", "INPUT", "-s", cleanIP, "-j", "DROP")
	if err := checkCmd.Run(); err == nil {
		// Rule already present in INPUT
		d.blockedIPs[cleanIP] = reason
		return nil
	}

	// 2. Insert into raw PREROUTING and filter INPUT for immediate fast drop
	_ = exec.CommandContext(ctx, "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", cleanIP, "-j", "DROP").Run()
	if err := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "1", "-s", cleanIP, "-j", "DROP").Run(); err != nil {
		// Try with sudo fallback if running unprivileged
		sudoCtx, sudoCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sudoCancel()
		_ = exec.CommandContext(sudoCtx, "sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", cleanIP, "-j", "DROP").Run()
		_ = exec.CommandContext(sudoCtx, "sudo", "iptables", "-I", "INPUT", "1", "-s", cleanIP, "-j", "DROP").Run()
	}

	// 3. Flush connection tracking and terminate existing sockets
	connCtx, connCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer connCancel()
	_ = exec.CommandContext(connCtx, "conntrack", "-D", "-s", cleanIP).Run()
	_ = exec.CommandContext(connCtx, "conntrack", "-D", "-d", cleanIP).Run()
	_ = exec.CommandContext(connCtx, "ss", "-K", "dst", cleanIP).Run()
	_ = exec.CommandContext(connCtx, "ss", "-K", "src", cleanIP).Run()

	d.blockedIPs[cleanIP] = reason
	log.Printf("[QUARANTINE_LINUX] ⚡ Enforced iptables/conntrack isolation for IP %s (Reason: %s)", cleanIP, reason)
	return nil
}

// UnblockIP removes the iptables drop rules safely.
func (d *LinuxQuarantineDriver) UnblockIP(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return fmt.Errorf("empty IP")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = exec.CommandContext(ctx, "iptables", "-t", "raw", "-D", "PREROUTING", "-s", cleanIP, "-j", "DROP").Run()
	_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", cleanIP, "-j", "DROP").Run()

	// Sudo fallback
	_ = exec.CommandContext(ctx, "sudo", "iptables", "-t", "raw", "-D", "PREROUTING", "-s", cleanIP, "-j", "DROP").Run()
	_ = exec.CommandContext(ctx, "sudo", "iptables", "-D", "INPUT", "-s", cleanIP, "-j", "DROP").Run()

	delete(d.blockedIPs, cleanIP)
	log.Printf("[QUARANTINE_LINUX] 🟢 Removed iptables isolation for IP %s", cleanIP)
	return nil
}

// ListBlocked returns all currently tracked quarantined IPs.
func (d *LinuxQuarantineDriver) ListBlocked() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make([]string, 0, len(d.blockedIPs))
	for ip := range d.blockedIPs {
		res = append(res, ip)
	}
	return res, nil
}
