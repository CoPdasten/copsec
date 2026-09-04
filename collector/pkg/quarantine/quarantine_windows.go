//go:build windows

package quarantine

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WindowsQuarantineDriver implements QuarantineDriver using Windows Defender Firewall via netsh.exe.
type WindowsQuarantineDriver struct {
	mu         sync.RWMutex
	blockedIPs map[string]string // ip -> reason
}

func init() {
	SetDefaultDriver(NewWindowsQuarantineDriver())
}

// NewWindowsQuarantineDriver creates a new Windows quarantine driver instance.
func NewWindowsQuarantineDriver() *WindowsQuarantineDriver {
	driver := &WindowsQuarantineDriver{
		blockedIPs: make(map[string]string),
	}
	driver.checkAdminPrivileges()
	return driver
}

// checkAdminPrivileges verifies if the process runs elevated as Administrator via "net session".
func (d *WindowsQuarantineDriver) checkAdminPrivileges() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "net", "session")
	err := cmd.Run()
	if err != nil {
		log.Println("[WARN] Windows Administrator privileges required for firewall rule enforcement.")
		return false
	}
	return true
}

// IsSupported returns true if netsh is available on Windows.
func (d *WindowsQuarantineDriver) IsSupported() bool {
	_, err := exec.LookPath("netsh.exe")
	if err != nil {
		_, err = exec.LookPath("netsh")
	}
	return err == nil
}

// ruleName returns the deterministic CoPSeC rule name for an IP: CoPSeC_Block_<IP>
func ruleName(ip string) string {
	return fmt.Sprintf("CoPSeC_Block_%s", ip)
}

// ruleExists checks if a firewall rule with the given name already exists in Windows Defender Firewall.
func (d *WindowsQuarantineDriver) ruleExists(ctx context.Context, name string) bool {
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf("name=%s", name))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// "No rules match the specified criteria" when not found
	outStr := string(out)
	if strings.Contains(outStr, "Rule Name:") || strings.Contains(outStr, name) {
		return true
	}
	return false
}

// BlockIP adds an inbound firewall rule blocking the target IP via netsh advfirewall.
// Format: netsh advfirewall firewall add rule name="CoPSeC_Block_<IP>" dir=in action=block remoteip=<IP> description="CoPSeC Automated Quarantine: <Reason>"
func (d *WindowsQuarantineDriver) BlockIP(ip string, reason string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" || net.ParseIP(cleanIP) == nil {
		return fmt.Errorf("invalid IP: %s", cleanIP)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	rName := ruleName(cleanIP)
	if reason == "" {
		reason = "High Threat Score / Autonomous SOAR Violation"
	}
	description := fmt.Sprintf("CoPSeC Automated Quarantine: %s", reason)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Idempotency: check if rule already exists before creating
	if d.ruleExists(ctx, rName) {
		d.blockedIPs[cleanIP] = reason
		log.Printf("[QUARANTINE_WINDOWS] Rule %s already exists in Windows Firewall. Skipping addition.", rName)
		return nil
	}

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", rName),
		"dir=in",
		"action=block",
		fmt.Sprintf("remoteip=%s", cleanIP),
		fmt.Sprintf("description=%s", description),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		d.checkAdminPrivileges()
		return fmt.Errorf("netsh firewall block failed for IP %s: %w (%s)", cleanIP, err, strings.TrimSpace(stderr.String()))
	}

	d.blockedIPs[cleanIP] = reason
	log.Printf("[QUARANTINE_WINDOWS] ⚡ Enforced Windows Firewall Block: %s (IP: %s, Reason: %s)", rName, cleanIP, reason)
	return nil
}

// UnblockIP deletes the quarantine firewall rule for the specified IP.
// Format: netsh advfirewall firewall delete rule name="CoPSeC_Block_<IP>"
func (d *WindowsQuarantineDriver) UnblockIP(ip string) error {
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return fmt.Errorf("empty IP")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	rName := ruleName(cleanIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", rName),
	)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	// Ignore error if deleting a non-existent rule (safely handle idempotency)
	_ = cmd.Run()

	delete(d.blockedIPs, cleanIP)
	log.Printf("[QUARANTINE_WINDOWS] 🟢 Removed Windows Firewall Block: %s (IP: %s)", rName, cleanIP)
	return nil
}

// ListBlocked queries all active CoPSeC_Block_* rules from Windows Firewall.
func (d *WindowsQuarantineDriver) ListBlocked() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to in-memory map
		res := make([]string, 0, len(d.blockedIPs))
		for ip := range d.blockedIPs {
			res = append(res, ip)
		}
		return res, nil
	}

	var found []string
	lines := strings.Split(string(out), "\n")
	prefix := "CoPSeC_Block_"
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Rule Name:") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				if strings.HasPrefix(name, prefix) {
					ip := strings.TrimPrefix(name, prefix)
					found = append(found, ip)
				}
			}
		}
	}

	// Merge with tracked in-memory map
	seen := make(map[string]bool)
	for _, ip := range found {
		seen[ip] = true
	}
	for ip := range d.blockedIPs {
		if !seen[ip] {
			found = append(found, ip)
		}
	}

	return found, nil
}
