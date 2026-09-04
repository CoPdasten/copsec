package quarantine

// QuarantineDriver defines the unified cross-platform contract for host isolation
// and network firewall quarantine across Linux (iptables/eBPF/XDP) and Windows (netsh/Defender Firewall).
type QuarantineDriver interface {
	BlockIP(ip string, reason string) error
	UnblockIP(ip string) error
	ListBlocked() ([]string, error)
	IsSupported() bool
}

var defaultDriver QuarantineDriver

// SetDefaultDriver sets the active platform quarantine driver.
func SetDefaultDriver(driver QuarantineDriver) {
	defaultDriver = driver
}

// GetDriver returns the active platform quarantine driver.
func GetDriver() QuarantineDriver {
	return defaultDriver
}
