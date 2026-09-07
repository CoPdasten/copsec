//go:build !linux

package ebpf

import (
	"os"
)

func sendSIGKILL(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// RefreshKernelSocketMap provides cross-platform mock/fallback implementation.
func (e *EDREngine) RefreshKernelSocketMap() error {
	// On non-Linux platforms, relies on in-memory registered tracepoint / socket mappings
	return nil
}
