//go:build linux

package main

import "syscall"

func calculateDiskUsage() float32 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		if total > 0 {
			return float32(float64(total-free) / float64(total) * 100)
		}
	}
	return 0
}
