package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemMetrics represents real-time hardware telemetry from Linux kernel.
type SystemMetrics struct {
	CPUPercent   float32
	RAMUsedGB    float32
	RAMTotalGB   float32
	RAMUsedMB    float64
	DiskUsedPerc float32
}

// CollectSystemMetrics reads real-time RAM, CPU, and Disk metrics.
func CollectSystemMetrics() SystemMetrics {
	var m SystemMetrics

	// 1. RAM Calculation (/proc/meminfo)
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		var totalKB, availKB float64
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					totalKB, _ = strconv.ParseFloat(fields[1], 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					availKB, _ = strconv.ParseFloat(fields[1], 64)
				}
			}
		}
		if totalKB > 0 {
			m.RAMTotalGB = float32(totalKB / (1024 * 1024))
			usedKB := totalKB - availKB
			if usedKB < 0 {
				usedKB = 0
			}
			m.RAMUsedGB = float32(usedKB / (1024 * 1024))
			m.RAMUsedMB = usedKB / 1024.0
		}
	}

	// 2. CPU Calculation (Two samples from /proc/stat)
	m.CPUPercent = calculateCPUUsage()

	// 3. Disk Calculation (syscall.Statfs on root filesystem)
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		if total > 0 {
			m.DiskUsedPerc = float32(float64(total-free) / float64(total) * 100)
		}
	}

	return m
}

func calculateCPUUsage() float32 {
	readStat := func() (idle, total uint64) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 4 {
				var sum uint64
				for i, val := range fields[1:] {
					num, _ := strconv.ParseUint(val, 10, 64)
					sum += num
					if i == 3 { // idle field
						idle = num
					}
				}
				total = sum
			}
		}
		return
	}

	idle0, total0 := readStat()
	time.Sleep(80 * time.Millisecond)
	idle1, total1 := readStat()

	totalDiff := float64(total1 - total0)
	idleDiff := float64(idle1 - idle0)

	if totalDiff <= 0 {
		return 0
	}
	usage := (1.0 - (idleDiff / totalDiff)) * 100
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}
	return float32(usage)
}
