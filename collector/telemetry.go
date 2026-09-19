package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

	// 3. Disk Calculation
	m.DiskUsedPerc = calculateDiskUsage()

	return m
}

var (
	cpuMu         sync.Mutex
	lastStatTotal uint64
	lastProcTicks uint64
	lastStatUsage float32
)

func calculateCPUUsage() float32 {
	cpuMu.Lock()
	defer cpuMu.Unlock()

	var procTicks uint64
	if statData, err := os.ReadFile("/proc/self/stat"); err == nil {
		str := string(statData)
		if idx := strings.LastIndex(str, ")"); idx >= 0 && idx+2 < len(str) {
			fields := strings.Fields(str[idx+2:])
			if len(fields) >= 13 {
				u, _ := strconv.ParseUint(fields[11], 10, 64)
				s, _ := strconv.ParseUint(fields[12], 10, 64)
				procTicks = u + s
			}
		}
	}

	readStatTotal := func() (total uint64, ok bool) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return 0, false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 4 && fields[0] == "cpu" {
				var sum uint64
				for _, val := range fields[1:] {
					num, _ := strconv.ParseUint(val, 10, 64)
					sum += num
				}
				return sum, true
			}
		}
		return 0, false
	}

	total, ok := readStatTotal()
	if !ok {
		return lastStatUsage
	}

	if lastStatTotal == 0 || (procTicks > 0 && lastProcTicks == 0) {
		lastStatTotal = total
		lastProcTicks = procTicks
		return 0.0
	}

	totalDiff := float64(total - lastStatTotal)
	lastStatTotal = total

	if totalDiff <= 0 {
		return lastStatUsage
	}

	if procTicks > 0 && lastProcTicks > 0 {
		procDiff := float64(procTicks - lastProcTicks)
		lastProcTicks = procTicks
		numCPU := float64(runtime.NumCPU())
		if numCPU <= 0 {
			numCPU = 1.0
		}
		usage := float32((procDiff / totalDiff) * 100.0 * numCPU)
		if usage < 0 {
			usage = 0
		}
		if usage > 100 {
			usage = 100
		}
		lastStatUsage = usage
		return usage
	}

	return lastStatUsage
}
