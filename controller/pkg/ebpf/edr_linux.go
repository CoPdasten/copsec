//go:build linux

package ebpf

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func sendSIGKILL(pid int) error {
	// Attempt to kill entire process group first if leader
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return syscall.Kill(pid, syscall.SIGKILL)
}

// RefreshKernelSocketMap scans /proc/net/tcp, /proc/net/tcp6, /proc/net/udp and /proc/*/fd
// to correlate active network sockets with process PIDs and command lines.
func (e *EDREngine) RefreshKernelSocketMap() error {
	inodeToSocket := make(map[string]SocketTuple)

	// 1. Parse /proc/net/tcp and /proc/net/tcp6
	parseProcNetFile("/proc/net/tcp", "TCP", inodeToSocket)
	parseProcNetFile("/proc/net/tcp6", "TCP", inodeToSocket)
	parseProcNetFile("/proc/net/udp", "UDP", inodeToSocket)
	parseProcNetFile("/proc/net/udp6", "UDP", inodeToSocket)

	if len(inodeToSocket) == 0 {
		return nil
	}

	// 2. Scan /proc/[pid]/fd to map socket inode to PID
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}

			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				if tuple, found := inodeToSocket[inode]; found {
					procCtx := e.readProcessContext(pid)
					e.RegisterSocketProcess(procCtx, tuple)
				}
			}
		}
	}

	return nil
}

func (e *EDREngine) readProcessContext(pid int) ProcessContext {
	ctx := ProcessContext{
		PID:         pid,
		StartTimeMs: time.Now().UnixMilli(),
	}

	// Read comm
	if commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		ctx.Comm = strings.TrimSpace(string(commBytes))
	}

	// Read cmdline
	if cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		parts := strings.Split(string(cmdBytes), "\x00")
		ctx.CommandLine = strings.Join(parts, " ")
	}

	// Read exe symlink
	if exeLink, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		ctx.BinaryPath = exeLink
	}

	// Read stat for PPID
	if statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		fields := strings.Fields(string(statBytes))
		if len(fields) >= 4 {
			if ppid, err := strconv.Atoi(fields[3]); err == nil {
				ctx.PPID = ppid
			}
		}
	}

	return ctx
}

func parseProcNetFile(filePath, proto string, dest map[string]SocketTuple) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		localAddr := parseHexAddr(fields[1])
		remAddr := parseHexAddr(fields[2])
		inode := fields[9]

		if localAddr == "" || remAddr == "" || inode == "0" {
			continue
		}

		localIP, localPortStr, _ := net.SplitHostPort(localAddr)
		remIP, remPortStr, _ := net.SplitHostPort(remAddr)
		lPort, _ := strconv.Atoi(localPortStr)
		rPort, _ := strconv.Atoi(remPortStr)

		dest[inode] = SocketTuple{
			SrcIP:    localIP,
			SrcPort:  lPort,
			DstIP:    remIP,
			DstPort:  rPort,
			Protocol: proto,
		}
	}
}

func parseHexAddr(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return ""
	}

	ipHex := parts[0]
	portHex := parts[1]

	portVal, err := strconv.ParseInt(portHex, 16, 64)
	if err != nil {
		return ""
	}

	if len(ipHex) == 8 {
		// IPv4 in little-endian order
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 4 {
			return ""
		}
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return fmt.Sprintf("%s:%d", ip.String(), portVal)
	} else if len(ipHex) == 32 {
		// IPv6 in 4-byte little-endian dwords
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 16 {
			return ""
		}
		var ipBytes [16]byte
		for i := 0; i < 16; i += 4 {
			ipBytes[i] = b[i+3]
			ipBytes[i+1] = b[i+2]
			ipBytes[i+2] = b[i+1]
			ipBytes[i+3] = b[i]
		}
		ip := net.IP(ipBytes[:])
		return fmt.Sprintf("[%s]:%d", ip.String(), portVal)
	}

	return ""
}
