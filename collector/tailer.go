package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	copsecproto "github.com/copsec/collector/proto"
	"golang.org/x/sys/unix"
)

// OffsetManager handles loading and persisting file read offsets.
type OffsetManager struct {
	mu       sync.RWMutex
	filePath string
	offsets  map[string]int64
}

// NewOffsetManager initializes an OffsetManager with offset persistence.
func NewOffsetManager(filePath string) *OffsetManager {
	om := &OffsetManager{
		filePath: filePath,
		offsets:  make(map[string]int64),
	}
	_ = om.Load()
	return om
}

// Load reads previously saved byte offsets from disk.
func (om *OffsetManager) Load() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	data, err := os.ReadFile(om.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &om.offsets)
}

// GetOffset returns the stored offset for a file.
func (om *OffsetManager) GetOffset(path string) int64 {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.offsets[path]
}

// SetOffset stores the updated offset for a file in memory.
func (om *OffsetManager) SetOffset(path string, offset int64) {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.offsets[path] = offset
}

// Flush persists in-memory offsets to disk atomically.
func (om *OffsetManager) Flush() error {
	om.mu.RLock()
	data, err := json.MarshalIndent(om.offsets, "", "  ")
	om.mu.RUnlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(om.filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", om.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmpFile, om.filePath)
}

// Tailer watches a single log file using inotify and streams lines.
type Tailer struct {
	source        string
	filePath      string
	offsetManager *OffsetManager
	outChan       chan<- LogEntry
}

// NewTailer creates a new tailer instance.
func NewTailer(source, filePath string, om *OffsetManager, outChan chan<- LogEntry) *Tailer {
	return &Tailer{
		source:        source,
		filePath:      filePath,
		offsetManager: om,
		outChan:       outChan,
	}
}

// Start begins the tailing loop until ctx is canceled.
func (t *Tailer) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC_RECOVER] Tailer for %s recovered: %v", t.filePath, r)
		}
	}()

	log.Printf("[INFO] Starting Tailer for [%s] -> %s", t.source, t.filePath)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Stopping Tailer for %s", t.filePath)
			return
		default:
			if err := t.tailFile(ctx); err != nil {
				if errors.Is(ctx.Err(), context.Canceled) {
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

func (t *Tailer) tailFile(ctx context.Context) error {
	// Strictly Read-Only Open
	file, err := os.OpenFile(t.filePath, os.O_RDONLY, 0)
	if err != nil {
		log.Printf("[TAILER_ERROR] Cannot open %s (%s): %v. Retrying in 3s...", t.source, t.filePath, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
			return nil
		}
	}
	defer file.Close()
	log.Printf("[TAILER_ACTIVE] Successfully hooked to %s (%s)", t.source, t.filePath)

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	savedOffset := t.offsetManager.GetOffset(t.filePath)
	currentSize := stat.Size()

	var currentOffset int64
	if savedOffset <= 0 {
		// First start: Seek to EOF (io.SeekEnd) to only stream fresh real-time events
		currentOffset = currentSize
		log.Printf("[TAILER] 🚀 Real-time tail active for [%s] -> %s (Started at EOF, Offset: %d)", t.source, t.filePath, currentOffset)
	} else if savedOffset > currentSize {
		// Log truncation detected (logrotate without copytruncate)
		log.Printf("[WARN] Log truncation detected on %s (offset: %d > size: %d). Resetting to EOF.",
			t.filePath, savedOffset, currentSize)
		currentOffset = currentSize
	} else {
		currentOffset = savedOffset
	}

	if _, err := file.Seek(currentOffset, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(file)

	// Catch up on unread lines
	currentOffset = t.readLines(reader, file, currentOffset)
	t.offsetManager.SetOffset(t.filePath, currentOffset)

	// Setup non-blocking inotify watch
	inotifyFd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		inotifyFd = -1
	} else {
		defer unix.Close(inotifyFd)
		watchMask := uint32(unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF)
		wd, err := unix.InotifyAddWatch(inotifyFd, t.filePath, watchMask)
		if err == nil {
			defer unix.InotifyRmWatch(inotifyFd, uint32(wd))
		}
	}

	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	pollFds := []unix.PollFd{
		{Fd: int32(inotifyFd), Events: unix.POLLIN},
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			t.offsetManager.SetOffset(t.filePath, currentOffset)
			_ = t.offsetManager.Flush()
			return nil

		case <-flushTicker.C:
			t.offsetManager.SetOffset(t.filePath, currentOffset)
			_ = t.offsetManager.Flush()

		default:
			// Dosya silindi mi / inode değişti mi / logrotate truncate mi oldu kontrolü
			if currentFi, statErr := os.Stat(t.filePath); statErr != nil || !os.SameFile(stat, currentFi) || currentFi.Size() < currentOffset {
				log.Printf("[TAILER_RESET] File rotated or recreated for %s (%s). Rehooking...", t.source, t.filePath)
				t.offsetManager.SetOffset(t.filePath, 0)
				_ = t.offsetManager.Flush()
				return nil
			}

			if inotifyFd < 0 {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(100 * time.Millisecond):
					currentOffset = t.readLines(reader, file, currentOffset)
					t.offsetManager.SetOffset(t.filePath, currentOffset)
					continue
				}
			}

			// Event-driven wait: returns immediately (0ms delay) on inotify events
			nEvents, err := unix.Poll(pollFds, 200)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}

			if nEvents > 0 && (pollFds[0].Revents&unix.POLLIN) != 0 {
				n, err := unix.Read(inotifyFd, buf)
				if err != nil {
					if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
						continue
					}
					continue
				}

				if n >= unix.SizeofInotifyEvent {
					offset := 0
					var rotatedOrDeleted bool
					for offset+unix.SizeofInotifyEvent <= n {
						rawEvent := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
						mask := rawEvent.Mask

						if mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 {
							rotatedOrDeleted = true
						}
						offset += unix.SizeofInotifyEvent + int(rawEvent.Len)
					}

					// Read newly available lines immediately
					currentOffset = t.readLines(reader, file, currentOffset)
					t.offsetManager.SetOffset(t.filePath, currentOffset)

					if rotatedOrDeleted {
						log.Printf("[INFO] Inotify detected rotation/deletion on %s. Reopening file...", t.filePath)
						return nil
					}
				}
			}
		}
	}
}

func (t *Tailer) readLines(reader *bufio.Reader, file *os.File, currentOffset int64) int64 {
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			currentOffset += int64(len(line))
			// Trim newline / CR
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
			}

			if len(line) > 0 {
				if isNoisyCollectorLog(line) {
					continue
				}

				// Dispatch to stream/buffer pipeline
				entry := LogEntry{
					Source:    t.source,
					Line:      line,
					Timestamp: time.Now().UnixMilli(),
				}
				t.sendLogNonBlocking(entry)
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
	}
	return currentOffset
}

// extractIPFromLine extracts client IP from Nginx, SSH, or Syslog raw lines.
func extractIPFromLine(rawLine, source string) string {
	lower := strings.ToLower(rawLine)
	// Internal OS / host-local execution commands must NEVER bind to arbitrary network IPs
	if strings.Contains(lower, "sudo:") ||
		strings.Contains(lower, "cron[") ||
		strings.Contains(lower, "systemd[") ||
		strings.Contains(lower, "pam_unix(sudo") ||
		strings.Contains(lower, "pam_unix(cron") {
		return "127.0.0.1"
	}

	fields := strings.Fields(rawLine)
	if len(fields) == 0 {
		return ""
	}

	// 1. Nginx Combined / Custom Format: First token is usually Client IP
	if source == "nginx" {
		cand := fields[0]
		cand = strings.Trim(cand, `",[]`)
		if net.ParseIP(cand) != nil {
			return cand
		}
	}

	// 2. SSH / Auth Log: "from <IP> port" or "for <user> from <IP>" or "rhost=<IP>"
	if source == "ssh" || source == "auth" {
		for i, w := range fields {
			if strings.EqualFold(w, "from") && i+1 < len(fields) {
				cand := strings.Trim(fields[i+1], `",[]:;()`)
				if net.ParseIP(cand) != nil {
					return cand
				}
			}
			if strings.HasPrefix(strings.ToLower(w), "rhost=") {
				cand := strings.TrimPrefix(w, "rhost=")
				cand = strings.Trim(cand, `",[]:;()`)
				if net.ParseIP(cand) != nil {
					return cand
				}
			}
		}
		// Host-local authentication without remote IP
		return "127.0.0.1"
	}

	// 3. Fallback Generic IPv4/IPv6 Scanner (only for non-auth network logs)
	for _, f := range fields {
		cleaned := strings.Trim(f, `",[]:;()`)
		if ip := net.ParseIP(cleaned); ip != nil {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return cleaned
			}
		}
	}

	return ""
}

// sendLogNonBlocking prevents tailer goroutines from stalling when buffer channel is saturated.
func (t *Tailer) sendLogNonBlocking(entry LogEntry) {
	select {
	case t.outChan <- entry:
	default:
		// Queue saturated: skip line non-blockingly to guarantee zero reader lockup
	}
}

// SuricataBase models Suricata Eve JSON log records.
type SuricataBase struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Alert     *struct {
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		SignatureID int    `json:"signature_id"`
	} `json:"alert,omitempty"`
}

// parseSuricataLine unmarshals Suricata eve.json lines directly without raw regex.
func parseSuricataLine(line string) (*copsecproto.LogEvent, bool) {
	var s SuricataBase
	if err := json.Unmarshal([]byte(line), &s); err != nil {
		return nil, false
	}

	// Filter out periodic Suricata heartbeat / stats telemetry from incident stream
	if s.EventType == "stats" || s.EventType == "heartbeat" {
		return nil, false
	}

	threatScore := int32(0)
	ruleID := "suricata_flow"
	mitreID := ""

	if s.EventType == "alert" && s.Alert != nil {
		threatScore = 85
		ruleID = s.Alert.Signature
		if ruleID == "" {
			ruleID = fmt.Sprintf("suricata_alert_%d", s.Alert.SignatureID)
		}
		if ruleID == "suricata_alert_0" || ruleID == "" {
			ruleID = "suricata_ids_alert"
		}
		sigLower := strings.ToLower(s.Alert.Signature)
		catLower := strings.ToLower(s.Alert.Category)
		if strings.Contains(sigLower, "sqli") || strings.Contains(sigLower, "sql injection") ||
			strings.Contains(sigLower, "rce") || strings.Contains(sigLower, "exploit") ||
			strings.Contains(sigLower, "command injection") || strings.Contains(catLower, "web") ||
			strings.Contains(sigLower, "traversal") {
			mitreID = "T1190"
		} else if strings.Contains(sigLower, "scan") || strings.Contains(catLower, "scan") {
			mitreID = "T1046"
		} else if strings.Contains(sigLower, "brute") || strings.Contains(sigLower, "login") {
			mitreID = "T1110"
		} else if strings.Contains(sigLower, "c2") || strings.Contains(sigLower, "beacon") {
			mitreID = "T1071"
		} else {
			mitreID = "T1190"
		}
	} else if s.EventType == "dns" {
		ruleID = "suricata_dns"
		threatScore = 0
		mitreID = ""
	} else {
		ruleID = "suricata_flow"
		threatScore = 0
		mitreID = ""
	}

	if isProtectedIP(s.SrcIP) {
		threatScore = 0
		mitreID = ""
	}

	ts := time.Now().UnixMilli()
	if s.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, s.Timestamp); err == nil {
			ts = t.UnixMilli()
		} else if t, err := time.Parse(time.RFC3339, s.Timestamp); err == nil {
			ts = t.UnixMilli()
		}
	}

	return &copsecproto.LogEvent{
		Source:           "suricata",
		ClientIp:         s.SrcIP,
		RawLine:          line,
		ThreatScore:      threatScore,
		RuleId:           ruleID,
		MitreTechniqueId: mitreID,
		TimestampMs:      ts,
	}, true
}

// parseAuthLine extracts standard Linux SSH and Auth patterns.
func parseAuthLine(line string) (*copsecproto.LogEvent, bool) {
	ip := extractIPFromLine(line, "auth")
	threatScore := int32(0)
	ruleID := "auth_event"
	mitreID := ""

	if strings.Contains(line, "Failed password") || strings.Contains(line, "authentication failure") || strings.Contains(line, "Invalid user") {
		threatScore = 70
		ruleID = "ssh_failed_password"
		mitreID = "T1110.001"
	} else if strings.Contains(line, "Accepted password") || strings.Contains(line, "Accepted publickey") {
		threatScore = 0
		ruleID = "ssh_login_success"
	} else if strings.Contains(line, "sudo:") && strings.Contains(line, "COMMAND=") {
		threatScore = 20
		ruleID = "sudo_execution"
		mitreID = "T1078"
		ip = "127.0.0.1"
	}

	if isProtectedIP(ip) && ruleID != "sudo_execution" {
		threatScore = 0
	}

	return &copsecproto.LogEvent{
		Source:           "auth",
		ClientIp:         ip,
		RawLine:          line,
		ThreatScore:      threatScore,
		RuleId:           ruleID,
		MitreTechniqueId: mitreID,
		TimestampMs:      time.Now().UnixMilli(),
	}, true
}

// parseLogLine normalizes raw lines across all source types (Suricata JSON, Auth regex, Nginx, Syslog, Audit).
func parseLogLine(sourceName, raw string) *copsecproto.LogEvent {
	nowMs := time.Now().UnixMilli()
	srcLower := strings.ToLower(sourceName)

	switch {
	case srcLower == "suricata" || strings.Contains(srcLower, "eve.json") || strings.Contains(srcLower, "suricata"):
		var s SuricataBase
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			threatScore := int32(0)
			ruleID := "suricata_flow"
			mitreID := ""
			if s.EventType == "alert" && s.Alert != nil {
				threatScore = 85
				ruleID = s.Alert.Signature
				if ruleID == "" {
					ruleID = "suricata_ids_alert"
				}
				sigLower := strings.ToLower(s.Alert.Signature)
				catLower := strings.ToLower(s.Alert.Category)
				if strings.Contains(sigLower, "sqli") || strings.Contains(sigLower, "sql injection") ||
					strings.Contains(sigLower, "rce") || strings.Contains(sigLower, "exploit") ||
					strings.Contains(sigLower, "command injection") || strings.Contains(catLower, "web") ||
					strings.Contains(sigLower, "traversal") {
					mitreID = "T1190"
				} else if strings.Contains(sigLower, "scan") || strings.Contains(catLower, "scan") {
					mitreID = "T1046"
				} else if strings.Contains(sigLower, "brute") || strings.Contains(sigLower, "login") {
					mitreID = "T1110"
				} else if strings.Contains(sigLower, "c2") || strings.Contains(sigLower, "beacon") {
					mitreID = "T1071"
				} else {
					mitreID = "T1190"
				}
			} else if s.EventType == "dns" {
				ruleID = "suricata_dns"
				threatScore = 0
				mitreID = ""
			} else {
				ruleID = "suricata_flow"
				threatScore = 0
				mitreID = ""
			}

			if isProtectedIP(s.SrcIP) {
				threatScore = 0
				mitreID = ""
			}

			ts := nowMs
			if s.Timestamp != "" {
				if t, err := time.Parse(time.RFC3339Nano, s.Timestamp); err == nil {
					ts = t.UnixMilli()
				} else if t, err := time.Parse(time.RFC3339, s.Timestamp); err == nil {
					ts = t.UnixMilli()
				}
			}
			return &copsecproto.LogEvent{
				Source:           "suricata",
				RawLine:          raw,
				ClientIp:         s.SrcIP,
				ThreatScore:      threatScore,
				RuleId:           ruleID,
				MitreTechniqueId: mitreID,
				TimestampMs:      ts,
			}
		}
		// JSON parse edilemezse ham log olarak ilet
		return &copsecproto.LogEvent{
			Source:      "suricata",
			RawLine:     raw,
			ClientIp:    extractIPFromLine(raw, "suricata"),
			TimestampMs: nowMs,
		}

	case srcLower == "auth" || srcLower == "ssh" || strings.Contains(srcLower, "auth.log"):
		threatScore := int32(0)
		ruleID := "auth_event"
		mitreID := ""
		ip := extractIPFromLine(raw, "auth")
		if strings.Contains(raw, "Failed password") || strings.Contains(raw, "authentication failure") || strings.Contains(raw, "Invalid user") {
			threatScore = 70
			ruleID = "ssh_failed_password"
			mitreID = "T1110.001"
		} else if strings.Contains(raw, "Accepted password") || strings.Contains(raw, "Accepted publickey") {
			threatScore = 0
			ruleID = "ssh_login_success"
		} else if strings.Contains(raw, "sudo:") && strings.Contains(raw, "COMMAND=") {
			threatScore = 20
			ruleID = "sudo_execution"
			mitreID = "T1078"
			ip = "127.0.0.1"
		}
		return &copsecproto.LogEvent{
			Source:           "auth",
			RawLine:          raw,
			ClientIp:         ip,
			ThreatScore:      threatScore,
			RuleId:           ruleID,
			MitreTechniqueId: mitreID,
			TimestampMs:      nowMs,
		}

	default: // nginx, syslog, audit
		ip := extractIPFromLine(raw, sourceName)
		statusCode := int32(ExtractHTTPStatus(raw))
		return &copsecproto.LogEvent{
			Source:      sourceName,
			RawLine:     raw,
			ClientIp:    ip,
			StatusCode:  statusCode,
			TimestampMs: nowMs,
		}
	}
}

// ParseLogSourceLine dispatches raw line parsing based on source or filepath.
func ParseLogSourceLine(source, line string, defaultTimestamp int64) *copsecproto.LogEvent {
	ev := parseLogLine(source, line)
	if defaultTimestamp > 0 && ev.TimestampMs == 0 {
		ev.TimestampMs = defaultTimestamp
	}
	return ev
}

// isNoisyCollectorLog drops self-generated feedback loop lines and background noise.
func isNoisyCollectorLog(rawLine string) bool {
	lower := strings.ToLower(rawLine)
	if strings.Contains(lower, "copsec-collector") ||
		strings.Contains(lower, "[collector_event]") ||
		strings.Contains(lower, "[soar_command]") ||
		strings.Contains(lower, "[soar_ack]") ||
		strings.Contains(lower, "tailscaled") ||
		strings.Contains(lower, "magicsock") ||
		strings.Contains(lower, "open-conn-track") ||
		strings.Contains(lower, "sysstat-collect") ||
		strings.Contains(lower, "systemd-resolved") ||
		strings.Contains(lower, "systemd-logind") ||
		strings.Contains(lower, "systemd[") ||
		strings.Contains(lower, "pam_unix(sudo:session)") ||
		strings.Contains(lower, "pam_unix(cron:session)") ||
		strings.Contains(lower, "session closed for user") ||
		(strings.Contains(lower, "cron[") && strings.Contains(lower, "session closed")) ||
		(strings.Contains(lower, "session opened for user root") && strings.Contains(lower, "by (uid=0)")) ||
		strings.Contains(lower, "starting clean php session") {
		return true
	}
	return false
}
