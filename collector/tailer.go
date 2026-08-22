package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
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
		if os.IsNotExist(err) {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(1 * time.Second):
				return nil
			}
		}
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	savedOffset := t.offsetManager.GetOffset(t.filePath)
	currentSize := stat.Size()

	var currentOffset int64
	if savedOffset > currentSize {
		// Log truncation detected (logrotate without copytruncate)
		log.Printf("[WARN] Log truncation detected on %s (offset: %d > size: %d). Resetting to 0.",
			t.filePath, savedOffset, currentSize)
		currentOffset = 0
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
	inotifyFd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		inotifyFd = -1
	} else {
		defer syscall.Close(inotifyFd)
		watchMask := uint32(syscall.IN_MODIFY | syscall.IN_MOVE_SELF | syscall.IN_DELETE_SELF)
		wd, err := syscall.InotifyAddWatch(inotifyFd, t.filePath, watchMask)
		if err == nil {
			defer syscall.InotifyRmWatch(inotifyFd, uint32(wd))
		}
	}

	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	// 250ms Hybrid Polling ticker to guarantee zero-miss on Linux inotify stalls / logrotate
	pollTicker := time.NewTicker(250 * time.Millisecond)
	defer pollTicker.Stop()

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

		case <-pollTicker.C:
			// Periodic size check to catch rotations or missed inotify events
			st, err := os.Stat(t.filePath)
			if err != nil {
				if os.IsNotExist(err) {
					// File moved / rotated
					log.Printf("[INFO] File %s temporarily unlinked. Waiting for recreate...", t.filePath)
					return nil
				}
			} else {
				if st.Size() < currentOffset {
					log.Printf("[INFO] File %s truncated (Size %d < Offset %d). Reopening...", t.filePath, st.Size(), currentOffset)
					return nil
				} else if st.Size() > currentOffset {
					currentOffset = t.readLines(reader, file, currentOffset)
					t.offsetManager.SetOffset(t.filePath, currentOffset)
				}
			}

		default:
			if inotifyFd < 0 {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			n, err := syscall.Read(inotifyFd, buf)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}

			if n < syscall.SizeofInotifyEvent {
				time.Sleep(50 * time.Millisecond)
				continue
			}

			offset := 0
			var rotatedOrDeleted bool
			for offset+syscall.SizeofInotifyEvent <= n {
				rawEvent := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
				mask := rawEvent.Mask

				if mask&(syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF) != 0 {
					rotatedOrDeleted = true
				}
				offset += syscall.SizeofInotifyEvent + int(rawEvent.Len)
			}

			// Read newly available lines
			currentOffset = t.readLines(reader, file, currentOffset)
			t.offsetManager.SetOffset(t.filePath, currentOffset)

			if rotatedOrDeleted {
				log.Printf("[INFO] Inotify detected rotation/deletion on %s. Reopening file...", t.filePath)
				return nil
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

// sendLogNonBlocking prevents tailer goroutines from stalling when buffer channel is saturated.
func (t *Tailer) sendLogNonBlocking(entry LogEntry) {
	select {
	case t.outChan <- entry:
	default:
		// Drop on saturated edge buffer to guarantee continuous file reading
	}
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
