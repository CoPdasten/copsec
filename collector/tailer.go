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

// NewOffsetManager initializes an offset manager storing state in targetPath.
func NewOffsetManager(targetPath string) *OffsetManager {
	om := &OffsetManager{
		filePath: targetPath,
		offsets:  make(map[string]int64),
	}
	om.load()
	return om
}

func (om *OffsetManager) load() {
	om.mu.Lock()
	defer om.mu.Unlock()

	data, err := os.ReadFile(om.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] Failed to read offset file %s: %v", om.filePath, err)
		}
		return
	}

	var loaded map[string]int64
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[WARN] Failed to parse offset JSON %s: %v", om.filePath, err)
		return
	}
	om.offsets = loaded
}

// GetOffset returns the recorded byte offset for a given file path.
func (om *OffsetManager) GetOffset(path string) int64 {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.offsets[path]
}

// SetOffset stores in-memory offset and commits atomically to disk.
func (om *OffsetManager) SetOffset(path string, offset int64) {
	om.mu.Lock()
	om.offsets[path] = offset
	om.mu.Unlock()
}

// Flush writes the in-memory offsets map to disk atomically.
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
		// Log rotation or truncation occurred: restart from beginning
		log.Printf("[INFO] File truncated or rotated for %s (size: %d < savedOffset: %d). Resetting offset to 0.",
			t.filePath, currentSize, savedOffset)
		currentOffset = 0
	} else if savedOffset == 0 && currentSize > 0 {
		// If first run and no saved offset, seek to the end
		currentOffset = currentSize
		t.offsetManager.SetOffset(t.filePath, currentOffset)
	} else {
		currentOffset = savedOffset
	}

	if _, err := file.Seek(currentOffset, io.SeekStart); err != nil {
		return err
	}

	// Initialize Non-blocking Inotify
	inotifyFd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init failed: %w", err)
	}
	defer syscall.Close(inotifyFd)

	watchFlags := uint32(syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_MOVE_SELF | syscall.IN_DELETE_SELF)
	wd, err := syscall.InotifyAddWatch(inotifyFd, t.filePath, watchFlags)
	if err != nil {
		return fmt.Errorf("inotify_add_watch failed for %s: %w", t.filePath, err)
	}
	defer syscall.InotifyRmWatch(inotifyFd, uint32(wd))

	reader := bufio.NewReaderSize(file, 64*1024)
	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()

	// Initial read
	currentOffset = t.readLines(reader, file, currentOffset)
	t.offsetManager.SetOffset(t.filePath, currentOffset)

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
			n, err := syscall.Read(inotifyFd, buf)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
					// Check file size periodically in case inotify missed an event or to avoid spinning
					time.Sleep(50 * time.Millisecond)
					continue
				}
				return err
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
				t.outChan <- LogEntry{
					Source:    t.source,
					Line:      line,
					Timestamp: time.Now().UnixMilli(),
				}
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
