package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	copsecproto "github.com/copsec/collector/proto"
)

// BufferedRecord wraps a LogEvent with an incremental sequence ID on disk.
type BufferedRecord struct {
	ID        int64                 `json:"id"`
	Timestamp int64                 `json:"timestamp"`
	Event     *copsecproto.LogEvent `json:"event"`
}

// OfflineBuffer provides a robust, zero-Cgo, disk-backed FIFO queue for offline event buffering.
type OfflineBuffer struct {
	mu           sync.Mutex
	filePath     string
	appendFile   *os.File
	nextID       int64
	inMemorySize int
}

// NewOfflineBuffer initializes or recovers the offline buffer database.
func NewOfflineBuffer(targetPath string) (*OfflineBuffer, error) {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		targetPath = "./buffer.db"
	}

	buf := &OfflineBuffer{
		filePath: targetPath,
	}

	if err := buf.init(); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *OfflineBuffer) init() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Count existing records and find the maximum ID
	file, err := os.OpenFile(b.filePath, os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		return fmt.Errorf("failed to open buffer file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	var count int
	var maxID int64
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec BufferedRecord
		if err := json.Unmarshal(line, &rec); err == nil {
			count++
			if rec.ID > maxID {
				maxID = rec.ID
			}
		}
	}

	b.nextID = maxID + 1
	b.inMemorySize = count
	b.appendFile = file

	log.Printf("[INFO] Offline Buffer initialized (%s). Recovered %d pending records.", b.filePath, count)
	return nil
}

// Enqueue persists a LogEvent to the local disk buffer.
func (b *OfflineBuffer) Enqueue(event *copsecproto.LogEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	rec := BufferedRecord{
		ID:        b.nextID,
		Timestamp: time.Now().UnixMilli(),
		Event:     event,
	}
	b.nextID++

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	if _, err := b.appendFile.Write(data); err != nil {
		return fmt.Errorf("buffer disk write failed: %w", err)
	}

	_ = b.appendFile.Sync()
	b.inMemorySize++
	return nil
}

// Size returns the count of buffered pending events.
func (b *OfflineBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inMemorySize
}

// DequeueBatch reads up to maxBatch events from the front of the queue without deleting them.
func (b *OfflineBuffer) DequeueBatch(maxBatch int) ([]*copsecproto.LogEvent, []int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.inMemorySize == 0 {
		return nil, nil, nil
	}

	file, err := os.Open(b.filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var events []*copsecproto.LogEvent
	var ids []int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(events) < maxBatch {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec BufferedRecord
		if err := json.Unmarshal(line, &rec); err == nil && rec.Event != nil {
			events = append(events, rec.Event)
			ids = append(ids, rec.ID)
		}
	}

	return events, ids, scanner.Err()
}

// Ack removes acknowledged records up to the highest acked ID and compacts the buffer file.
func (b *OfflineBuffer) Ack(ackedIDs []int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(ackedIDs) == 0 {
		return nil
	}

	ackedMap := make(map[int64]bool, len(ackedIDs))
	for _, id := range ackedIDs {
		ackedMap[id] = true
	}

	// Close active write handle for compaction
	_ = b.appendFile.Close()

	srcFile, err := os.Open(b.filePath)
	if err != nil {
		return err
	}

	tmpPath := b.filePath + ".compact"
	dstFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		srcFile.Close()
		return err
	}

	scanner := bufio.NewScanner(srcFile)
	var remainingCount int
	writer := bufio.NewWriter(dstFile)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec BufferedRecord
		if err := json.Unmarshal(line, &rec); err == nil {
			if !ackedMap[rec.ID] {
				_, _ = writer.Write(line)
				_ = writer.WriteByte('\n')
				remainingCount++
			}
		}
	}

	_ = writer.Flush()
	srcFile.Close()
	dstFile.Close()

	if err := os.Rename(tmpPath, b.filePath); err != nil {
		return err
	}

	// Reopen append handle
	newAppendFile, err := os.OpenFile(b.filePath, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	b.appendFile = newAppendFile
	b.inMemorySize = remainingCount

	return nil
}

// Close gracefully closes the buffer file handles.
func (b *OfflineBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.appendFile != nil {
		return b.appendFile.Close()
	}
	return nil
}
