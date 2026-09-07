//go:build !linux

package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"time"
)

func (t *Tailer) tailLoopPlatform(ctx context.Context, file *os.File, reader *bufio.Reader, stat os.FileInfo, currentOffset int64) error {
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	pollTicker := time.NewTicker(100 * time.Millisecond)
	defer pollTicker.Stop()

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
			// File rotation / truncation check
			if currentFi, statErr := os.Stat(t.filePath); statErr != nil || !os.SameFile(stat, currentFi) || currentFi.Size() < currentOffset {
				log.Printf("[TAILER_RESET] File rotated or recreated for %s (%s). Rehooking...", t.source, t.filePath)
				t.offsetManager.SetOffset(t.filePath, 0)
				_ = t.offsetManager.Flush()
				return nil
			}

			currentOffset = t.readLines(reader, file, currentOffset)
			t.offsetManager.SetOffset(t.filePath, currentOffset)
		}
	}
}
