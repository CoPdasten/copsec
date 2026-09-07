//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"log"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (t *Tailer) tailLoopPlatform(ctx context.Context, file *os.File, reader *bufio.Reader, stat os.FileInfo, currentOffset int64) error {
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
			// File rotation / truncation check
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
