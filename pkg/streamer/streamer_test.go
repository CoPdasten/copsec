package streamer

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamer_Standalone_Streams(t *testing.T) {
	var out bytes.Buffer
	s := NewSIEMStreamer(4, 1000, &out)

	var receivedCount int32
	s.SetCustomHandler(func(e *KernelEvent) {
		atomic.AddInt32(&receivedCount, 1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	event := &KernelEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		SrcIP:     "10.0.0.5",
		DstIP:     "10.0.0.1",
		SrcPort:   1234,
		DstPort:   80,
		Protocol:  "TCP",
		Action:    "TARPIT",
		Length:    128,
	}

	ingestCount := 25
	for i := 0; i < ingestCount; i++ {
		s.Ingest(event)
	}

	time.Sleep(50 * time.Millisecond)
	_ = s.Stop()

	stats := s.GetStats()
	if stats.TotalStreamed != uint64(ingestCount) {
		t.Errorf("Expected %d streamed, got %d", ingestCount, stats.TotalStreamed)
	}
	if atomic.LoadInt32(&receivedCount) != int32(ingestCount) {
		t.Errorf("Expected %d received in handler, got %d", ingestCount, atomic.LoadInt32(&receivedCount))
	}
	if out.Len() == 0 {
		t.Errorf("Expected output buffer to contain JSON logs")
	}
}

func TestStreamer_Concurrent_Race(t *testing.T) {
	var out bytes.Buffer
	s := NewSIEMStreamer(4, 5000, &out)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = s.Start(ctx)

	var wg sync.WaitGroup
	workers := 8
	eventsPerWorker := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < eventsPerWorker; j++ {
				s.Ingest(&KernelEvent{
					Timestamp: time.Now().Format(time.RFC3339),
					SrcIP:     "192.168.1.50",
					DstIP:     "192.168.1.1",
					SrcPort:   uint16(1000 + j),
					DstPort:   443,
					Protocol:  "TCP",
					Action:    "XDP_DROP",
				})
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)
	_ = s.Stop()

	stats := s.GetStats()
	expectedTotal := uint64(workers * eventsPerWorker)
	if stats.TotalIngested != expectedTotal {
		t.Errorf("Expected %d ingested, got %d", expectedTotal, stats.TotalIngested)
	}
}
