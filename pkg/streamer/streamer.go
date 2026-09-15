package streamer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

const (
	DefaultQueueCapacity = 10000
	DefaultWorkerCount   = 4
)

// KernelEvent models the raw telemetry event extracted from in-kernel eBPF ring/perf buffers
type KernelEvent struct {
	Timestamp  string            `json:"timestamp"`
	SrcIP      string            `json:"src_ip"`
	DstIP      string            `json:"dst_ip"`
	SrcPort    uint16            `json:"src_port"`
	DstPort    uint16            `json:"dst_port"`
	Protocol   string            `json:"protocol"`
	Action     string            `json:"action"` // XDP_DROP, XDP_PASS, TARPIT
	Length     uint32            `json:"length"`
	Entropy    float64           `json:"entropy"`
	PayloadHex string            `json:"payload_hex,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// EventStreamer is the abstract interface consuming from eBPF ring/perf buffers
type EventStreamer interface {
	Start(ctx context.Context) error
	Stop() error
	Ingest(event *KernelEvent)
	GetStats() StreamerStats
}

// StreamerStats captures operational throughput and telemetry metrics
type StreamerStats struct {
	TotalIngested uint64 `json:"total_ingested"`
	TotalStreamed uint64 `json:"total_streamed"`
	TotalDropped  uint64 `json:"total_dropped"`
	ActiveWorkers int    `json:"active_workers"`
	QueueLength   int    `json:"queue_length"`
	QueueCapacity int    `json:"queue_capacity"`
}

// SIEMStreamer implements EventStreamer with standalone concurrent worker pools
type SIEMStreamer struct {
	eventChan   chan *KernelEvent
	output      io.Writer
	workerCount int
	stopChan    chan struct{}
	wg          sync.WaitGroup
	running     int32

	// Operational Metrics (Atomic)
	totalIngested uint64
	totalStreamed uint64
	totalDropped  uint64

	// Protects concurrent writes to output io.Writer
	writeMu sync.Mutex

	// Optional downstream consumer / broadcaster hook
	customHandler func(event *KernelEvent)
	handlerMu     sync.RWMutex
}

// NewSIEMStreamer constructs a standalone, decoupled SIEMStreamer
func NewSIEMStreamer(workerCount int, queueCap int, out io.Writer) *SIEMStreamer {
	if workerCount <= 0 {
		workerCount = DefaultWorkerCount
	}
	if queueCap <= 0 {
		queueCap = DefaultQueueCapacity
	}
	if out == nil {
		out = os.Stdout
	}

	return &SIEMStreamer{
		eventChan:   make(chan *KernelEvent, queueCap),
		output:      out,
		workerCount: workerCount,
		stopChan:    make(chan struct{}),
	}
}

// SetCustomHandler allows registering an in-memory broadcast handler (e.g., WebSocket fanout)
func (s *SIEMStreamer) SetCustomHandler(h func(event *KernelEvent)) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.customHandler = h
}

// Start spawns the concurrent worker pool to consume from the buffered channel
func (s *SIEMStreamer) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return errors.New("streamer is already running")
	}

	for i := 0; i < s.workerCount; i++ {
		s.wg.Add(1)
		go s.workerLoop(ctx, i)
	}

	log.Printf("[STREAMER] [READY] Initialized standalone SIEM worker pool (%d workers, %d buffer cap)",
		s.workerCount, cap(s.eventChan))
	return nil
}

// Ingest receives raw kernel events from the eBPF ring/perf buffer unconditionally
func (s *SIEMStreamer) Ingest(event *KernelEvent) {
	if event == nil {
		return
	}
	atomic.AddUint64(&s.totalIngested, 1)

	// Non-blocking enqueue with graceful drop under extreme backpressure
	select {
	case s.eventChan <- event:
	default:
		// Queue full: drop with counter
		atomic.AddUint64(&s.totalDropped, 1)
	}
}

// workerLoop drains the channel and formats events to the structured SIEM output
func (s *SIEMStreamer) workerLoop(ctx context.Context, workerID int) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			s.drainQueue()
			return
		case event, ok := <-s.eventChan:
			if !ok {
				return
			}
			s.processEvent(event)
		}
	}
}

// processEvent formats and dispatches the kernel event
func (s *SIEMStreamer) processEvent(event *KernelEvent) {
	if event == nil {
		return
	}

	// 1. Structured JSON output
	data, err := json.Marshal(event)
	if err == nil {
		data = append(data, '\n')
		s.writeMu.Lock()
		_, _ = s.output.Write(data)
		s.writeMu.Unlock()
		atomic.AddUint64(&s.totalStreamed, 1)
	}

	// 2. Broadcast to custom handler if registered
	s.handlerMu.RLock()
	h := s.customHandler
	s.handlerMu.RUnlock()

	if h != nil {
		h(event)
	}
}

// drainQueue flushes buffered events upon graceful shutdown
func (s *SIEMStreamer) drainQueue() {
	for {
		select {
		case event, ok := <-s.eventChan:
			if !ok {
				return
			}
			s.processEvent(event)
		default:
			return
		}
	}
}

// Stop gracefully terminates the worker pool
func (s *SIEMStreamer) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return nil
	}

	close(s.stopChan)
	s.wg.Wait()
	log.Printf("[STREAMER] [STOPPED] SIEM worker pool shutdown cleanly (Streamed: %d, Dropped: %d)",
		atomic.LoadUint64(&s.totalStreamed), atomic.LoadUint64(&s.totalDropped))
	return nil
}

// GetStats returns point-in-time metrics
func (s *SIEMStreamer) GetStats() StreamerStats {
	return StreamerStats{
		TotalIngested: atomic.LoadUint64(&s.totalIngested),
		TotalStreamed: atomic.LoadUint64(&s.totalStreamed),
		TotalDropped:  atomic.LoadUint64(&s.totalDropped),
		ActiveWorkers: s.workerCount,
		QueueLength:   len(s.eventChan),
		QueueCapacity: cap(s.eventChan),
	}
}
