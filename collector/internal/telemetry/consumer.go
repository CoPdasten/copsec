package telemetry

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// DropReason classifies the security rationale behind kernel-level XDP drops.
type DropReason uint8

const (
	DropReasonUnknown   DropReason = 0
	DropReasonLPMBlock  DropReason = 1
	DropReasonRateLimit DropReason = 2
	DropReasonSynFlood  DropReason = 3
	DropReasonMalformed DropReason = 4
)

// String returns human-readable name of the drop reason.
func (r DropReason) String() string {
	switch r {
	case DropReasonLPMBlock:
		return "LPM_BLOCK"
	case DropReasonRateLimit:
		return "RATE_LIMIT"
	case DropReasonSynFlood:
		return "SYN_FLOOD"
	case DropReasonMalformed:
		return "MALFORMED"
	default:
		return "UNKNOWN"
	}
}

// DropEvent binary layout matches kernel struct drop_event_t (strictly aligned to 64-bit boundaries).
// Total binary size: 4 (src_ip) + 4 (dst_ip) + 2 (src_port) + 2 (dst_port) + 1 (protocol) + 1 (drop_reason) + 2 (pad) + 8 (timestamp_ns) = 24 bytes.
type DropEvent struct {
	SrcIP       uint32     // 4 bytes: IPv4 source address in network order
	DstIP       uint32     // 4 bytes: IPv4 destination address in network order
	SrcPort     uint16     // 2 bytes: L4 source port (host order)
	DstPort     uint16     // 2 bytes: L4 destination port (host order)
	Protocol    uint8      // 1 byte:  IP protocol (e.g. 6=TCP, 17=UDP, 1=ICMP)
	DropReason  DropReason // 1 byte:  Drop reason classification
	Pad         [2]byte    // 2 bytes: 64-bit alignment padding
	TimestampNs uint64     // 8 bytes: Monotonic nanosecond timestamp (bpf_ktime_get_ns)
}

// DropEventSize defines the exact binary byte size of struct drop_event_t (24 bytes).
const DropEventSize = int(unsafe.Sizeof(DropEvent{}))

// Reset clears all fields of DropEvent for clean reuse in sync.Pool.
func (e *DropEvent) Reset() {
	*e = DropEvent{}
}

// SrcNetIP returns standard net.IP representation of the IPv4 source address.
func (e *DropEvent) SrcNetIP() net.IP {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], e.SrcIP)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// DstNetIP returns standard net.IP representation of the IPv4 destination address.
func (e *DropEvent) DstNetIP() net.IP {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], e.DstIP)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// IP returns standard net.IP representation of SrcIP for compatibility.
func (e *DropEvent) IP() net.IP {
	return e.SrcNetIP()
}

// ProtocolString returns human-readable L4 protocol name.
func (e *DropEvent) ProtocolString() string {
	switch e.Protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("IPPROTO_%d", e.Protocol)
	}
}

// ReasonString returns human-readable name of the drop reason.
func (e *DropEvent) ReasonString() string {
	return e.DropReason.String()
}

// String returns formatted event representation.
func (e *DropEvent) String() string {
	return fmt.Sprintf("DropEvent{Src=%s:%d, Dst=%s:%d, Proto=%s, Reason=%s, TimeNs=%d}",
		e.SrcNetIP(), e.SrcPort, e.DstNetIP(), e.DstPort, e.ProtocolString(), e.DropReason, e.TimestampNs)
}

// =============================================================================
//  sync.Pool Zero-Allocation Memory Invariance
// =============================================================================

var dropEventPool = sync.Pool{
	New: func() any {
		return new(DropEvent)
	},
}

// AcquireDropEvent leases a reusable *DropEvent from the pool with zero heap allocations.
func AcquireDropEvent() *DropEvent {
	e := dropEventPool.Get().(*DropEvent)
	e.Reset()
	return e
}

// ReleaseDropEvent safely returns a *DropEvent back to the pool for reuse.
func ReleaseDropEvent(e *DropEvent) {
	if e == nil {
		return
	}
	dropEventPool.Put(e)
}

// =============================================================================
//  Consumer Abstractions & Configuration
// =============================================================================

// HandlerFunc defines the callback invoked by worker pool routines to handle drop events.
type HandlerFunc func(ctx context.Context, event *DropEvent)

// ReaderSource defines interface for ring buffer readers allowing unit test mocking.
type ReaderSource interface {
	ReadInto(rec *ringbuf.Record) error
	Close() error
}

// Config defines worker pool and queue parameters.
type Config struct {
	// WorkerCount specifies the number of concurrent worker goroutines (defaults to runtime.NumCPU()).
	WorkerCount int
	// QueueCapacity defines the channel capacity for the fan-out queue (default: 65536).
	QueueCapacity int
}

// DefaultConfig returns optimal production settings scaling with system CPU cores.
func DefaultConfig() *Config {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	return &Config{
		WorkerCount:   workers,
		QueueCapacity: 65536,
	}
}

// Metrics captures real-time telemetry counters for the consumer pipeline.
type Metrics struct {
	EventsReceived uint64
	EventsDropped  uint64
	BytesReceived  uint64
	ReadErrors     uint64
	WorkersActive  int
	QueueDepth     int
}

// Consumer implements high-throughput, zero-allocation ring buffer ingestion.
type Consumer struct {
	reader    ReaderSource
	handler   HandlerFunc
	cfg       *Config
	eventChan chan *DropEvent
	running   atomic.Bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	// Metrics
	eventsRx      atomic.Uint64
	eventsDropped atomic.Uint64
	bytesRx       atomic.Uint64
	readErrors    atomic.Uint64
}

// NewConsumer initializes a consumer with an arbitrary ReaderSource.
func NewConsumer(source ReaderSource, handler HandlerFunc, cfg *Config) (*Consumer, error) {
	if source == nil {
		return nil, errors.New("reader source cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = runtime.NumCPU()
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 65536
	}

	return &Consumer{
		reader:    source,
		handler:   handler,
		cfg:       cfg,
		eventChan: make(chan *DropEvent, cfg.QueueCapacity),
	}, nil
}

// NewConsumerFromMap constructs a Consumer directly from an eBPF map of type BPF_MAP_TYPE_RINGBUF.
func NewConsumerFromMap(ringbufMap *ebpf.Map, handler HandlerFunc, cfg *Config) (*Consumer, error) {
	if ringbufMap == nil {
		return nil, errors.New("ringbufMap pointer cannot be nil")
	}
	if ringbufMap.Type() != ebpf.RingBuf {
		return nil, fmt.Errorf("expected map type RingBuf, got %s", ringbufMap.Type())
	}

	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to open ringbuf reader: %w", err)
	}

	return NewConsumer(rd, handler, cfg)
}

// Start spawns the reader and fan-out worker goroutines.
func (c *Consumer) Start(ctx context.Context) error {
	if c.running.Swap(true) {
		return errors.New("telemetry consumer is already running")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	// 1. Launch fan-out worker pool scaling with NumCPU
	for i := 0; i < c.cfg.WorkerCount; i++ {
		c.wg.Add(1)
		go c.workerLoop(runCtx)
	}

	// 2. Launch kernel ring buffer reader routine
	c.wg.Add(1)
	go c.readerLoop(runCtx)

	// Watcher to unblock reader when context is canceled externally
	go func() {
		<-runCtx.Done()
		_ = c.Close()
	}()

	return nil
}

// workerLoop drains events from the channel and recycles structs back to sync.Pool.
func (c *Consumer) workerLoop(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining events during shutdown to ensure zero memory leaks
			for {
				select {
				case event, ok := <-c.eventChan:
					if !ok {
						return
					}
					if c.handler != nil {
						c.handler(ctx, event)
					}
					ReleaseDropEvent(event)
				default:
					return
				}
			}
		case event, ok := <-c.eventChan:
			if !ok {
				return
			}
			if c.handler != nil {
				c.handler(ctx, event)
			}
			// Zero-allocation: struct recycled immediately after processing
			ReleaseDropEvent(event)
		}
	}
}

// readerLoop reads records from BPF ring buffer and dispatches without blocking.
func (c *Consumer) readerLoop(ctx context.Context) {
	defer c.wg.Done()
	defer close(c.eventChan)

	// Reusable ringbuf record across iterations (zero allocations)
	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := c.reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			c.readErrors.Add(1)
			time.Sleep(20 * time.Millisecond)
			continue
		}

		if len(record.RawSample) < DropEventSize {
			c.readErrors.Add(1)
			continue
		}

		c.bytesRx.Add(uint64(len(record.RawSample)))

		// Zero-allocation: lease DropEvent from sync.Pool
		event := AcquireDropEvent()

		// Zero-copy type reinterpretation directly from kernel memory buffer without reflection
		*event = *(*DropEvent)(unsafe.Pointer(&record.RawSample[0]))

		// Non-blocking backpressure pipeline:
		// If worker channels are saturated, drop event non-blockingly, increment atomic
		// dropped-event counter, and return the pooled struct to avoid memory leaks.
		select {
		case c.eventChan <- event:
			c.eventsRx.Add(1)
		default:
			c.eventsDropped.Add(1)
			ReleaseDropEvent(event)
		}
	}
}

// Metrics returns the live statistical counters of the consumer.
func (c *Consumer) Metrics() Metrics {
	return Metrics{
		EventsReceived: c.eventsRx.Load(),
		EventsDropped:  c.eventsDropped.Load(),
		BytesReceived:  c.bytesRx.Load(),
		ReadErrors:     c.readErrors.Load(),
		WorkersActive:  c.cfg.WorkerCount,
		QueueDepth:     len(c.eventChan),
	}
}

// Close gracefully terminates the consumer and releases ring buffer resources.
func (c *Consumer) Close() error {
	c.closeOnce.Do(func() {
		c.running.Store(false)
		if c.cancel != nil {
			c.cancel()
		}
		if c.reader != nil {
			c.closeErr = c.reader.Close()
		}
	})
	c.wg.Wait()
	return c.closeErr
}
