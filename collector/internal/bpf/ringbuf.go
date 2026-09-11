package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// DropReason classifies the security rationale behind kernel-level XDP drops.
type DropReason uint8

const (
	DropReasonUnknown        DropReason = 0
	DropReasonSynFlood       DropReason = 1
	DropReasonL7DpiSignature DropReason = 2
	DropReasonEntropyAnomaly DropReason = 3
	DropReasonRateLimit      DropReason = 4
)

// String returns the human-readable canonical representation of the drop reason.
func (r DropReason) String() string {
	switch r {
	case DropReasonSynFlood:
		return "SYN_FLOOD"
	case DropReasonL7DpiSignature:
		return "L7_DPI_SIGNATURE"
	case DropReasonEntropyAnomaly:
		return "ENTROPY_ANOMALY"
	case DropReasonRateLimit:
		return "RATE_LIMIT"
	default:
		return "UNKNOWN"
	}
}

// DropEvent binary layout matches struct drop_event_t (strictly aligned to 64-bit boundaries).
// Total binary size: 4 + 2 + 2 + 1 + 7 + 8 = 24 bytes.
type DropEvent struct {
	SrcIP       uint32     // IPv4 source address in network order
	SrcPort     uint16     // L4 source port (host order)
	Protocol    uint16     // L4 protocol (e.g. 6=TCP, 17=UDP)
	DropReason  DropReason // Reason classification
	Pad         [7]byte    // 64-bit alignment padding
	TimestampNs uint64     // Kernel monotonic/ktime timestamp in nanoseconds
}

// DropEventSize defines the exact binary byte size of struct drop_event_t.
const DropEventSize = int(unsafe.Sizeof(DropEvent{}))

// IP converts the network-order IPv4 address to standard net.IP.
func (e *DropEvent) IP() net.IP {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], e.SrcIP)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// TelemetryBus abstracts event propagation across the collector subsystems without heap allocation.
type TelemetryBus interface {
	Dispatch(event DropEvent)
}

// ChannelBus implements TelemetryBus using a non-blocking channel.
type ChannelBus chan DropEvent

// Dispatch implements TelemetryBus on ChannelBus without allocating.
func (cb ChannelBus) Dispatch(event DropEvent) {
	select {
	case cb <- event:
	default:
		// Queue full / backpressure: drop sample to preserve line-rate read performance
	}
}

// FuncBus adapts a simple callback into a TelemetryBus.
type FuncBus func(event DropEvent)

// Dispatch executes the callback.
func (fb FuncBus) Dispatch(event DropEvent) {
	fb(event)
}

// TelemetryObjects encapsulates the loaded eBPF maps required for telemetry ingestion.
type TelemetryObjects struct {
	TelemetryRingbuf *ebpf.Map
}

// ReaderSource defines an abstraction over cilium/ebpf/ringbuf.Reader for zero-allocation reading.
type ReaderSource interface {
	ReadInto(rec *ringbuf.Record) error
	Close() error
}

// TelemetryProcessor manages zero-copy consumption from BPF_MAP_TYPE_RINGBUF.
type TelemetryProcessor struct {
	reader   ReaderSource
	bus      TelemetryBus
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	running  atomic.Bool
	eventsRx atomic.Uint64
	bytesRx  atomic.Uint64
	errCount atomic.Uint64
}

// NewReader initializes a TelemetryProcessor directly from TelemetryObjects.
func NewReader(objs *TelemetryObjects, bus TelemetryBus) (*TelemetryProcessor, error) {
	if objs == nil || objs.TelemetryRingbuf == nil {
		return nil, errors.New("telemetry_ringbuf map pointer cannot be nil")
	}
	rd, err := ringbuf.NewReader(objs.TelemetryRingbuf)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ringbuf reader: %w", err)
	}
	return NewProcessorWithSource(rd, bus), nil
}

// NewProcessorWithSource creates a TelemetryProcessor with an arbitrary ReaderSource.
func NewProcessorWithSource(source ReaderSource, bus TelemetryBus) *TelemetryProcessor {
	return &TelemetryProcessor{
		reader: source,
		bus:    bus,
	}
}

// Start launches the dedicated background goroutine for reading ring buffer samples.
func (p *TelemetryProcessor) Start(ctx context.Context) {
	if p.running.Swap(true) {
		return // already running
	}

	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.wg.Add(1)

	go p.workerLoop(runCtx)
}

// workerLoop drains events from the kernel ring buffer with zero heap allocations per event.
func (p *TelemetryProcessor) workerLoop(ctx context.Context) {
	defer p.wg.Done()
	defer p.running.Store(false)

	// Pre-allocate a single ringbuf.Record to reuse its buffer across reads.
	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := p.reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			p.errCount.Add(1)
			continue
		}

		if len(record.RawSample) < DropEventSize {
			p.errCount.Add(1)
			continue
		}

		p.bytesRx.Add(uint64(len(record.RawSample)))
		p.eventsRx.Add(1)

		// Zero-copy type reinterpretation directly from the kernel ring buffer memory slice.
		event := *(*DropEvent)(unsafe.Pointer(&record.RawSample[0]))

		if p.bus != nil {
			p.bus.Dispatch(event)
		}
	}
}

// Metrics returns the total processed events, bytes, and error counts.
func (p *TelemetryProcessor) Metrics() (events uint64, bytes uint64, errors uint64) {
	return p.eventsRx.Load(), p.bytesRx.Load(), p.errCount.Load()
}

// Close gracefully terminates the worker goroutine and releases ring buffer kernel resources.
func (p *TelemetryProcessor) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	var err error
	if p.reader != nil {
		err = p.reader.Close()
	}
	p.wg.Wait()
	return err
}
