package bpf

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

// mockReader implements ReaderSource for deterministic in-memory testing.
type mockReader struct {
	mu      sync.Mutex
	records [][]byte
	closed  bool
	notify  chan struct{}
}

func newMockReader(samples [][]byte) *mockReader {
	return &mockReader{
		records: samples,
		notify:  make(chan struct{}, 1),
	}
}

func (m *mockReader) ReadInto(rec *ringbuf.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ringbuf.ErrClosed
	}

	if len(m.records) == 0 {
		m.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		m.mu.Lock()
		if m.closed {
			return ringbuf.ErrClosed
		}
		if len(m.records) == 0 {
			return nil
		}
	}

	item := m.records[0]
	m.records = m.records[1:]
	rec.RawSample = item
	return nil
}

func (m *mockReader) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func encodeTestEvent(srcIP string, port uint16, proto uint16, reason DropReason, ts uint64) []byte {
	buf := make([]byte, DropEventSize)
	ip := net.ParseIP(srcIP).To4()
	if ip != nil {
		copy(buf[0:4], ip)
	}
	binary.LittleEndian.PutUint16(buf[4:6], port)
	binary.LittleEndian.PutUint16(buf[6:8], proto)
	buf[8] = byte(reason)
	// buf[9:16] are padding bytes
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	return buf
}

func TestDropEventStructureAlignment(t *testing.T) {
	if DropEventSize != 24 {
		t.Fatalf("Expected DropEvent size of 24 bytes, got %d", DropEventSize)
	}

	var dummy DropEvent
	if unsafe.Offsetof(dummy.SrcIP) != 0 {
		t.Errorf("SrcIP offset expected 0, got %d", unsafe.Offsetof(dummy.SrcIP))
	}
	if unsafe.Offsetof(dummy.SrcPort) != 4 {
		t.Errorf("SrcPort offset expected 4, got %d", unsafe.Offsetof(dummy.SrcPort))
	}
	if unsafe.Offsetof(dummy.Protocol) != 6 {
		t.Errorf("Protocol offset expected 6, got %d", unsafe.Offsetof(dummy.Protocol))
	}
	if unsafe.Offsetof(dummy.DropReason) != 8 {
		t.Errorf("DropReason offset expected 8, got %d", unsafe.Offsetof(dummy.DropReason))
	}
	if unsafe.Offsetof(dummy.Pad) != 9 {
		t.Errorf("Pad offset expected 9, got %d", unsafe.Offsetof(dummy.Pad))
	}
	if unsafe.Offsetof(dummy.TimestampNs) != 16 {
		t.Errorf("TimestampNs offset expected 16, got %d", unsafe.Offsetof(dummy.TimestampNs))
	}
}

func TestDropReasonString(t *testing.T) {
	cases := []struct {
		r        DropReason
		expected string
	}{
		{DropReasonSynFlood, "SYN_FLOOD"},
		{DropReasonL7DpiSignature, "L7_DPI_SIGNATURE"},
		{DropReasonEntropyAnomaly, "ENTROPY_ANOMALY"},
		{DropReasonRateLimit, "RATE_LIMIT"},
		{DropReason(99), "UNKNOWN"},
	}

	for _, c := range cases {
		if c.r.String() != c.expected {
			t.Errorf("Expected %s, got %s", c.expected, c.r.String())
		}
	}
}

func TestTelemetryProcessorZeroAllocationParsing(t *testing.T) {
	rawSample := encodeTestEvent("198.51.100.25", 4433, 6, DropReasonL7DpiSignature, 1788812345678)
	var record ringbuf.Record
	record.RawSample = rawSample

	var sink DropEvent
	bus := FuncBus(func(ev DropEvent) {
		sink = ev
	})

	allocs := testing.AllocsPerRun(1000, func() {
		ev := *(*DropEvent)(unsafe.Pointer(&record.RawSample[0]))
		bus.Dispatch(ev)
	})

	if allocs != 0 {
		t.Errorf("Expected 0 allocations during event decode & dispatch, got %f", allocs)
	}

	if sink.DropReason != DropReasonL7DpiSignature {
		t.Errorf("Expected reason %v, got %v", DropReasonL7DpiSignature, sink.DropReason)
	}
	if sink.SrcPort != 4433 {
		t.Errorf("Expected port 4433, got %d", sink.SrcPort)
	}
	if sink.Protocol != 6 {
		t.Errorf("Expected protocol 6, got %d", sink.Protocol)
	}
	if sink.TimestampNs != 1788812345678 {
		t.Errorf("Expected ts 1788812345678, got %d", sink.TimestampNs)
	}
}

func TestTelemetryProcessorLifecycleAndChannelBus(t *testing.T) {
	samples := [][]byte{
		encodeTestEvent("192.0.2.1", 80, 6, DropReasonSynFlood, 1000),
		encodeTestEvent("192.0.2.2", 53, 17, DropReasonEntropyAnomaly, 2000),
		encodeTestEvent("192.0.2.3", 443, 6, DropReasonRateLimit, 3000),
	}

	mock := newMockReader(samples)
	eventCh := make(ChannelBus, 10)
	proc := NewProcessorWithSource(mock, eventCh)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	proc.Start(ctx)

	var received []DropEvent
	for i := 0; i < 3; i++ {
		select {
		case ev := <-eventCh:
			received = append(received, ev)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("Timeout waiting for event %d", i)
		}
	}

	if len(received) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(received))
	}

	if received[0].DropReason != DropReasonSynFlood {
		t.Errorf("Event 0 reason mismatch: %v", received[0].DropReason)
	}
	if received[1].DropReason != DropReasonEntropyAnomaly {
		t.Errorf("Event 1 reason mismatch: %v", received[1].DropReason)
	}
	if received[2].DropReason != DropReasonRateLimit {
		t.Errorf("Event 2 reason mismatch: %v", received[2].DropReason)
	}

	events, bytes, errs := proc.Metrics()
	if events != 3 {
		t.Errorf("Expected 3 events metrics, got %d", events)
	}
	if bytes != 3*uint64(DropEventSize) {
		t.Errorf("Expected %d bytes metrics, got %d", 3*DropEventSize, bytes)
	}
	if errs != 0 {
		t.Errorf("Expected 0 errors metrics, got %d", errs)
	}

	if err := proc.Close(); err != nil {
		t.Errorf("Error closing processor: %v", err)
	}
}
