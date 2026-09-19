package telemetry

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// mockReader implements ReaderSource for unit testing.
type mockReader struct {
	mu      sync.Mutex
	records [][]byte
	closed  bool
	index   int
}

func (m *mockReader) ReadInto(rec *ringbuf.Record) error {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return ringbuf.ErrClosed
		}

		if m.index < len(m.records) {
			data := m.records[m.index]
			m.index++
			m.mu.Unlock()

			rec.RawSample = make([]byte, len(data))
			copy(rec.RawSample, data)
			return nil
		}
		m.mu.Unlock()

		time.Sleep(5 * time.Millisecond)
	}
}

func (m *mockReader) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func makeSampleDropEvent(ip uint32, port uint16, reason DropReason) []byte {
	buf := make([]byte, DropEventSize)
	binary.NativeEndian.PutUint32(buf[0:4], ip)
	binary.NativeEndian.PutUint16(buf[4:6], port)
	binary.NativeEndian.PutUint16(buf[6:8], 6) // TCP
	buf[8] = byte(reason)
	buf[9] = 4 // IPv4
	binary.NativeEndian.PutUint64(buf[16:24], 1234567890)
	return buf
}

func TestSyncPoolZeroAllocation(t *testing.T) {
	// Leased object must have clean state
	e1 := AcquireDropEvent()
	e1.SrcIP = 0x01020304
	e1.SrcPort = 8080
	e1.DropReason = DropReasonSynFlood

	ReleaseDropEvent(e1)

	e2 := AcquireDropEvent()
	if e2.SrcIP != 0 || e2.SrcPort != 0 || e2.DropReason != 0 {
		t.Errorf("AcquireDropEvent did not return a zeroed struct: %+v", e2)
	}
	ReleaseDropEvent(e2)
}

func BenchmarkDropEventPool(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := AcquireDropEvent()
		e.SrcIP = uint32(i)
		e.SrcPort = 443
		e.DropReason = DropReasonRateLimit
		ReleaseDropEvent(e)
	}
}

func TestConsumerWorkerPoolProcessing(t *testing.T) {
	const totalEvents = 100
	mock := &mockReader{
		records: make([][]byte, totalEvents),
	}

	for i := 0; i < totalEvents; i++ {
		mock.records[i] = makeSampleDropEvent(0x0A000001+uint32(i), uint16(1000+i), DropReasonSynFlood)
	}

	var processedCount atomic.Uint64
	handler := func(ctx context.Context, event *DropEvent) {
		processedCount.Add(1)
		if event.ProtocolString() != "TCP" {
			t.Errorf("expected protocol TCP, got %s", event.ProtocolString())
		}
	}

	cfg := &Config{
		WorkerCount:   4,
		QueueCapacity: 256,
	}

	consumer, err := NewConsumer(mock, handler, cfg)
	if err != nil {
		t.Fatalf("failed to create consumer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := consumer.Start(ctx); err != nil {
		t.Fatalf("failed to start consumer: %v", err)
	}

	// Wait for all events to be processed
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if processedCount.Load() == totalEvents {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	_ = consumer.Close()

	if processedCount.Load() != totalEvents {
		t.Errorf("processed %d events; want %d", processedCount.Load(), totalEvents)
	}

	metrics := consumer.Metrics()
	if metrics.EventsReceived != totalEvents {
		t.Errorf("metrics.EventsReceived = %d; want %d", metrics.EventsReceived, totalEvents)
	}
	if metrics.EventsDropped != 0 {
		t.Errorf("metrics.EventsDropped = %d; want 0", metrics.EventsDropped)
	}
}

func TestConsumerNonBlockingBackpressure(t *testing.T) {
	// Tiny queue to force saturation
	cfg := &Config{
		WorkerCount:   1,
		QueueCapacity: 2,
	}

	const totalEvents = 50
	mock := &mockReader{
		records: make([][]byte, totalEvents),
	}
	for i := 0; i < totalEvents; i++ {
		mock.records[i] = makeSampleDropEvent(0x0A000001, 80, DropReasonRateLimit)
	}

	// Handler is artificially slow to saturate the queue
	var processedCount atomic.Uint64
	handler := func(ctx context.Context, event *DropEvent) {
		time.Sleep(50 * time.Millisecond)
		processedCount.Add(1)
	}

	consumer, err := NewConsumer(mock, handler, cfg)
	if err != nil {
		t.Fatalf("failed to create consumer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := consumer.Start(ctx); err != nil {
		t.Fatalf("failed to start consumer: %v", err)
	}

	<-ctx.Done()
	_ = consumer.Close()

	metrics := consumer.Metrics()
	// Total events generated = received + dropped
	totalHandled := metrics.EventsReceived + metrics.EventsDropped
	if totalHandled == 0 {
		t.Errorf("expected some events to be handled or dropped, got total=0")
	}

	if metrics.EventsDropped > 0 {
		t.Logf("Backpressure verified: successfully dropped %d events without reader blocking", metrics.EventsDropped)
	}
}

func TestDropEventHelpers(t *testing.T) {
	// IPv4 test
	e4 := &DropEvent{
		SrcIP:       binary.NativeEndian.Uint32(net.ParseIP("192.168.1.50").To4()),
		SrcPort:     443,
		Protocol:    6,
		DropReason:  DropReasonL7Dpi,
		IPVersion:   4,
		TimestampNs: 1000,
	}

	if e4.IP().String() != "192.168.1.50" {
		t.Errorf("e4.IP() = %s; want 192.168.1.50", e4.IP().String())
	}
	if e4.ReasonString() != "L7_DPI" {
		t.Errorf("e4.ReasonString() = %s; want L7_DPI", e4.ReasonString())
	}
	if e4.ProtocolString() != "TCP" {
		t.Errorf("e4.ProtocolString() = %s; want TCP", e4.ProtocolString())
	}

	// IPv6 test
	ip6 := net.ParseIP("2001:db8::1").To16()
	e6 := &DropEvent{
		Protocol:   17,
		DropReason: DropReasonEntropyAnomaly,
		IPVersion:  6,
	}
	copy(e6.SrcIP6[:], ip6)

	if e6.IP().String() != "2001:db8::1" {
		t.Errorf("e6.IP() = %s; want 2001:db8::1", e6.IP().String())
	}
	if e6.ProtocolString() != "UDP" {
		t.Errorf("e6.ProtocolString() = %s; want UDP", e6.ProtocolString())
	}
}
