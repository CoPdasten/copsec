package bpf

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// RawPacketSample binary layout strictly matches struct packet_sample_t in bpf/xdp_copsec_filter.c
// Binary layout:
// uint32 WireLen     (4 bytes)
// uint16 CaptureLen  (2 bytes)
// uint8  DropReason  (1 byte)
// uint8  IPVersion   (1 byte)
// uint64 TimestampNs (8 bytes)
// uint8  Data[128]   (128 bytes)
// Total binary size = 144 bytes (strictly 64-bit aligned).
type RawPacketSample struct {
	WireLen     uint32
	CaptureLen  uint16
	DropReason  DropReason
	IPVersion   uint8
	TimestampNs uint64
	Data        [128]byte
}

// RawPacketSampleSize defines the exact binary byte size of struct packet_sample_t.
const RawPacketSampleSize = int(unsafe.Sizeof(RawPacketSample{}))

// ByteSlice returns the captured packet prefix as a slice bounded by CaptureLen.
func (s *RawPacketSample) ByteSlice() []byte {
	n := int(s.CaptureLen)
	if n > len(s.Data) {
		n = len(s.Data)
	}
	res := make([]byte, n)
	copy(res, s.Data[:n])
	return res
}

// HexDump formats the captured bytes into a canonical hex dump string.
func (s *RawPacketSample) HexDump() string {
	return hex.Dump(s.ByteSlice())
}

// HexString returns continuous hex encoding of captured bytes.
func (s *RawPacketSample) HexString() string {
	return hex.EncodeToString(s.ByteSlice())
}

// IPVersionString returns "IPv4" or "IPv6".
func (s *RawPacketSample) IPVersionString() string {
	if s.IPVersion == 6 {
		return "IPv6"
	}
	return "IPv4"
}

// DropReasonString returns human-readable drop classification.
func (s *RawPacketSample) DropReasonString() string {
	return s.DropReason.String()
}

// SrcIP parses and extracts the source IP from the captured Ethernet frame.
func (s *RawPacketSample) SrcIP() net.IP {
	if s.IPVersion == 6 {
		// Ethernet header is 14 bytes; IPv6 src IP is at offset 14 + 8 = 22 (16 bytes)
		if len(s.Data) >= 38 {
			ip := make(net.IP, 16)
			copy(ip, s.Data[22:38])
			return ip
		}
	} else {
		// Ethernet header is 14 bytes; IPv4 src IP is at offset 14 + 12 = 26 (4 bytes)
		if len(s.Data) >= 30 {
			return net.IPv4(s.Data[26], s.Data[27], s.Data[28], s.Data[29])
		}
	}
	return nil
}

// SrcIPString returns the string representation of the source IP.
func (s *RawPacketSample) SrcIPString() string {
	ip := s.SrcIP()
	if ip != nil {
		return ip.String()
	}
	return "-"
}

// DstIP parses and extracts the destination IP from the captured Ethernet frame.
func (s *RawPacketSample) DstIP() net.IP {
	if s.IPVersion == 6 {
		// Ethernet header is 14 bytes; IPv6 dst IP is at offset 14 + 24 = 38 (16 bytes)
		if len(s.Data) >= 54 {
			ip := make(net.IP, 16)
			copy(ip, s.Data[38:54])
			return ip
		}
	} else {
		// Ethernet header is 14 bytes; IPv4 dst IP is at offset 14 + 16 = 30 (4 bytes)
		if len(s.Data) >= 34 {
			return net.IPv4(s.Data[30], s.Data[31], s.Data[32], s.Data[33])
		}
	}
	return nil
}

// DstIPString returns the string representation of the destination IP.
func (s *RawPacketSample) DstIPString() string {
	ip := s.DstIP()
	if ip != nil {
		return ip.String()
	}
	return "-"
}

// Protocol returns the L4 protocol number (e.g. 6 for TCP, 17 for UDP).
func (s *RawPacketSample) Protocol() uint8 {
	if s.IPVersion == 6 {
		if len(s.Data) >= 21 {
			return s.Data[20] // nexthdr at offset 14 + 6
		}
	} else {
		if len(s.Data) >= 24 {
			return s.Data[23] // protocol at offset 14 + 9
		}
	}
	return 0
}

// ProtocolString returns human readable L4 protocol name.
func (s *RawPacketSample) ProtocolString() string {
	switch s.Protocol() {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP-%d", s.Protocol())
	}
}

// SrcPort extracts L4 source port if available in captured data.
func (s *RawPacketSample) SrcPort() uint16 {
	if s.IPVersion == 6 {
		if len(s.Data) >= 56 {
			return binary.BigEndian.Uint16(s.Data[54:56])
		}
	} else {
		if len(s.Data) >= 15 {
			ihl := int(s.Data[14]&0x0F) * 4
			offset := 14 + ihl
			if len(s.Data) >= offset+2 {
				return binary.BigEndian.Uint16(s.Data[offset : offset+2])
			}
		}
	}
	return 0
}

// DstPort extracts L4 destination port if available in captured data.
func (s *RawPacketSample) DstPort() uint16 {
	if s.IPVersion == 6 {
		if len(s.Data) >= 58 {
			return binary.BigEndian.Uint16(s.Data[56:58])
		}
	} else {
		if len(s.Data) >= 15 {
			ihl := int(s.Data[14]&0x0F) * 4
			offset := 14 + ihl
			if len(s.Data) >= offset+4 {
				return binary.BigEndian.Uint16(s.Data[offset+2 : offset+4])
			}
		}
	}
	return 0
}

// RawPacketBus abstracts sample dispatching across collector subsystems.
type RawPacketBus interface {
	Dispatch(sample RawPacketSample)
}

// RawPacketFuncBus adapts a function callback into a RawPacketBus.
type RawPacketFuncBus func(sample RawPacketSample)

// Dispatch invokes the callback.
func (fb RawPacketFuncBus) Dispatch(sample RawPacketSample) {
	fb(sample)
}

// RawPacketProcessor manages zero-copy consumption from raw_packet_ringbuf.
type RawPacketProcessor struct {
	reader    *ringbuf.Reader
	bus       RawPacketBus
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	running   atomic.Bool
	samplesRx atomic.Uint64
	bytesRx   atomic.Uint64
	errCount  atomic.Uint64
}

// NewRawPacketProcessor initializes a RawPacketProcessor from an ebpf.Map pointer.
func NewRawPacketProcessor(packetRingbuf *ebpf.Map, bus RawPacketBus) (*RawPacketProcessor, error) {
	if packetRingbuf == nil {
		return nil, errors.New("raw_packet_ringbuf map pointer cannot be nil")
	}
	rd, err := ringbuf.NewReader(packetRingbuf)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize raw_packet_ringbuf reader: %w", err)
	}
	return &RawPacketProcessor{
		reader: rd,
		bus:    bus,
	}, nil
}

// Start launches the worker loop in a background goroutine.
func (p *RawPacketProcessor) Start(ctx context.Context) {
	if p.running.Swap(true) {
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.wg.Add(1)

	go func() {
		<-runCtx.Done()
		_ = p.Close()
	}()

	go p.workerLoop(runCtx)
}

func (p *RawPacketProcessor) workerLoop(ctx context.Context) {
	defer p.wg.Done()
	defer p.running.Store(false)

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
			time.Sleep(20 * time.Millisecond)
			continue
		}

		if len(record.RawSample) < RawPacketSampleSize {
			p.errCount.Add(1)
			continue
		}

		p.bytesRx.Add(uint64(len(record.RawSample)))
		p.samplesRx.Add(1)

		sample := *(*RawPacketSample)(unsafe.Pointer(&record.RawSample[0]))

		if p.bus != nil {
			p.bus.Dispatch(sample)
		}
	}
}

// Metrics returns total received samples, bytes, and error counts.
func (p *RawPacketProcessor) Metrics() (samples uint64, bytes uint64, errors uint64) {
	return p.samplesRx.Load(), p.bytesRx.Load(), p.errCount.Load()
}

// Close gracefully terminates the reader and releases BPF map resources.
func (p *RawPacketProcessor) Close() error {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.reader != nil {
			p.closeErr = p.reader.Close()
		}
	})
	p.wg.Wait()
	return p.closeErr
}
