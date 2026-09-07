package forensics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RawPacket represents a captured network packet stored in the forensics ring buffer.
type RawPacket struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     net.IP    `json:"src_ip"`
	DstIP     net.IP    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"` // 6 = TCP, 17 = UDP, 1 = ICMP
	Payload   []byte    `json:"-"`
	RawData   []byte    `json:"-"`
}

// SizeBytes calculates the memory footprint of a single RawPacket.
func (p *RawPacket) SizeBytes() int {
	return 64 + len(p.Payload) + len(p.RawData)
}

// ForensicSnapshot contains metadata about a serialized PCAP incident file.
type ForensicSnapshot struct {
	Filename    string `json:"filename"`
	FilePath    string `json:"file_path"`
	TargetIP    string `json:"target_ip"`
	Reason      string `json:"reason"`
	TimestampMs int64  `json:"timestamp_ms"`
	PacketCount int    `json:"packet_count"`
	FileSize    int64  `json:"file_size"`
	CreatedAt   string `json:"created_at"`
}

// PCAPBuffer maintains an in-memory thread-safe circular ring buffer storing recent network packets
// capped to a sliding time window (30 seconds) and memory quota (64 MB per interface).
type PCAPBuffer struct {
	mu            sync.RWMutex
	maxSizeBytes  int
	timeHorizon   time.Duration
	storageDir    string
	packets       []*RawPacket
	currentSize   int
	totalIngested uint64
	totalDumps    uint64
	snapshots     map[string]*ForensicSnapshot // filename -> snapshot
}

var (
	defaultBuffer *PCAPBuffer
	bufferOnce    sync.Once
)

// GetDefaultPCAPBuffer returns the singleton forensics ring buffer instance.
func GetDefaultPCAPBuffer() *PCAPBuffer {
	bufferOnce.Do(func() {
		defaultBuffer = NewPCAPBuffer(64*1024*1024, 30*time.Second, "/var/log/copsec/forensics")
	})
	return defaultBuffer
}

// NewPCAPBuffer initializes a new circular forensics ring buffer.
func NewPCAPBuffer(maxBytes int, timeHorizon time.Duration, storageDir string) *PCAPBuffer {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024 // 64 MB default
	}
	if timeHorizon <= 0 {
		timeHorizon = 30 * time.Second
	}
	if storageDir == "" {
		storageDir = "/var/log/copsec/forensics"
	}

	// Verify writable storage directory with fallback
	if err := os.MkdirAll(storageDir, 0750); err != nil {
		storageDir = "./forensics"
		_ = os.MkdirAll(storageDir, 0750)
	}

	return &PCAPBuffer{
		maxSizeBytes: maxBytes,
		timeHorizon:  timeHorizon,
		storageDir:   storageDir,
		packets:      make([]*RawPacket, 0, 1024),
		snapshots:    make(map[string]*ForensicSnapshot),
	}
}

// Ingest adds a new packet record to the circular ring buffer, evicting expired or overflowing packets.
func (b *PCAPBuffer) Ingest(srcIP, dstIP string, srcPort, dstPort int, protocol uint8, payload []byte) {
	sIP := net.ParseIP(srcIP)
	dIP := net.ParseIP(dstIP)
	if sIP == nil || dIP == nil {
		return
	}

	pkt := &RawPacket{
		Timestamp: time.Now(),
		SrcIP:     sIP,
		DstIP:     dIP,
		SrcPort:   uint16(srcPort),
		DstPort:   uint16(dstPort),
		Protocol:  protocol,
		Payload:   payload,
	}

	b.PushPacket(pkt)
}

// PushPacket appends a RawPacket and enforces 30s horizon and 64MB memory limits.
func (b *PCAPBuffer) PushPacket(pkt *RawPacket) {
	if pkt == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	pktSize := pkt.SizeBytes()
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now()
		pkt.Timestamp = now
	}

	cutoff := now.Add(-b.timeHorizon)

	// 1. Evict expired packets (> 30 seconds old)
	startIdx := 0
	for i, p := range b.packets {
		if p.Timestamp.After(cutoff) {
			startIdx = i
			break
		}
		b.currentSize -= p.SizeBytes()
		if i == len(b.packets)-1 {
			startIdx = len(b.packets)
		}
	}
	if startIdx > 0 {
		b.packets = b.packets[startIdx:]
	}

	// 2. Evict oldest packets if exceeding max memory capacity
	for len(b.packets) > 0 && b.currentSize+pktSize > b.maxSizeBytes {
		b.currentSize -= b.packets[0].SizeBytes()
		b.packets = b.packets[1:]
	}

	b.packets = append(b.packets, pkt)
	b.currentSize += pktSize
	atomic.AddUint64(&b.totalIngested, 1)
}

// SnapshotForIP extracts all packets associated with the offending IP from the ring buffer,
// serializes them into standard .pcap format, and writes to disk asynchronously.
func (b *PCAPBuffer) SnapshotForIP(targetIP string, reason string) (*ForensicSnapshot, error) {
	cleanIP := strings.TrimSpace(targetIP)
	if cleanIP == "" {
		return nil, fmt.Errorf("empty target IP for PCAP snapshot")
	}

	parsedTarget := net.ParseIP(cleanIP)
	if parsedTarget == nil {
		return nil, fmt.Errorf("invalid IP format: %s", cleanIP)
	}

	b.mu.RLock()
	// Filter matching packets for target IP
	matching := make([]*RawPacket, 0, len(b.packets))
	for _, p := range b.packets {
		if p.SrcIP.Equal(parsedTarget) || p.DstIP.Equal(parsedTarget) || p.SrcIP.String() == cleanIP || p.DstIP.String() == cleanIP {
			matching = append(matching, p)
		}
	}
	b.mu.RUnlock()

	// If no packets matched target IP, still generate empty or baseline capture
	pcapBytes, err := SerializeToPCAP(matching)
	if err != nil {
		return nil, fmt.Errorf("pcap serialization failed: %w", err)
	}

	// Persist to target file: /var/log/copsec/forensics/attack_<IP>_<TIMESTAMP>.pcap
	safeIP := strings.ReplaceAll(cleanIP, ":", "_")
	timestampMs := time.Now().UnixMilli()
	filename := fmt.Sprintf("attack_%s_%d.pcap", safeIP, timestampMs)

	// Ensure directory
	dir := b.storageDir
	if err := os.MkdirAll(dir, 0750); err != nil {
		dir = "./forensics"
		_ = os.MkdirAll(dir, 0750)
	}

	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, pcapBytes, 0640); err != nil {
		// Fallback to /tmp if write failed
		filePath = filepath.Join(os.TempDir(), filename)
		if err := os.WriteFile(filePath, pcapBytes, 0640); err != nil {
			return nil, fmt.Errorf("failed to write forensic pcap file: %w", err)
		}
	}

	snapshot := &ForensicSnapshot{
		Filename:    filename,
		FilePath:    filePath,
		TargetIP:    cleanIP,
		Reason:      reason,
		TimestampMs: timestampMs,
		PacketCount: len(matching),
		FileSize:    int64(len(pcapBytes)),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	b.mu.Lock()
	b.snapshots[filename] = snapshot
	b.mu.Unlock()

	atomic.AddUint64(&b.totalDumps, 1)
	log.Printf("[FORENSICS] 📦 Captured pre-attack PCAP ring buffer dump for %s -> %s (%d packets, %d bytes)",
		cleanIP, filePath, len(matching), len(pcapBytes))

	return snapshot, nil
}

// ListSnapshots returns all generated forensic PCAP snapshots.
func (b *PCAPBuffer) ListSnapshots() []*ForensicSnapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()

	list := make([]*ForensicSnapshot, 0, len(b.snapshots))
	for _, s := range b.snapshots {
		cp := *s
		list = append(list, &cp)
	}

	// Scan storage directory for any additional historical pcaps
	files, err := os.ReadDir(b.storageDir)
	if err == nil {
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".pcap") {
				if _, ok := b.snapshots[f.Name()]; !ok {
					info, _ := f.Info()
					sz := int64(0)
					if info != nil {
						sz = info.Size()
					}
					list = append(list, &ForensicSnapshot{
						Filename: f.Name(),
						FilePath: filepath.Join(b.storageDir, f.Name()),
						FileSize: sz,
					})
				}
			}
		}
	}

	return list
}

// GetSnapshotPath returns the safe absolute path for a pcap filename.
func (b *PCAPBuffer) GetSnapshotPath(filename string) (string, error) {
	cleanName := filepath.Base(filename)
	if !strings.HasSuffix(cleanName, ".pcap") || strings.Contains(cleanName, "..") {
		return "", fmt.Errorf("invalid pcap filename: %s", filename)
	}

	// Check storageDir
	path := filepath.Join(b.storageDir, cleanName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Check ./forensics
	path = filepath.Join("./forensics", cleanName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Check /tmp
	path = filepath.Join(os.TempDir(), cleanName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	return "", os.ErrNotExist
}

// SerializeToPCAP encodes a slice of RawPacket records into standard Wireshark/tcpdump .pcap binary format.
func SerializeToPCAP(packets []*RawPacket) ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1. Libpcap Global Header (24 bytes)
	// Magic Number: 0xa1b2c3d4 (standard microsecond resolution)
	// Version: 2.4
	// Timezone: 0, Sigfigs: 0
	// Snaplen: 65535
	// Network / LinkType: 1 (LINKTYPE_ETHERNET)
	globalHeader := struct {
		MagicNumber  uint32
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32
		SigFigs      uint32
		SnapLen      uint32
		Network      uint32
	}{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      1, // LINKTYPE_ETHERNET
	}

	if err := binary.Write(buf, binary.LittleEndian, globalHeader); err != nil {
		return nil, err
	}

	// 2. Packet Records
	for _, pkt := range packets {
		rawPktBytes := pkt.RawData
		if len(rawPktBytes) == 0 {
			rawPktBytes = buildEthernetPacket(pkt)
		}

		ts := pkt.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}

		sec := uint32(ts.Unix())
		usec := uint32(ts.Nanosecond() / 1000)
		pktLen := uint32(len(rawPktBytes))

		pktHeader := struct {
			TsSec   uint32
			TsUsec  uint32
			InclLen uint32
			OrigLen uint32
		}{
			TsSec:   sec,
			TsUsec:  usec,
			InclLen: pktLen,
			OrigLen: pktLen,
		}

		if err := binary.Write(buf, binary.LittleEndian, pktHeader); err != nil {
			return nil, err
		}
		if _, err := buf.Write(rawPktBytes); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// buildEthernetPacket constructs a valid synthetic L2 Ethernet + IPv4 + TCP/UDP frame.
func buildEthernetPacket(pkt *RawPacket) []byte {
	buf := new(bytes.Buffer)

	// Ethernet Header (14 bytes): DstMAC (6), SrcMAC (6), EtherType (2: 0x0800 for IPv4)
	dstMAC := []byte{0x00, 0x50, 0x56, 0xfa, 0xce, 0x01}
	srcMAC := []byte{0x00, 0x50, 0x56, 0xfa, 0xce, 0x02}
	buf.Write(dstMAC)
	buf.Write(srcMAC)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0800)) // IPv4

	// IPv4 Header (20 bytes)
	srcIPv4 := pkt.SrcIP.To4()
	if srcIPv4 == nil {
		srcIPv4 = net.IPv4(127, 0, 0, 1).To4()
	}
	dstIPv4 := pkt.DstIP.To4()
	if dstIPv4 == nil {
		dstIPv4 = net.IPv4(127, 0, 0, 1).To4()
	}

	proto := pkt.Protocol
	if proto == 0 {
		proto = 6 // TCP
	}

	l4PayloadLen := len(pkt.Payload)
	l4HeaderLen := 20
	if proto == 17 {
		l4HeaderLen = 8 // UDP
	}
	totalLen := uint16(20 + l4HeaderLen + l4PayloadLen)

	ipHeader := []byte{
		0x45, 0x00, // Version 4, IHL 5, DSCP/ECN 0
		byte(totalLen >> 8), byte(totalLen & 0xff), // Total Length
		0x13, 0x37, // Identification
		0x40, 0x00, // Flags (Don't Fragment), Fragment Offset 0
		64, proto, // TTL 64, Protocol
		0x00, 0x00, // Header Checksum placeholder
	}
	buf.Write(ipHeader)
	buf.Write(srcIPv4)
	buf.Write(dstIPv4)

	// L4 Header (TCP or UDP)
	if proto == 17 {
		// UDP Header (8 bytes)
		udpLen := uint16(8 + l4PayloadLen)
		_ = binary.Write(buf, binary.BigEndian, pkt.SrcPort)
		_ = binary.Write(buf, binary.BigEndian, pkt.DstPort)
		_ = binary.Write(buf, binary.BigEndian, udpLen)
		_ = binary.Write(buf, binary.BigEndian, uint16(0)) // Checksum
	} else {
		// TCP Header (20 bytes)
		_ = binary.Write(buf, binary.BigEndian, pkt.SrcPort)
		_ = binary.Write(buf, binary.BigEndian, pkt.DstPort)
		_ = binary.Write(buf, binary.BigEndian, uint32(1000))  // Seq
		_ = binary.Write(buf, binary.BigEndian, uint32(2000))  // Ack
		buf.Write([]byte{0x50, 0x18})                          // Data offset (5 words = 20 bytes), Flags (PSH, ACK)
		_ = binary.Write(buf, binary.BigEndian, uint16(65535)) // Window size
		_ = binary.Write(buf, binary.BigEndian, uint16(0))     // Checksum
		_ = binary.Write(buf, binary.BigEndian, uint16(0))     // Urgent pointer
	}

	// Payload
	if len(pkt.Payload) > 0 {
		buf.Write(pkt.Payload)
	}

	return buf.Bytes()
}

// RegisterHTTPHandlers mounts forensics inspection and PCAP download REST endpoints.
func RegisterHTTPHandlers(mux *http.ServeMux, buffer *PCAPBuffer) {
	if buffer == nil {
		buffer = GetDefaultPCAPBuffer()
	}

	mux.HandleFunc("/api/forensics/pcaps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snapshots := buffer.ListSnapshots()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Simple JSON writer
		var buf bytes.Buffer
		buf.WriteString(`{"success":true,"count":`)
		buf.WriteString(fmt.Sprintf("%d", len(snapshots)))
		buf.WriteString(`,"pcaps":[`)
		for i, s := range snapshots {
			if i > 0 {
				buf.WriteString(`,`)
			}
			buf.WriteString(fmt.Sprintf(`{"filename":%q,"file_path":%q,"target_ip":%q,"reason":%q,"timestamp_ms":%d,"packet_count":%d,"file_size":%d,"created_at":%q}`,
				s.Filename, s.FilePath, s.TargetIP, s.Reason, s.TimestampMs, s.PacketCount, s.FileSize, s.CreatedAt))
		}
		buf.WriteString(`]}`)
		_, _ = w.Write(buf.Bytes())
	})

	mux.HandleFunc("/api/forensics/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		filename := r.URL.Query().Get("file")
		if filename == "" {
			http.Error(w, `{"error":"missing file parameter"}`, http.StatusBadRequest)
			return
		}

		filePath, err := buffer.GetSnapshotPath(filename)
		if err != nil {
			http.Error(w, `{"error":"pcap file not found"}`, http.StatusNotFound)
			return
		}

		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, `{"error":"unable to read pcap file"}`, http.StatusInternalServerError)
			return
		}
		defer file.Close()

		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(filePath)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, file)
	})
}
