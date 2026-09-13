package bpf

import (
	"net"
	"strings"
	"testing"
)

func TestRawPacketSampleHelpers(t *testing.T) {
	// 1. IPv4 TCP Sample Test
	sampleV4 := RawPacketSample{
		WireLen:     64,
		CaptureLen:  54,
		DropReason:  DropReasonSynFlood,
		IPVersion:   4,
		TimestampNs: 1700000000000000000,
	}
	// Build Ethernet (14B) + IPv4 (20B) + TCP (20B)
	// Ethernet
	copy(sampleV4.Data[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(sampleV4.Data[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	sampleV4.Data[12] = 0x08
	sampleV4.Data[13] = 0x00

	// IPv4 Header (at 14)
	sampleV4.Data[14] = 0x45 // Version 4, IHL 5 (20 bytes)
	sampleV4.Data[23] = 6    // IPPROTO_TCP
	copy(sampleV4.Data[26:30], []byte{10, 0, 2, 1})       // Src IP
	copy(sampleV4.Data[30:34], []byte{192, 168, 1, 10})   // Dst IP

	// TCP Header (at 34)
	sampleV4.Data[34] = 0xad // SrcPort 44332 (0xad2c)
	sampleV4.Data[35] = 0x2c
	sampleV4.Data[36] = 0x00 // DstPort 80 (0x0050)
	sampleV4.Data[37] = 0x50

	if sampleV4.IPVersionString() != "IPv4" {
		t.Errorf("Expected IPv4, got %s", sampleV4.IPVersionString())
	}
	if sampleV4.ProtocolString() != "TCP" {
		t.Errorf("Expected TCP, got %s", sampleV4.ProtocolString())
	}
	if sampleV4.DropReasonString() != "SYN_FLOOD" {
		t.Errorf("Expected SYN_FLOOD, got %s", sampleV4.DropReasonString())
	}
	if sampleV4.SrcIPString() != "10.0.2.1" {
		t.Errorf("Expected 10.0.2.1, got %s", sampleV4.SrcIPString())
	}
	if sampleV4.SrcPort() != 44332 {
		t.Errorf("Expected src port 44332, got %d", sampleV4.SrcPort())
	}
	if sampleV4.DstPort() != 80 {
		t.Errorf("Expected dst port 80, got %d", sampleV4.DstPort())
	}

	rawBytes := sampleV4.ByteSlice()
	if len(rawBytes) != 54 {
		t.Errorf("Expected 54 bytes slice, got %d", len(rawBytes))
	}

	hexDump := sampleV4.HexDump()
	if !strings.Contains(hexDump, "0800 4500") && !strings.Contains(hexDump, "08 00 45") {
		t.Errorf("HexDump format incorrect:\n%s", hexDump)
	}

	hexStr := sampleV4.HexString()
	if !strings.HasPrefix(hexStr, "001122334455") {
		t.Errorf("HexString format incorrect: %s", hexStr)
	}

	// 2. IPv6 UDP Sample Test
	sampleV6 := RawPacketSample{
		WireLen:     128,
		CaptureLen:  62,
		DropReason:  DropReasonEntropyAnomaly,
		IPVersion:   6,
		TimestampNs: 1700000000000000000,
	}
	// Ethernet (14B)
	sampleV6.Data[12] = 0x86
	sampleV6.Data[13] = 0xdd

	// IPv6 Header (at 14, 40 bytes)
	sampleV6.Data[14] = 0x60 // IPv6
	sampleV6.Data[20] = 17   // nexthdr = UDP (offset 14 + 6 = 20)
	v6Parsed := net.ParseIP("2001:db8::cafe:1").To16()
	copy(sampleV6.Data[22:38], v6Parsed) // Src IP at offset 14 + 8 = 22

	// UDP Header (at 54)
	sampleV6.Data[54] = 0x1f // SrcPort 8080 (0x1f90)
	sampleV6.Data[55] = 0x90
	sampleV6.Data[56] = 0x00 // DstPort 53 (0x0035)
	sampleV6.Data[57] = 0x35

	if sampleV6.IPVersionString() != "IPv6" {
		t.Errorf("Expected IPv6, got %s", sampleV6.IPVersionString())
	}
	if sampleV6.ProtocolString() != "UDP" {
		t.Errorf("Expected UDP, got %s", sampleV6.ProtocolString())
	}
	if sampleV6.DropReasonString() != "ENTROPY_ANOMALY" {
		t.Errorf("Expected ENTROPY_ANOMALY, got %s", sampleV6.DropReasonString())
	}
	if sampleV6.SrcIPString() != "2001:db8::cafe:1" {
		t.Errorf("Expected 2001:db8::cafe:1, got %s", sampleV6.SrcIPString())
	}
	if sampleV6.SrcPort() != 8080 {
		t.Errorf("Expected src port 8080, got %d", sampleV6.SrcPort())
	}
	if sampleV6.DstPort() != 53 {
		t.Errorf("Expected dst port 53, got %d", sampleV6.DstPort())
	}
}
