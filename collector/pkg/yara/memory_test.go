package yara

import (
	"testing"
)

func TestMemoryScannerPatternHits(t *testing.T) {
	scanner := NewMemoryScanner(nil)

	// 1. Cobalt Strike Beacon match
	csPayload := []byte("User-Agent: Mozilla/5.0\r\n%s as %s\\%s: %d\r\nHost: c2.attacker.com")
	hit1 := scanner.ScanBuffer(csPayload, "svchost.exe", 4567)
	if hit1 == nil {
		t.Fatalf("Expected Cobalt Strike signature hit in memory buffer")
	}
	if hit1.Category != "COBALT_STRIKE" {
		t.Errorf("Expected category COBALT_STRIKE, got %s", hit1.Category)
	}

	// 2. Shellcode /bin/sh match
	shellcode := []byte{0x90, 0x90, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x90}
	hit2 := scanner.ScanBuffer(shellcode, "nginx_worker", 8901)
	if hit2 == nil {
		t.Fatalf("Expected Execve shellcode hit in memory buffer")
	}
	if hit2.Category != "SHELLCODE" {
		t.Errorf("Expected category SHELLCODE, got %s", hit2.Category)
	}

	// 3. Obfuscated Webshell match
	webshell := []byte("<?php eval(base64_decode('aW5jbHVkZSgnLi4vcGFzc3dkJyk7')); ?>")
	hit3 := scanner.ScanBuffer(webshell, "php-fpm", 9999)
	if hit3 == nil {
		t.Fatalf("Expected webshell regex hit in memory buffer")
	}
	if hit3.Category != "WEBSHELL" {
		t.Errorf("Expected category WEBSHELL, got %s", hit3.Category)
	}

	// 4. Benign buffer
	benign := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	hit4 := scanner.ScanBuffer(benign, "httpd", 1111)
	if hit4 != nil {
		t.Errorf("Expected no hit on benign buffer, got %v", hit4)
	}
}
