package detection

import (
	"sync"
	"testing"
	"time"
)

func TestShannonEntropyCalculation(t *testing.T) {
	// Baseline common domain label
	googleLabel := "google"
	googleEntropy := CalculateShannonEntropy(googleLabel)

	// google has 6 chars: 'g':2, 'o':2, 'l':1, 'e':1
	// p(g)=2/6, p(o)=2/6, p(l)=1/6, p(e)=1/6
	// H = -2*(2/6*log2(2/6)) - 2*(1/6*log2(1/6)) ≈ 1.918
	if googleEntropy < 1.8 || googleEntropy > 2.2 {
		t.Fatalf("Expected google entropy around ~1.92, got %.3f", googleEntropy)
	}

	// High entropy base64 / hex exfiltration payload (32 hex characters)
	// Example: "a8f3b9c1d4e7f8a1b2c3d4e5f6a7b8c9"
	hexTunnelPayload := "a8f3b9c1d4e7f8a1b2c3d4e5f6a7b8c9"
	hexEntropy := CalculateShannonEntropy(hexTunnelPayload)

	// In 32 chars of diverse hex, entropy should be >= 3.8
	if hexEntropy < 3.8 {
		t.Fatalf("Expected hex payload entropy >= 3.8, got %.3f", hexEntropy)
	}

	// Base64 high-entropy tunneling payload with mixed case, digits, symbols
	// Example: "aW50ZWxsaWdlbmNlX3NlY3JldF9kYXRhX2V4ZmlsdHJhdGlvbg=="
	b64TunnelPayload := "aW50ZWxsaWdlbmNlX3NlY3JldF9kYXRhX2V4ZmlsdHJhdGlvbg"
	b64Entropy := CalculateShannonEntropy(b64TunnelPayload)

	// In 51 chars of diverse base64, entropy should be >= 4.5
	if b64Entropy < 4.5 {
		t.Fatalf("Expected base64 tunnel payload entropy >= 4.5, got %.3f", b64Entropy)
	}

	// High-entropy random alphanumeric string
	randomHighEntropy := "9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA"
	randEntropy := CalculateShannonEntropy(randomHighEntropy)
	if randEntropy < 4.8 {
		t.Fatalf("Expected random payload entropy >= 4.8, got %.3f", randEntropy)
	}
}

func TestDNSTunnelingDetectionSlidingWindow(t *testing.T) {
	var triggeredAlerts []*DNSEntropyResult
	var mu sync.Mutex

	evaluator := NewDNSEntropyEvaluator(24, 4.5, 3, 30*time.Second, func(res *DNSEntropyResult) {
		mu.Lock()
		defer mu.Unlock()
		triggeredAlerts = append(triggeredAlerts, res)
	})

	srcIP := "192.168.50.100"

	// 1. Normal benign domain queries should NOT trigger spikes
	res, triggered := evaluator.EvaluateQuery(srcIP, "www.google.com")
	if triggered || res.IsHighEntropy {
		t.Fatalf("Benign query flagged as high entropy: %+v", res)
	}

	res, triggered = evaluator.EvaluateQuery(srcIP, "mail.company-portal.internal.net")
	if triggered || res.IsHighEntropy {
		t.Fatalf("Benign portal query flagged as high entropy: %+v", res)
	}

	// 2. High-entropy DNS Tunneling Spike 1 (Length > 24, Entropy > 4.5)
	tunnelDomain1 := "9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.exfil-tunnel.com"
	res, triggered = evaluator.EvaluateQuery(srcIP, tunnelDomain1)
	if !res.IsHighEntropy {
		t.Fatalf("Expected query to be classified as high entropy: entropy=%.3f, len=%d", res.Entropy, res.LabelLength)
	}
	if triggered || res.ActiveSpikeCount != 1 {
		t.Fatalf("Spike 1 should not trigger ban yet: triggered=%v, spikes=%d", triggered, res.ActiveSpikeCount)
	}

	// 3. High-entropy DNS Tunneling Spike 2
	tunnelDomain2 := "8Xp2wJ3uK7vA2lO6iE1sM5xB4qC9rZ.exfil-tunnel.com"
	res, triggered = evaluator.EvaluateQuery(srcIP, tunnelDomain2)
	if !res.IsHighEntropy || triggered || res.ActiveSpikeCount != 2 {
		t.Fatalf("Spike 2 should increment counter to 2 without trigger: spikes=%d", res.ActiveSpikeCount)
	}

	// 4. High-entropy DNS Tunneling Spike 3 (Threshold of 3 reached within 30s)
	tunnelDomain3 := "7Wo1vI2tJ6uZ1kN5hD0rL4wA3pB8qY.exfil-tunnel.com"
	res, triggered = evaluator.EvaluateQuery(srcIP, tunnelDomain3)
	if !triggered {
		t.Fatalf("Expected Spike 3 to trigger RULE-DNS-TUNNEL-001")
	}

	if res.RuleID != "RULE-DNS-TUNNEL-001" || res.ThreatScore != 85 || res.MitreID != "T1071.004" {
		t.Fatalf("Unexpected rule metadata on trigger: %+v", res)
	}

	mu.Lock()
	if len(triggeredAlerts) != 1 {
		t.Fatalf("Expected 1 callback alert triggered, got %d", len(triggeredAlerts))
	}
	mu.Unlock()
}

func TestDNSTunnelingSlidingWindowExpiry(t *testing.T) {
	// Window of 200ms for fast test of sliding window expiration
	evaluator := NewDNSEntropyEvaluator(24, 4.5, 3, 200*time.Millisecond, nil)
	srcIP := "10.10.10.5"

	tunnelDomain := "9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.c2.io"

	// 2 spikes
	evaluator.EvaluateQuery(srcIP, tunnelDomain)
	evaluator.EvaluateQuery(srcIP, tunnelDomain)

	// Wait for window to expire (> 200ms)
	time.Sleep(250 * time.Millisecond)

	// 3rd spike after expiry should reset window count to 1 (not trigger)
	res, triggered := evaluator.EvaluateQuery(srcIP, tunnelDomain)
	if triggered || res.ActiveSpikeCount != 1 {
		t.Fatalf("Expected spikes to reset after window expiry, got count=%d, triggered=%v", res.ActiveSpikeCount, triggered)
	}
}

func TestParseDNSLogSuricataAndBind(t *testing.T) {
	// 1. Suricata EVE Log
	suricataLog := `{"timestamp":"2026-09-06T18:00:00.000000+0000","event_type":"dns","src_ip":"192.168.1.75","src_port":53210,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":1234,"rrname":"9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.evil.com","rrtype":"A"}}`
	srcIP, domain, ok := ParseDNSLog(suricataLog)
	if !ok || srcIP != "192.168.1.75" || domain != "9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.evil.com" {
		t.Fatalf("Failed to parse Suricata DNS log: ok=%v, srcIP=%s, domain=%s", ok, srcIP, domain)
	}

	// 2. BIND Log
	bindLog := `06-Sep-2026 18:00:00.000 client @0x7f123456 10.0.0.99#45123 (9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.evil.com): query: 9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.evil.com IN A + (127.0.0.1)`
	srcIP, domain, ok = ParseDNSLog(bindLog)
	if !ok || srcIP != "10.0.0.99" || domain != "9Zq1xK4vL8wB3mP7jF2tN6yC5rD0sA.evil.com" {
		t.Fatalf("Failed to parse BIND DNS log: ok=%v, srcIP=%s, domain=%s", ok, srcIP, domain)
	}
}
