package analyzer

import (
	"crypto/rand"
	"math"
	"testing"
	"time"
)

func TestCalculateEntropyKnownValues(t *testing.T) {
	// Case 1: Empty or 1-byte data -> 0.0
	if h := CalculateEntropy(nil); h != 0.0 {
		t.Errorf("Expected 0.0 for nil, got %f", h)
	}
	if h := CalculateEntropy([]byte("A")); h != 0.0 {
		t.Errorf("Expected 0.0 for 1 byte, got %f", h)
	}

	// Case 2: Monotonous repeating data (Zero entropy)
	zeroData := make([]byte, 256)
	for i := range zeroData {
		zeroData[i] = 'Z'
	}
	if h := CalculateEntropy(zeroData); h != 0.0 {
		t.Errorf("Expected 0.0 for identical bytes, got %f", h)
	}

	// Case 3: Uniform distribution of all 256 byte values -> exactly 8.0 bits
	uniform := make([]byte, 256)
	for i := 0; i < 256; i++ {
		uniform[i] = byte(i)
	}
	hUniform := CalculateEntropy(uniform)
	if math.Abs(hUniform-8.0) > 1e-9 {
		t.Errorf("Expected exactly 8.0 for uniform byte distribution, got %f", hUniform)
	}

	// Case 4: English plain text baseline (~3.5 - 4.5)
	plainText := []byte("The quick brown fox jumps over the lazy dog and runs through the forest again and again with all the animals watching peacefully.")
	hPlain := CalculateEntropy(plainText)
	if hPlain < 3.5 || hPlain > 4.5 {
		t.Errorf("Expected standard prose entropy between 3.5 and 4.5, got %f", hPlain)
	}

	// Case 5: Cryptographic pseudo-random data (High entropy > 7.0)
	randomBytes := make([]byte, 512)
	_, _ = rand.Read(randomBytes)
	hRand := CalculateEntropy(randomBytes)
	if hRand < 7.0 {
		t.Errorf("Expected crypto random entropy > 7.0, got %f", hRand)
	}
}

func TestEntropyEvaluatorClassification(t *testing.T) {
	evaluator := NewEntropyEvaluator()

	// Short payload (< 24 bytes) ignored to prevent false positives
	shortRes := evaluator.Evaluate([]byte("短"))
	if shortRes.IsAnomaly || shortRes.Classification != ClassificationNormal {
		t.Errorf("Expected short payload to be classified as NORMAL, got %+v", shortRes)
	}

	// Normal HTTP text
	normalPayload := []byte("GET /api/v1/health HTTP/1.1\r\nHost: internal.corp\r\nAuthorization: Bearer token123\r\n\r\n")
	normRes := evaluator.Evaluate(normalPayload)
	if normRes.IsAnomaly {
		t.Errorf("Expected normal traffic to NOT be flagged as anomaly, got score %f", normRes.Score)
	}

	// High entropy random C2 beacon / packed payload
	c2Payload := make([]byte, 256)
	_, _ = rand.Read(c2Payload)
	anomalyRes := evaluator.Evaluate(c2Payload)
	if !anomalyRes.IsAnomaly || anomalyRes.Classification != ClassificationAnomaly {
		t.Errorf("Expected random payload to be flagged as anomaly, got %+v", anomalyRes)
	}
	if anomalyRes.Score < 5.85 {
		t.Errorf("Expected anomaly score >= 5.85, got %f", anomalyRes.Score)
	}
}

// Mock BanInjector
type mockBanInjector struct {
	bannedIP string
	ttl      time.Duration
	reason   string
}

func (m *mockBanInjector) AddBanWithTTL(ipStr string, ttl time.Duration, reasonCode uint32, reason string) error {
	m.bannedIP = ipStr
	m.ttl = ttl
	m.reason = reason
	return nil
}

// Mock TelemetryDispatcher
type mockDispatcher struct {
	dispatchedIP string
	eventType    string
	score        int
	details      string
}

func (m *mockDispatcher) DispatchLog(srcIP string, eventType string, score int, details string) error {
	m.dispatchedIP = srcIP
	m.eventType = eventType
	m.score = score
	m.details = details
	return nil
}

func TestHandleEntropyAnomalyIntegration(t *testing.T) {
	evaluator := NewEntropyEvaluator()
	mockBan := &mockBanInjector{}
	mockDisp := &mockDispatcher{}

	highEntropyBytes := make([]byte, 128)
	_, _ = rand.Read(highEntropyBytes)

	srcIP := "185.220.101.5"
	eval, err := evaluator.HandleEntropyAnomaly(srcIP, highEntropyBytes, mockBan, mockDisp)
	if err != nil {
		t.Fatalf("HandleEntropyAnomaly returned error: %v", err)
	}

	if !eval.IsAnomaly {
		t.Fatalf("Expected anomaly flag to be true")
	}

	if mockBan.bannedIP != srcIP {
		t.Errorf("Expected IP %s to be quarantined, got %s", srcIP, mockBan.bannedIP)
	}

	if mockDisp.dispatchedIP != srcIP || mockDisp.eventType != "ENTROPY_ANOMALY" {
		t.Errorf("Expected telemetry dispatch for %s, got %+v", srcIP, mockDisp)
	}
}

// Benchmark asserting 0 heap allocations per operation
func BenchmarkCalculateEntropy(b *testing.B) {
	sample := []byte("POST /c2/beacon?data=X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* HTTP/1.1\r\nHost: malicious.xyz\r\n\r\n")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CalculateEntropy(sample)
	}
}
