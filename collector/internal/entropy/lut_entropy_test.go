package entropy

import (
	"crypto/rand"
	"math"
	"testing"
)

// referenceShannon calculates standard Shannon entropy using traditional float64 math.Log2.
func referenceShannon(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	fn := float64(n)
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / fn
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func TestCalculateEntropyLUT_Consistency(t *testing.T) {
	const epsilon = 1e-9

	// Case 1: Pure uniform repeating single byte -> Exactly 0.0 bits
	zeroData := make([]byte, 256)
	for i := range zeroData {
		zeroData[i] = 0xAA
	}
	hZero := CalculateEntropyLUT(zeroData)
	if math.Abs(hZero-0.0) > epsilon {
		t.Errorf("expected 0.0 entropy for uniform byte payload, got: %f", hZero)
	}

	// Case 2: Exactly 1 instance of every possible byte [0..255] -> Exactly 8.0 bits (max theoretical)
	allBytes := make([]byte, 256)
	for i := 0; i < 256; i++ {
		allBytes[i] = byte(i)
	}
	hMax := CalculateEntropyLUT(allBytes)
	if math.Abs(hMax-8.0) > epsilon {
		t.Errorf("expected 8.0 entropy for all-distinct byte payload, got: %f", hMax)
	}

	// Case 3: 50/50 two symbols (128 of 'A', 128 of 'B') -> Exactly 1.0 bit
	halfHalf := make([]byte, 256)
	for i := 0; i < 128; i++ {
		halfHalf[i] = 'A'
	}
	for i := 128; i < 256; i++ {
		halfHalf[i] = 'B'
	}
	hOne := CalculateEntropyLUT(halfHalf)
	if math.Abs(hOne-1.0) > epsilon {
		t.Errorf("expected 1.0 entropy for 50/50 payload, got: %f", hOne)
	}

	// Case 4: Multiple pseudo-random and patterned slices compared against reference Shannon
	for trial := 0; trial < 50; trial++ {
		sample := make([]byte, 256)
		_, err := rand.Read(sample)
		if err != nil {
			t.Fatalf("crypto/rand read failed: %v", err)
		}

		lutVal := CalculateEntropyLUT(sample)
		refVal := referenceShannon(sample)

		diff := math.Abs(lutVal - refVal)
		if diff > epsilon {
			t.Errorf("trial %d: LUT entropy (%f) diverged from reference (%f), diff: %e", trial, lutVal, refVal, diff)
		}
	}

	// Case 5: Empty slice handling
	if e := CalculateEntropyLUT(nil); e != 0.0 {
		t.Errorf("expected 0.0 for nil slice, got: %f", e)
	}
	if e := CalculateEntropyLUT([]byte{}); e != 0.0 {
		t.Errorf("expected 0.0 for empty slice, got: %f", e)
	}

	// Case 6: Variable length (non-256 byte) consistency
	varLenSample := []byte("GET /login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\n\r\n")
	lutVar := CalculateEntropyLUT(varLenSample)
	refVar := referenceShannon(varLenSample)
	if math.Abs(lutVar-refVar) > epsilon {
		t.Errorf("variable length LUT entropy (%f) diverged from reference (%f)", lutVar, refVar)
	}
}

func TestIsHighEntropyAnomaly(t *testing.T) {
	// Normal ASCII plaintext (typical entropy 3.5 - 4.5)
	plain := []byte("The quick brown fox jumps over the lazy dog repeatedly to form an ASCII string of 256 bytes. Testing normal English plain text payload distribution for lower entropy scoring comparison against encrypted or packed binary payloads.")
	for len(plain) < 256 {
		plain = append(plain, ' ')
	}
	isAnomaly, score := IsHighEntropyAnomaly(plain[:256], 6.5)
	if isAnomaly {
		t.Errorf("plain text erroneously flagged as high-entropy anomaly: score %f", score)
	}

	// High-entropy random payload (typical entropy > 7.5)
	randomBuf := make([]byte, 256)
	_, _ = rand.Read(randomBuf)
	isAnomaly, score = IsHighEntropyAnomaly(randomBuf, 6.5)
	if !isAnomaly {
		t.Errorf("random encrypted payload failed to trigger anomaly threshold: score %f", score)
	}
}

func BenchmarkCalculateEntropyLUT(b *testing.B) {
	payload := make([]byte, 256)
	_, _ = rand.Read(payload)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CalculateEntropyLUT(payload)
	}
}

func BenchmarkReferenceShannon(b *testing.B) {
	payload := make([]byte, 256)
	_, _ = rand.Read(payload)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = referenceShannon(payload)
	}
}
