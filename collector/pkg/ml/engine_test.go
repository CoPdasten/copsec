package ml

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

func TestIsolationForestFitAndScore(t *testing.T) {
	forest := NewIsolationForest(32, 64)

	// Benign baseline samples (low values with natural variance)
	var samples [][]float64
	for i := 0; i < 100; i++ {
		reqRate := 0.5 + float64(i%10)*0.2
		entropy := 3.0 + float64(i%8)*0.2
		portDiv := 0.02 + float64(i%5)*0.01
		errRate := float64(i%4) * 0.01
		bytePkt := 0.2 + float64(i%6)*0.1
		samples = append(samples, []float64{reqRate, entropy, portDiv, errRate, bytePkt})
	}
	forest.Fit(samples)

	// Normal sample score should be low
	normalScore := forest.Score([]float64{1.0, 3.5, 0.05, 0.0, 0.5})
	if normalScore > 0.65 {
		t.Errorf("Expected low anomaly score for baseline sample, got %f", normalScore)
	}

	// Outlier / Anomaly sample score should be high
	outlierScore := forest.Score([]float64{250.0, 7.9, 0.95, 1.0, 8.5})
	if outlierScore < 0.65 {
		t.Errorf("Expected high anomaly score for extreme outlier, got %f", outlierScore)
	}
}

func TestShannonEntropyCalculation(t *testing.T) {
	// Zero entropy
	zeros := make([]byte, 100)
	if e := CalculateShannonEntropy(zeros); e != 0.0 {
		t.Errorf("Expected 0.0 entropy for uniform bytes, got %f", e)
	}

	// Maximum entropy (random bytes -> ~8.0)
	randomBytes := make([]byte, 1024)
	_, _ = rand.Read(randomBytes)
	e := CalculateShannonEntropy(randomBytes)
	if e < 7.2 {
		t.Errorf("Expected high entropy (>7.2) for random bytes, got %f", e)
	}
}

func TestFlowAnomalyEngineDetection(t *testing.T) {
	engine := NewFlowAnomalyEngine(0.70)
	now := time.Now().UnixMilli()

	// 1. Benign request
	benignPayload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	res1 := engine.EvaluateFlow("198.51.100.10", benignPayload, 80, 200, now)
	if res1.IsAnomaly {
		t.Errorf("Expected benign request to not be flagged as anomaly: %+v", res1)
	}

	// 2. High-volume stealth fuzzing / anomaly attack (high req rate + high entropy encrypted payload)
	encryptedPayload := make([]byte, 2048)
	_, _ = rand.Read(encryptedPayload)

	for i := 0; i < 30; i++ {
		_ = engine.EvaluateFlow("198.51.100.20", encryptedPayload, 8000+i, 404, now+int64(i*10))
	}
	res2 := engine.EvaluateFlow("198.51.100.20", encryptedPayload, 9999, 500, now+400)
	if !res2.IsAnomaly {
		t.Errorf("Expected high-velocity multi-port encrypted burst to be flagged as anomaly, got score: %f", res2.AnomalyScore)
	}
}

func TestInferenceLatencyBenchmark(t *testing.T) {
	engine := GetDefaultEngine()
	payload := []byte("POST /api/v1/auth HTTP/1.1\r\nHost: target.com\r\n\r\n")
	now := time.Now().UnixMilli()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		_ = engine.EvaluateFlow("198.51.100.30", payload, 443, 200, now+int64(i))
	}
	elapsed := time.Since(start)
	avgLatency := elapsed / 1000

	// Must be well under 500 microseconds per evaluation
	if avgLatency > 500*time.Microsecond {
		t.Errorf("Inference latency too slow: %v (target < 500µs)", avgLatency)
	}
}

func TestConcurrentMLEvaluationSafety(t *testing.T) {
	engine := GetDefaultEngine()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := []byte("GET /test HTTP/1.1\r\n")
			_ = engine.EvaluateFlow("198.51.100.40", payload, 80, 200, time.Now().UnixMilli())
		}(i)
	}
	wg.Wait()

	stats := engine.GetStats()
	if stats["inferences_total"].(uint64) < 50 {
		t.Errorf("Expected at least 50 inferences, got %v", stats["inferences_total"])
	}
}
