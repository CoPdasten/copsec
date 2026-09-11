package analyzer

import (
	"fmt"
	"math"
	"time"
)

// Precomputed table for f * log2(f) for f in [0, 1024) to accelerate zero-alloc analysis
var precomputedFLog2F [1024]float64

func init() {
	for i := 1; i < 1024; i++ {
		f := float64(i)
		precomputedFLog2F[i] = f * math.Log2(f)
	}
}

// CalculateEntropy computes the Shannon Entropy H(X) in bits per byte [0.0 - 8.0]
// using zero heap allocations and an algebraically simplified single-division formula:
//
//	H(X) = log2(n) - (1/n) * sum(f_i * log2(f_i))
func CalculateEntropy(data []byte) float64 {
	n := len(data)
	if n <= 1 {
		return 0.0
	}

	// 256-entry stack-allocated byte frequency array (0 heap allocations)
	var freq [256]uint32
	for _, b := range data {
		freq[b]++
	}

	var sumFLog2F float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		if count < 1024 {
			sumFLog2F += precomputedFLog2F[count]
		} else {
			f := float64(count)
			sumFLog2F += f * math.Log2(f)
		}
	}

	fn := float64(n)
	entropy := math.Log2(fn) - (sumFLog2F / fn)

	// Clamp floating point jitter within [0.0, 8.0]
	if entropy < 0.0 {
		return 0.0
	}
	if entropy > 8.0 {
		return 8.0
	}
	return entropy
}

// EntropyConfig defines baseline and anomaly thresholds for L7 payload inspection.
type EntropyConfig struct {
	MinLength           int     // Minimum payload length required for evaluation (default: 24 bytes)
	BaselineMin         float64 // Normal text/HTTP lower bound (default: 3.50)
	BaselineMax         float64 // Normal text/HTTP upper bound (default: 4.50)
	SuspiciousThreshold float64 // Elevated entropy threshold (default: 4.80)
	AnomalyThreshold    float64 // Critical C2 beacon / packed exploit threshold (default: 5.85)
}

// DefaultEntropyConfig returns production thresholds for enterprise active defense.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		MinLength:           24,
		BaselineMin:         3.50,
		BaselineMax:         4.50,
		SuspiciousThreshold: 4.80,
		AnomalyThreshold:    5.85,
	}
}

// Classification constants for security triage.
const (
	ClassificationNormal     = "NORMAL_TRAFFIC"
	ClassificationElevated   = "ELEVATED_STRUCTURED_DATA"
	ClassificationSuspicious = "SUSPICIOUS_ENCRYPTED_OR_COMPRESSED"
	ClassificationAnomaly    = "C2_BEACON_OR_PACKED_EXPLOIT"
)

// EntropyEvaluation records the mathematical score and security classification.
type EntropyEvaluation struct {
	Score          float64 `json:"score"`
	Length         int     `json:"length"`
	Classification string  `json:"classification"`
	IsAnomaly      bool    `json:"is_anomaly"`
	IsSuspicious   bool    `json:"is_suspicious"`
}

// EntropyEvaluator executes stateful heuristic scoring over L7 buffers.
type EntropyEvaluator struct {
	cfg EntropyConfig
}

// NewEntropyEvaluator initializes an evaluator with custom or default thresholds.
func NewEntropyEvaluator(cfg ...EntropyConfig) *EntropyEvaluator {
	c := DefaultEntropyConfig()
	if len(cfg) > 0 {
		c = cfg[0]
	}
	return &EntropyEvaluator{cfg: c}
}

// Evaluate analyzes byte distribution randomness across an L7 buffer.
func (e *EntropyEvaluator) Evaluate(payload []byte) EntropyEvaluation {
	n := len(payload)
	if n < e.cfg.MinLength {
		return EntropyEvaluation{
			Score:          0.0,
			Length:         n,
			Classification: ClassificationNormal,
			IsAnomaly:      false,
			IsSuspicious:   false,
		}
	}

	score := CalculateEntropy(payload)

	res := EntropyEvaluation{
		Score:  score,
		Length: n,
	}

	if score >= e.cfg.AnomalyThreshold {
		res.Classification = ClassificationAnomaly
		res.IsAnomaly = true
		res.IsSuspicious = true
	} else if score >= e.cfg.SuspiciousThreshold {
		res.Classification = ClassificationSuspicious
		res.IsAnomaly = false
		res.IsSuspicious = true
	} else if score > e.cfg.BaselineMax {
		res.Classification = ClassificationElevated
		res.IsAnomaly = false
		res.IsSuspicious = false
	} else {
		res.Classification = ClassificationNormal
		res.IsAnomaly = false
		res.IsSuspicious = false
	}

	return res
}

// BanInjector abstracts eBPF/XDP map quarantine insertion.
type BanInjector interface {
	AddBanWithTTL(ipStr string, ttl time.Duration, reasonCode uint32, reason string) error
}

// TelemetryDispatcher abstracts gRPC streaming to the Vault controller.
type TelemetryDispatcher interface {
	DispatchLog(srcIP string, eventType string, score int, details string) error
}

// HandleEntropyAnomaly evaluates an L7 buffer, automatically enforces an eBPF quarantine ban
// if the threshold is exceeded, and streams a structured telemetry alert to the Controller.
func (e *EntropyEvaluator) HandleEntropyAnomaly(
	srcIP string,
	payload []byte,
	ban BanInjector,
	disp TelemetryDispatcher,
) (EntropyEvaluation, error) {
	eval := e.Evaluate(payload)
	if !eval.IsAnomaly {
		return eval, nil
	}

	// 1. Automatically quarantine offending IP in the eBPF banned_ips LRU map
	// Reason code 3 = DROP_REASON_ENTROPY_ANOMALY
	reason := fmt.Sprintf("High-Entropy L7 Anomaly (H=%.2f > %.2f) — C2 Beacon / Packed Payload",
		eval.Score, e.cfg.AnomalyThreshold)

	if ban != nil && srcIP != "" {
		if err := ban.AddBanWithTTL(srcIP, 30*time.Minute, 3, reason); err != nil {
			return eval, fmt.Errorf("failed to quarantine high-entropy IP %s: %w", srcIP, err)
		}
	}

	// 2. Dispatch telemetry event to Vault controller via gRPC
	if disp != nil && srcIP != "" {
		threatScore := int(math.Min(100, (eval.Score/8.0)*100.0))
		if err := disp.DispatchLog(srcIP, "ENTROPY_ANOMALY", threatScore, reason); err != nil {
			// Log error but return eval result
			return eval, fmt.Errorf("failed to dispatch entropy alert via gRPC: %w", err)
		}
	}

	return eval, nil
}
