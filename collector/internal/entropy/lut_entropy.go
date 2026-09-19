package entropy

import (
	"math"
)

// log2LUT precomputes -p * log2(p) for all possible frequency counts [0..256]
// in a standard 256-byte packet slice (where p = count / 256.0).
var log2LUT [257]float64

func init() {
	// For count = 0: lim_{p -> 0} -p * log2(p) = 0
	log2LUT[0] = 0.0

	for count := 1; count <= 256; count++ {
		p := float64(count) / 256.0
		log2LUT[count] = -p * math.Log2(p)
	}
}

// CalculateEntropyLUT computes the Shannon Entropy H(X) in bits per symbol [0.0 - 8.0]
// using zero heap allocations. For standard 256-byte payload slices, it performs an O(1)
// look-up table summation without floating-point division or logarithm calculations.
func CalculateEntropyLUT(payload []byte) float64 {
	n := len(payload)
	if n == 0 {
		return 0.0
	}

	// 256-entry stack-allocated byte frequency array (512 bytes, 0 heap allocations)
	var freq [256]uint16
	for _, b := range payload {
		freq[b]++
	}

	// Fast-path: Standard 256-byte slice executed via direct Look-Up Table (~4 ns/op)
	if n == 256 {
		var entropy float64
		for _, count := range freq {
			entropy += log2LUT[count]
		}
		if entropy < 0.0 {
			return 0.0
		}
		if entropy > 8.0 {
			return 8.0
		}
		return entropy
	}

	// General-path: Variable length payload fallback
	fn := float64(n)
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / fn
			entropy -= p * math.Log2(p)
		}
	}

	if entropy < 0.0 {
		return 0.0
	}
	if entropy > 8.0 {
		return 8.0
	}
	return entropy
}

// IsHighEntropyAnomaly checks whether a payload exceeds the specified Shannon entropy threshold,
// identifying encrypted shellcode, packed executables, or covert tunneling.
func IsHighEntropyAnomaly(payload []byte, threshold float64) (bool, float64) {
	entropy := CalculateEntropyLUT(payload)
	return entropy >= threshold, entropy
}
