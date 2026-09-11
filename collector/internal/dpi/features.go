package dpi

import (
	"bytes"
	"math"
)

// Exploit punctuation character set: ', ", ;, -, /, <, >, $, (, ), {, }, =
var isExploitPunctuation [256]bool

// Obfuscation / Escape character set: %, \, &
var isObfuscationChar [256]bool

// Malicious keywords token set
var maliciousTokens = []string{
	"exec",
	"eval",
	"base64",
	"system",
	"select",
	"union",
	"script",
	"load_file",
}

func init() {
	exploitPunctuation := []byte{
		'\'', '"', ';', '-', '/', '<', '>', '$', '(', ')', '{', '}', '=',
	}
	for _, b := range exploitPunctuation {
		isExploitPunctuation[b] = true
	}

	obfChars := []byte{'%', '\\', '&'}
	for _, b := range obfChars {
		isObfuscationChar[b] = true
	}
}

// Features contains mathematical vectors and density ratios extracted from a payload.
type Features struct {
	PayloadLength           int     `json:"payload_length"`
	ShannonEntropy          float64 `json:"shannon_entropy"`
	SpecialCharDensity      float64 `json:"special_char_density"`
	ObfuscationDensity      float64 `json:"obfuscation_density"`
	MaliciousKeywordDensity float64 `json:"malicious_keyword_density"`
	NormalizedPayload       string  `json:"normalized_payload,omitempty"`
}

var maliciousTokenBytes = [][]byte{
	[]byte("exec"),
	[]byte("eval"),
	[]byte("base64"),
	[]byte("system"),
	[]byte("select"),
	[]byte("union"),
	[]byte("script"),
	[]byte("load_file"),
}

// ExtractFeatures analyzes a raw byte payload and extracts mathematical vectors in real time.
// 1. Normalizes payload via URL unescaping with fallback to lowercase raw bytes.
// 2. Calculates exact Shannon entropy in a single pass.
// 3. Computes Special Character Density focusing on exploit punctuation.
// 4. Computes Obfuscation / Escape Density (%, \, & and comment evasion).
// 5. Computes Malicious Keyword Density against target token sets.
func ExtractFeatures(raw []byte) Features {
	rawLen := len(raw)
	if rawLen == 0 {
		return Features{}
	}

	// 1. Fast Payload Normalization
	normalizedBytes := normalizePayloadFast(raw)
	normLen := len(normalizedBytes)
	if normLen == 0 {
		return Features{PayloadLength: rawLen}
	}

	// 2 & 3. Single-pass exact entropy counts and special character density
	var counts [256]int
	var specialCount int
	for _, b := range normalizedBytes {
		counts[b]++
		if isExploitPunctuation[b] {
			specialCount++
		}
	}

	total := float64(normLen)
	var entropy float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	specialDensity := float64(specialCount) / total

	// 4. Obfuscation / Escape Density: %, \, & plus comment evasion tokens (/* and */)
	var obfCount int
	for i := 0; i < rawLen; i++ {
		b := raw[i]
		if isObfuscationChar[b] {
			obfCount++
		}
		if b == '/' && i+1 < rawLen && raw[i+1] == '*' {
			obfCount += 2
			i++
		} else if b == '*' && i+1 < rawLen && raw[i+1] == '/' {
			obfCount += 2
			i++
		}
	}
	obfDensity := float64(obfCount) / float64(rawLen)

	// 5. Malicious Keyword Density against token sets
	var kwChars int
	for _, token := range maliciousTokenBytes {
		count := bytes.Count(normalizedBytes, token)
		if count > 0 {
			kwChars += count * len(token)
		}
	}
	kwDensity := float64(kwChars) / total

	return Features{
		PayloadLength:           rawLen,
		ShannonEntropy:          entropy,
		SpecialCharDensity:      specialDensity,
		ObfuscationDensity:      obfDensity,
		MaliciousKeywordDensity: kwDensity,
		NormalizedPayload:       string(normalizedBytes),
	}
}

// normalizePayloadFast unescapes URL sequences while lowercasing bytes with minimal allocations.
func normalizePayloadFast(raw []byte) []byte {
	rawLen := len(raw)
	if rawLen == 0 {
		return nil
	}

	hasEncoding := false
	for _, b := range raw {
		if b == '%' || b == '+' {
			hasEncoding = true
			break
		}
	}

	if !hasEncoding {
		buf := make([]byte, rawLen)
		for i := 0; i < rawLen; i++ {
			buf[i] = toLowerTable[raw[i]]
		}
		return buf
	}

	// Decode URL escapes and lowercase simultaneously
	buf := make([]byte, 0, rawLen)
	for i := 0; i < rawLen; i++ {
		switch raw[i] {
		case '+':
			buf = append(buf, ' ')
		case '%':
			if i+2 < rawLen {
				h1 := fromHex(raw[i+1])
				h2 := fromHex(raw[i+2])
				if h1 >= 0 && h2 >= 0 {
					decoded := byte((h1 << 4) | h2)
					buf = append(buf, toLowerTable[decoded])
					i += 2
					continue
				}
			}
			buf = append(buf, '%')
		default:
			buf = append(buf, toLowerTable[raw[i]])
		}
	}
	return buf
}

func fromHex(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	if c >= 'A' && c <= 'F' {
		return int(c - 'A' + 10)
	}
	return -1
}

// CalculateShannonEntropy measures exact bit randomness: H(X) = -sum(P(x_i) * log2(P(x_i))).
func CalculateShannonEntropy(data []byte) float64 {
	dataLen := len(data)
	if dataLen == 0 {
		return 0.0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	var entropy float64
	total := float64(dataLen)
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// EvaluateAnomalyScore scores the extracted features using calibrated heuristic weights:
// - Short packets (<10 bytes) are filtered (returns 0.00).
// - Entropy > 4.5 -> 20% weight
// - Special Character Density -> 35% weight
// - Obfuscation Density -> 25% weight
// - Malicious Keyword Density -> 20% weight
// Returns a normalized confidence score between 0.00 and 1.00.
func EvaluateAnomalyScore(f Features) float64 {
	// Filter short packets (<10 bytes) to eliminate false positives on TCP handshakes / ACKs
	if f.PayloadLength < 10 {
		return 0.0
	}

	var score float64

	// 1. Entropy > 4.5 -> 20% weight
	if f.ShannonEntropy > 4.5 {
		entropyRatio := math.Min(1.0, (f.ShannonEntropy-4.5)/1.5)
		score += 0.20 * (0.60 + 0.40*entropyRatio)
	}

	// 2. Special Character Density -> 35% weight
	specNorm := math.Min(1.0, f.SpecialCharDensity/0.25)
	score += 0.35 * specNorm

	// 3. Obfuscation Density -> 25% weight
	obfNorm := math.Min(1.0, f.ObfuscationDensity/0.10)
	score += 0.25 * obfNorm

	// 4. Malicious Keyword Density -> 20% weight
	kwNorm := math.Min(1.0, f.MaliciousKeywordDensity/0.10)
	score += 0.20 * kwNorm

	return math.Max(0.0, math.Min(1.0, score))
}
