package ml

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowFeatures represents normalized behavioral dimensions extracted from a network flow.
type FlowFeatures struct {
	ReqRate         float64 `json:"req_rate"`          // F1: Requests per second (0.0 - 500.0+)
	PayloadEntropy  float64 `json:"payload_entropy"`   // F2: Shannon entropy (0.0 - 8.0)
	PortDiversity   float64 `json:"port_diversity"`    // F3: Unique destination ports ratio (0.0 - 1.0)
	ErrorRate       float64 `json:"error_rate"`        // F4: HTTP 4xx/5xx ratio (0.0 - 1.0)
	BytePacketRatio float64 `json:"byte_packet_ratio"` // F5: Byte-to-packet payload variance / IAT
}

// ToVector returns the 5-dimensional numerical slice for model evaluation.
func (f FlowFeatures) ToVector() []float64 {
	return []float64{
		f.ReqRate,
		f.PayloadEntropy,
		f.PortDiversity,
		f.ErrorRate,
		f.BytePacketRatio,
	}
}

// MLAnomalyResult captures the classification confidence and feature contributions.
type MLAnomalyResult struct {
	IsAnomaly       bool              `json:"is_anomaly"`
	AnomalyScore    float64           `json:"anomaly_score"`   // 0.0 -> 1.0
	ConfidencePct   float64           `json:"confidence_pct"`  // 0.0% -> 100.0%
	Features        FlowFeatures      `json:"features"`
	TopContributors map[string]float64 `json:"top_contributors"`
	Description     string            `json:"description"`
}

// iTreeNode is a node in an Isolation Tree.
type iTreeNode struct {
	SplitFeature int
	SplitValue   float64
	Size         int
	IsLeaf       bool
	Left         *iTreeNode
	Right        *iTreeNode
}

// IsolationForest implements a Pure-Go, zero-dependency anomaly detection ensemble.
type IsolationForest struct {
	mu         sync.RWMutex
	numTrees   int
	sampleSize int
	maxDepth   int
	trees      []*iTreeNode
	cFactor    float64
	trained    bool
}

// NewIsolationForest creates an ensemble of isolation trees.
func NewIsolationForest(numTrees, sampleSize int) *IsolationForest {
	if numTrees <= 0 {
		numTrees = 50
	}
	if sampleSize <= 0 {
		sampleSize = 256
	}
	maxDepth := int(math.Ceil(math.Log2(float64(sampleSize))))

	return &IsolationForest{
		numTrees:   numTrees,
		sampleSize: sampleSize,
		maxDepth:   maxDepth,
		trees:      make([]*iTreeNode, 0, numTrees),
		cFactor:    eulerConstantCorrection(sampleSize),
	}
}

// eulerConstantCorrection computes the average path length of unsuccessful searches in BST: c(n) = 2(ln(n-1) + 0.5772156649) - 2(n-1)/n.
func eulerConstantCorrection(n int) float64 {
	if n <= 1 {
		return 1.0
	}
	if n == 2 {
		return 1.0
	}
	fn := float64(n)
	return 2.0*(math.Log(fn-1.0)+0.5772156649) - (2.0 * (fn - 1.0) / fn)
}

// Fit trains the isolation forest ensemble on a collection of feature vectors.
func (f *IsolationForest) Fit(samples [][]float64) {
	if len(samples) == 0 {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	numSamples := len(samples)
	actualSampleSize := int(math.Min(float64(f.sampleSize), float64(numSamples)))
	f.cFactor = eulerConstantCorrection(actualSampleSize)
	f.maxDepth = int(math.Ceil(math.Log2(float64(actualSampleSize))))

	f.trees = make([]*iTreeNode, f.numTrees)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < f.numTrees; i++ {
		// Subsample without replacement
		subsample := make([][]float64, actualSampleSize)
		perm := rng.Perm(numSamples)
		for j := 0; j < actualSampleSize; j++ {
			subsample[j] = samples[perm[j]]
		}
		f.trees[i] = f.buildTree(subsample, 0, f.maxDepth, rng)
	}

	f.trained = true
}

func (f *IsolationForest) buildTree(data [][]float64, currentDepth, maxDepth int, rng *rand.Rand) *iTreeNode {
	if len(data) <= 1 || currentDepth >= maxDepth {
		return &iTreeNode{
			Size:   len(data),
			IsLeaf: true,
		}
	}

	numFeatures := len(data[0])
	splitFeature := rng.Intn(numFeatures)

	minVal, maxVal := data[0][splitFeature], data[0][splitFeature]
	for _, row := range data {
		if row[splitFeature] < minVal {
			minVal = row[splitFeature]
		}
		if row[splitFeature] > maxVal {
			maxVal = row[splitFeature]
		}
	}

	if minVal == maxVal {
		return &iTreeNode{
			Size:   len(data),
			IsLeaf: true,
		}
	}

	splitVal := minVal + rng.Float64()*(maxVal-minVal)

	var leftData, rightData [][]float64
	for _, row := range data {
		if row[splitFeature] < splitVal {
			leftData = append(leftData, row)
		} else {
			rightData = append(rightData, row)
		}
	}

	return &iTreeNode{
		SplitFeature: splitFeature,
		SplitValue:   splitVal,
		Size:         len(data),
		IsLeaf:       false,
		Left:         f.buildTree(leftData, currentDepth+1, maxDepth, rng),
		Right:        f.buildTree(rightData, currentDepth+1, maxDepth, rng),
	}
}

// Score calculates the anomaly score for a given vector x: s(x, n) = 2^(-E(h(x)) / c(n)).
func (f *IsolationForest) Score(x []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	heuristicBoost := f.heuristicScore(x)

	if !f.trained || len(f.trees) == 0 {
		return heuristicBoost
	}

	totalPathLength := 0.0
	for _, tree := range f.trees {
		totalPathLength += f.pathLength(x, tree, 0)
	}
	avgPathLength := totalPathLength / float64(len(f.trees))

	// Anomaly score formula: s = 2^(-avgPathLength / cFactor)
	treeScore := math.Pow(2.0, -avgPathLength/f.cFactor)
	finalScore := math.Max(treeScore, heuristicBoost)
	return math.Max(0.0, math.Min(1.0, finalScore))
}

func (f *IsolationForest) pathLength(x []float64, node *iTreeNode, currentDepth float64) float64 {
	if node == nil {
		return currentDepth
	}
	if node.IsLeaf || node.Size <= 1 {
		return currentDepth + eulerConstantCorrection(node.Size)
	}

	if node.SplitFeature < len(x) && x[node.SplitFeature] < node.SplitValue {
		return f.pathLength(x, node.Left, currentDepth+1)
	}
	return f.pathLength(x, node.Right, currentDepth+1)
}

func (f *IsolationForest) heuristicScore(x []float64) float64 {
	if len(x) < 5 {
		return 0.0
	}
	// x = [ReqRate, Entropy, PortDiv, ErrorRate, BytePacket]
	score := 0.0
	if x[0] > 10.0 {
		score += math.Min(0.35, (x[0]-10.0)/40.0)
	}
	if x[1] > 6.0 {
		score += 0.35 // High-entropy encrypted payload/shellcode
	} else if x[1] < 1.0 && x[0] > 5.0 {
		score += 0.25 // NOP sled / repetitive byte flooding
	}
	if x[2] > 0.25 {
		score += 0.30 // Port scanning / multi-port fuzzing
	}
	if x[3] > 0.4 {
		score += 0.25 // High 4xx error rate
	}
	return math.Min(1.0, score)
}

// FlowWindow tracks sliding-window flow statistics per IP.
type FlowWindow struct {
	mu           sync.Mutex
	timestamps   []int64
	ports        map[int]struct{}
	totalReqs    int
	errorReqs    int
	lastPayloads [][]byte
}

// FlowTracker extracts 5-dimensional flow vectors in real time.
type FlowTracker struct {
	mu      sync.RWMutex
	windows map[string]*FlowWindow
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		windows: make(map[string]*FlowWindow),
	}
}

// CalculateShannonEntropy measures data randomness (0.0 to 8.0 bits).
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func (ft *FlowTracker) Extract(ip string, payload []byte, destPort int, statusCode int, nowMs int64) FlowFeatures {
	ft.mu.Lock()
	win, exists := ft.windows[ip]
	if !exists {
		win = &FlowWindow{
			timestamps:   make([]int64, 0, 50),
			ports:        make(map[int]struct{}),
			lastPayloads: make([][]byte, 0, 10),
		}
		ft.windows[ip] = win
	}
	ft.mu.Unlock()

	win.mu.Lock()
	defer win.mu.Unlock()

	// Prune timestamps older than 60s
	cutoff := nowMs - 60000
	validIdx := 0
	for i, ts := range win.timestamps {
		if ts >= cutoff {
			validIdx = i
			break
		}
	}
	win.timestamps = win.timestamps[validIdx:]
	win.timestamps = append(win.timestamps, nowMs)

	if destPort > 0 {
		win.ports[destPort] = struct{}{}
	}
	win.totalReqs++
	if statusCode >= 400 {
		win.errorReqs++
	}

	// 1. Flow Request Rate (Req/Sec)
	var reqRate float64 = 1.0
	if len(win.timestamps) > 1 {
		spanSec := float64(nowMs-win.timestamps[0]) / 1000.0
		if spanSec > 0.1 {
			reqRate = float64(len(win.timestamps)) / spanSec
		}
	}

	// 2. Payload Shannon Entropy
	entropy := CalculateShannonEntropy(payload)

	// 3. Port Diversity Ratio
	portDiv := float64(len(win.ports)) / float64(math.Max(1.0, float64(win.totalReqs)))
	if portDiv > 1.0 {
		portDiv = 1.0
	}

	// 4. HTTP Error Rate Ratio
	errorRate := float64(win.errorReqs) / float64(math.Max(1.0, float64(win.totalReqs)))

	// 5. Byte-to-Packet Ratio / Timing variance
	bytePacketRatio := float64(len(payload)) / 1024.0 // Normalized to KB
	if bytePacketRatio > 10.0 {
		bytePacketRatio = 10.0
	}

	return FlowFeatures{
		ReqRate:         reqRate,
		PayloadEntropy:  entropy,
		PortDiversity:   portDiv,
		ErrorRate:       errorRate,
		BytePacketRatio: bytePacketRatio,
	}
}

// FlowAnomalyEngine manages real-time online anomaly detection and threat scoring feeds.
type FlowAnomalyEngine struct {
	mu             sync.RWMutex
	forest         *IsolationForest
	tracker        *FlowTracker
	threshold      float64
	baselineBuffer [][]float64
	inferences     uint64
	anomaliesFound uint64
}

var (
	defaultMLEngine *FlowAnomalyEngine
	mlOnce          sync.Once
)

// GetDefaultEngine returns the singleton ML anomaly detection engine.
func GetDefaultEngine() *FlowAnomalyEngine {
	mlOnce.Do(func() {
		defaultMLEngine = NewFlowAnomalyEngine(0.85)
	})
	return defaultMLEngine
}

// NewFlowAnomalyEngine creates and initializes the ML flow anomaly engine with synthetic benign baselines.
func NewFlowAnomalyEngine(threshold float64) *FlowAnomalyEngine {
	if threshold <= 0.0 || threshold > 1.0 {
		threshold = 0.85
	}

	engine := &FlowAnomalyEngine{
		forest:         NewIsolationForest(64, 128),
		tracker:        NewFlowTracker(),
		threshold:      threshold,
		baselineBuffer: make([][]float64, 0, 500),
	}

	engine.initSyntheticBaseline()
	return engine
}

// initSyntheticBaseline pre-trains the model with typical benign web/SSH/DNS baseline patterns.
func (e *FlowAnomalyEngine) initSyntheticBaseline() {
	var samples [][]float64
	rng := rand.New(rand.NewSource(42))

	// Benign browsing & steady API requests (low rate, moderate entropy, 1 port, 0% error)
	for i := 0; i < 200; i++ {
		reqRate := 0.5 + rng.Float64()*4.0                  // 0.5 - 4.5 req/s
		entropy := 3.5 + rng.Float64()*1.8                  // 3.5 - 5.3 entropy
		portDiv := 0.05 + rng.Float64()*0.1                 // 1-2 ports
		errRate := 0.0 + rng.Float64()*0.05                 // 0% - 5% error
		bytePacket := 0.2 + rng.Float64()*1.5               // 200B - 1.7KB
		samples = append(samples, []float64{reqRate, entropy, portDiv, errRate, bytePacket})
	}

	e.forest.Fit(samples)
}

// EvaluateFlow processes an incoming flow packet or event, extracting features and performing sub-millisecond inference.
func (e *FlowAnomalyEngine) EvaluateFlow(
	ip string,
	payload []byte,
	destPort int,
	statusCode int,
	nowMs int64,
) MLAnomalyResult {
	atomic.AddUint64(&e.inferences, 1)

	if nowMs == 0 {
		nowMs = time.Now().UnixMilli()
	}

	features := e.tracker.Extract(ip, payload, destPort, statusCode, nowMs)
	vec := features.ToVector()

	score := e.forest.Score(vec)
	isAnomaly := score >= e.threshold

	if isAnomaly {
		atomic.AddUint64(&e.anomaliesFound, 1)
	}

	// Calculate feature contributions
	contributors := make(map[string]float64)
	if features.ReqRate > 20.0 {
		contributors["Flow Velocity"] = math.Min(100.0, features.ReqRate*2.0)
	}
	if features.PayloadEntropy > 6.0 || (features.PayloadEntropy < 1.0 && len(payload) > 64) {
		contributors["Entropy Anomaly"] = (features.PayloadEntropy / 8.0) * 100.0
	}
	if features.PortDiversity > 0.4 {
		contributors["Port Diversity (Scan)"] = features.PortDiversity * 100.0
	}
	if features.ErrorRate > 0.6 {
		contributors["HTTP Error Burst"] = features.ErrorRate * 100.0
	}

	var desc []string
	for k, v := range contributors {
		desc = append(desc, fmt.Sprintf("%s (%.0f%%)", k, v))
	}
	descStr := "Nominal flow behavior"
	if len(desc) > 0 {
		descStr = strings.Join(desc, ", ")
	}

	return MLAnomalyResult{
		IsAnomaly:       isAnomaly,
		AnomalyScore:    score,
		ConfidencePct:   math.Round(score * 1000.0) / 10.0,
		Features:        features,
		TopContributors: contributors,
		Description:     descStr,
	}
}

// GetStats returns telemetry counters for the ML anomaly subsystem.
func (e *FlowAnomalyEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"inferences_total": atomic.LoadUint64(&e.inferences),
		"anomalies_total":  atomic.LoadUint64(&e.anomaliesFound),
		"threshold":        e.threshold,
		"model_trees":      e.forest.numTrees,
		"model_trained":    e.forest.trained,
	}
}
