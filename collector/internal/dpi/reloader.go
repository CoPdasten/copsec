package dpi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	managementproto "github.com/copsec/collector/proto/management"
	"google.golang.org/grpc"
)

// AhoCorasickDFA encapsulates an immutable compiled deterministic finite automaton with jump tables.
type AhoCorasickDFA struct {
	root       *trieNode
	rules      []Rule
	version    uint64
	compiledAt time.Time
}

// Version returns the compilation sequence number for this DFA instance.
func (d *AhoCorasickDFA) Version() uint64 {
	if d == nil {
		return 0
	}
	return d.version
}

// CompiledAt returns the exact UTC timestamp when this state machine was constructed.
func (d *AhoCorasickDFA) CompiledAt() time.Time {
	if d == nil {
		return time.Time{}
	}
	return d.compiledAt
}

// Rules returns a defensive copy of the rules compiled into this automaton.
func (d *AhoCorasickDFA) Rules() []Rule {
	if d == nil {
		return nil
	}
	res := make([]Rule, len(d.rules))
	copy(res, d.rules)
	return res
}

// RuleCount returns the total number of distinct signatures active in this automaton.
func (d *AhoCorasickDFA) RuleCount() int {
	if d == nil {
		return 0
	}
	return len(d.rules)
}

// Scan performs single-pass deterministic O(N) traversal over raw byte stream.
// Returns the first matched signature verdict and true, or empty verdict and false.
func (d *AhoCorasickDFA) Scan(data []byte) (MatchResult, bool) {
	if d == nil || d.root == nil || len(data) == 0 {
		return MatchResult{}, false
	}

	curr := d.root
	for i := 0; i < len(data); i++ {
		b := toLowerTable[data[i]]
		curr = curr.children[b]
		if len(curr.matches) > 0 {
			first := curr.matches[0]
			return MatchResult{
				MatchedPattern: first.Pattern,
				RuleID:         first.ID,
				RuleName:       first.Name,
				Category:       first.Category,
				Offset:         i - len(first.Pattern) + 1,
			}, true
		}
	}

	return MatchResult{}, false
}

// ScanAll traverses raw bytes in single-pass O(N) and returns all matched signature verdicts.
func (d *AhoCorasickDFA) ScanAll(data []byte) []MatchResult {
	if d == nil || d.root == nil || len(data) == 0 {
		return nil
	}

	var results []MatchResult
	curr := d.root
	for i := 0; i < len(data); i++ {
		b := toLowerTable[data[i]]
		curr = curr.children[b]
		for _, m := range curr.matches {
			results = append(results, MatchResult{
				MatchedPattern: m.Pattern,
				RuleID:         m.ID,
				RuleName:       m.Name,
				Category:       m.Category,
				Offset:         i - len(m.Pattern) + 1,
			})
		}
	}

	return results
}

// DynamicEngine provides zero-downtime hot-swapping of Aho-Corasick DFAs using atomic.Pointer.
// Read operations (Scan, ScanAll) are completely lock-free and never blocked during swaps.
type DynamicEngine struct {
	dfa          atomic.Pointer[AhoCorasickDFA]
	swapMu       sync.Mutex
	version      atomic.Uint64
	swapCount    atomic.Uint64
	lastSwapNano atomic.Int64
}

// NewDynamicEngine constructs a DynamicEngine initialized with the provided rule collection.
func NewDynamicEngine(initialRules []Rule) *DynamicEngine {
	engine := &DynamicEngine{}
	if len(initialRules) == 0 {
		initialRules = GetEmbeddedSignatures()
	}
	_ = engine.HotSwapRules(initialRules)
	return engine
}

// HotSwapRules validates signatures, compiles a fresh deterministic DFA with precomputed
// [256]*trieNode jump tables, and atomically swaps the active engine pointer.
func (e *DynamicEngine) HotSwapRules(signatures []Rule) error {
	if len(signatures) == 0 {
		return errors.New("cannot hot-swap empty signature set")
	}

	e.swapMu.Lock()
	defer e.swapMu.Unlock()

	nextVersion := e.version.Add(1)
	compiledDFA := compileDFA(signatures, nextVersion)

	// Atomically swap the active DFA pointer with zero downtime
	e.dfa.Store(compiledDFA)
	e.swapCount.Add(1)
	e.lastSwapNano.Store(time.Now().UnixNano())

	log.Printf("[DPI_RELOADER] ⚡ Atomically hot-swapped DFA ruleset to version %d (%d rules compiled)",
		nextVersion, compiledDFA.RuleCount())
	return nil
}

// HotSwapRawPatterns parses raw string patterns (such as CVE identifiers or regex-free strings),
// wraps them into typed Rules, and atomically updates the DFA.
func (e *DynamicEngine) HotSwapRawPatterns(patterns []string, category RuleCategory, severity string) error {
	if len(patterns) == 0 {
		return errors.New("empty patterns list")
	}

	if category == "" {
		category = CategoryCustomZeroDay
	}
	if severity == "" {
		severity = "HIGH"
	}

	rules := make([]Rule, 0, len(patterns))
	for idx, pat := range patterns {
		clean := strings.TrimSpace(pat)
		if clean == "" {
			continue
		}
		rules = append(rules, Rule{
			ID:       fmt.Sprintf("RAW_SIG_%d", idx+1),
			Name:     fmt.Sprintf("Custom Pattern: %s", clean),
			Pattern:  clean,
			Category: category,
			Severity: severity,
		})
	}

	if len(rules) == 0 {
		return errors.New("no valid patterns extracted")
	}

	return e.HotSwapRules(rules)
}

// HotSwapFromJSON parses a JSON bundle representing []Rule and applies the atomic swap.
func (e *DynamicEngine) HotSwapFromJSON(jsonData []byte) error {
	var rules []Rule
	if err := json.Unmarshal(jsonData, &rules); err != nil {
		return fmt.Errorf("failed to parse JSON rule bundle: %w", err)
	}
	return e.HotSwapRules(rules)
}

// Scan delegates single-pass traversal to the active atomic DFA.
func (e *DynamicEngine) Scan(data []byte) (MatchResult, bool) {
	active := e.dfa.Load()
	if active == nil {
		return MatchResult{}, false
	}
	return active.Scan(data)
}

// ScanAll delegates multi-pattern extraction to the active atomic DFA.
func (e *DynamicEngine) ScanAll(data []byte) []MatchResult {
	active := e.dfa.Load()
	if active == nil {
		return nil
	}
	return active.ScanAll(data)
}

// GetRules returns a snapshot of rules in the currently active DFA.
func (e *DynamicEngine) GetRules() []Rule {
	active := e.dfa.Load()
	if active == nil {
		return nil
	}
	return active.Rules()
}

// RuleCount returns the total number of rules in the active DFA.
func (e *DynamicEngine) RuleCount() int {
	active := e.dfa.Load()
	if active == nil {
		return 0
	}
	return active.RuleCount()
}

// Version returns the current active DFA version.
func (e *DynamicEngine) Version() uint64 {
	active := e.dfa.Load()
	if active == nil {
		return 0
	}
	return active.Version()
}

// SwapCount returns the cumulative number of successful atomic hot swaps.
func (e *DynamicEngine) SwapCount() uint64 {
	return e.swapCount.Load()
}

// LastSwapTime returns the timestamp of the last successful hot swap.
func (e *DynamicEngine) LastSwapTime() time.Time {
	nano := e.lastSwapNano.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

// compileDFA compiles rules into an AhoCorasickDFA with precomputed [256]*trieNode jump transitions.
func compileDFA(rules []Rule, version uint64) *AhoCorasickDFA {
	root := &trieNode{}
	cleanRules := make([]Rule, 0, len(rules))

	for _, r := range rules {
		normPattern := strings.ToLower(strings.TrimSpace(r.Pattern))
		if normPattern == "" {
			continue
		}

		ruleCopy := r
		ruleCopy.Pattern = normPattern
		cleanRules = append(cleanRules, ruleCopy)

		curr := root
		for i := 0; i < len(normPattern); i++ {
			b := normPattern[i]
			if curr.children[b] == nil {
				curr.children[b] = &trieNode{}
			}
			curr = curr.children[b]
		}
		curr.matches = append(curr.matches, &ruleCopy)
	}

	// BFS-driven Failure Pointer & Jump Table Construction
	queue := make([]*trieNode, 0, 1024)

	// Level 1: Direct root children
	for b := 0; b < 256; b++ {
		if root.children[b] != nil {
			root.children[b].fail = root
			queue = append(queue, root.children[b])
		} else {
			root.children[b] = root
		}
	}

	// Level 2+: Propagate failure pointers and build deterministic jump transitions
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for b := 0; b < 256; b++ {
			child := curr.children[b]
			if child != nil {
				child.fail = curr.fail.children[b]
				if len(child.fail.matches) > 0 {
					child.matches = append(child.matches, child.fail.matches...)
				}
				queue = append(queue, child)
			} else {
				// Precompute next transition jump table so scan loop does not traverse fail chains
				curr.children[b] = curr.fail.children[b]
			}
		}
	}

	return &AhoCorasickDFA{
		root:       root,
		rules:      cleanRules,
		version:    version,
		compiledAt: time.Now(),
	}
}

// ManagementServer implements SensorManagementServiceServer for remote signature pushing (e.g. from pardus1).
type ManagementServer struct {
	managementproto.UnimplementedSensorManagementServiceServer
	engine *DynamicEngine
}

// NewManagementServer creates a gRPC server adapter for the DynamicEngine.
func NewManagementServer(engine *DynamicEngine) *ManagementServer {
	return &ManagementServer{
		engine: engine,
	}
}

// PushSignatures handles dynamic bundle deployment from remote management nodes without service restarts.
func (s *ManagementServer) PushSignatures(ctx context.Context, req *managementproto.SignatureBundle) (*managementproto.PushSignaturesResponse, error) {
	if req == nil {
		return nil, errors.New("nil signature bundle request")
	}

	sender := req.PushedBy
	if sender == "" {
		sender = "unknown-controller"
	}

	log.Printf("[MANAGEMENT_GRPC] Inbound threat bundle %q (v%s) received from %q with %d structured rules",
		req.BundleId, req.BundleVersion, sender, len(req.Rules))

	var newRules []Rule

	// 1. Parse structured rules if present
	if len(req.Rules) > 0 {
		newRules = make([]Rule, 0, len(req.Rules))
		for _, r := range req.Rules {
			if strings.TrimSpace(r.Pattern) == "" {
				continue
			}
			newRules = append(newRules, Rule{
				ID:       r.Id,
				Name:     r.Name,
				Pattern:  r.Pattern,
				Category: RuleCategory(r.Category),
				Severity: r.Severity,
			})
		}
	}

	// 2. Parse raw bundle payload if provided
	if len(req.RawBundleData) > 0 {
		var rawRules []Rule
		if err := json.Unmarshal(req.RawBundleData, &rawRules); err == nil {
			newRules = append(newRules, rawRules...)
		}
	}

	if len(newRules) == 0 {
		return &managementproto.PushSignaturesResponse{
			Success:        false,
			Message:        "no valid signatures found in bundle",
			TimestampMs:    time.Now().UnixMilli(),
			EngineVersion:  s.engine.Version(),
			RulesLoaded:    0,
		}, nil
	}

	// 3. Atomically compile & swap
	if err := s.engine.HotSwapRules(newRules); err != nil {
		return &managementproto.PushSignaturesResponse{
			Success:        false,
			Message:        fmt.Sprintf("compilation failed: %v", err),
			TimestampMs:    time.Now().UnixMilli(),
			EngineVersion:  s.engine.Version(),
			RulesLoaded:    0,
		}, nil
	}

	return &managementproto.PushSignaturesResponse{
		Success:       true,
		Message:       fmt.Sprintf("successfully compiled and hot-swapped %d rules from %s", len(newRules), sender),
		RulesLoaded:   uint32(len(newRules)),
		EngineVersion: s.engine.Version(),
		TimestampMs:   time.Now().UnixMilli(),
	}, nil
}

// GetEngineStatus returns telemetry regarding active rules and swap counters.
func (s *ManagementServer) GetEngineStatus(ctx context.Context, req *managementproto.EngineStatusRequest) (*managementproto.EngineStatusResponse, error) {
	return &managementproto.EngineStatusResponse{
		ActiveRulesCount:   uint32(s.engine.RuleCount()),
		EngineVersion:      s.engine.Version(),
		LastSwapTimestampMs: s.engine.LastSwapTime().UnixMilli(),
		TotalSwaps:         s.engine.SwapCount(),
	}, nil
}

// StartManagementServer binds and serves the SensorManagementService on the specified listener.
func StartManagementServer(lis net.Listener, engine *DynamicEngine, opt ...grpc.ServerOption) (*grpc.Server, error) {
	grpcServer := grpc.NewServer(opt...)
	server := NewManagementServer(engine)
	managementproto.RegisterSensorManagementServiceServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[MANAGEMENT_GRPC] Server exited with error: %v", err)
		}
	}()

	log.Printf("[MANAGEMENT_GRPC] 🛡️ Sensor Management Service actively listening on %s", lis.Addr())
	return grpcServer, nil
}
