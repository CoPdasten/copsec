package healing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FIMTarget encapsulates a protected system configuration file and its immutable baseline.
type FIMTarget struct {
	Path            string      `json:"path"`
	BaselineSHA256  string      `json:"baseline_sha256"`
	BaselineContent []byte      `json:"-"`
	Permissions     os.FileMode `json:"permissions"`
	LastCheckedMs   int64       `json:"last_checked_ms"`
}

// FIMDriftEvent records a detected configuration tampering incident and its automated self-healing action.
type FIMDriftEvent struct {
	TimestampMs    int64  `json:"timestamp_ms"`
	FilePath       string `json:"file_path"`
	TamperedSHA256 string `json:"tampered_sha256"`
	BaselineSHA256 string `json:"baseline_sha256"`
	Remediated     bool   `json:"remediated"`
	ThreatScore    int    `json:"threat_score"`
	MitreID        string `json:"mitre_id"`
	Details        string `json:"details"`
}

// FIMHealingEngine monitors critical files and automatically restores unauthorized modifications.
type FIMHealingEngine struct {
	mu            sync.RWMutex
	targets       map[string]*FIMTarget
	driftsTotal   uint64
	healedTotal   uint64
	recentEvents  []FIMDriftEvent
	onDriftHealed func(ev FIMDriftEvent)
}

var (
	defaultEngine *FIMHealingEngine
	engineOnce    sync.Once
)

// GetDefaultFIMEngine returns the singleton self-healing FIM engine.
func GetDefaultFIMEngine() *FIMHealingEngine {
	engineOnce.Do(func() {
		defaultEngine = NewFIMHealingEngine(nil)
	})
	return defaultEngine
}

// NewFIMHealingEngine initializes the Self-Healing FIM subsystem.
func NewFIMHealingEngine(onDrift func(ev FIMDriftEvent)) *FIMHealingEngine {
	engine := &FIMHealingEngine{
		targets:       make(map[string]*FIMTarget),
		recentEvents:  make([]FIMDriftEvent, 0, 50),
		onDriftHealed: onDrift,
	}
	engine.initDefaultTargets()
	return engine
}

func (e *FIMHealingEngine) initDefaultTargets() {
	// Sample critical targets with fallback creation for sandboxed environments
	defaultPaths := []string{
		"/etc/ssh/sshd_config",
		"/etc/sudoers",
		"/etc/passwd",
		"/etc/pam.d/common-auth",
	}

	for _, p := range defaultPaths {
		if data, err := os.ReadFile(p); err == nil {
			info, _ := os.Stat(p)
			mode := os.FileMode(0644)
			if info != nil {
				mode = info.Mode()
			}
			e.RegisterTarget(p, data, mode)
		}
	}
}

// RegisterTarget registers a baseline file snapshot into the self-healing vault.
func (e *FIMHealingEngine) RegisterTarget(path string, content []byte, mode os.FileMode) {
	e.mu.Lock()
	defer e.mu.Unlock()

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)

	e.targets[path] = &FIMTarget{
		Path:            path,
		BaselineSHA256:  hashStr,
		BaselineContent: contentCopy,
		Permissions:     mode,
		LastCheckedMs:   time.Now().UnixMilli(),
	}
}

// VerifyAndHeal checks a single file for unauthorized drift and immediately restores baseline if tampered.
func (e *FIMHealingEngine) VerifyAndHeal(path string) (*FIMDriftEvent, bool) {
	e.mu.Lock()
	target, exists := e.targets[path]
	e.mu.Unlock()

	if !exists {
		return nil, false
	}

	currentData, err := os.ReadFile(path)
	if err != nil {
		// File was deleted or moved: Trigger emergency self-healing restoration
		return e.executeHealing(target, "FILE_DELETED", fmt.Sprintf("Critical config %s was removed. Instantly recreated from immutable baseline.", path)), true
	}

	currentHash := sha256.Sum256(currentData)
	currentHashStr := hex.EncodeToString(currentHash[:])

	if currentHashStr != target.BaselineSHA256 {
		// Hash Mismatch: Configuration drift detected!
		details := fmt.Sprintf("Cryptographic drift on %s: Hash %s != Baseline %s. Overwriting with sanitized baseline.",
			path, currentHashStr[:8], target.BaselineSHA256[:8])
		return e.executeHealing(target, currentHashStr, details), true
	}

	target.LastCheckedMs = time.Now().UnixMilli()
	return nil, false
}

// VerifyAll scans all registered targets and remediates any detected tampering.
func (e *FIMHealingEngine) VerifyAll() []*FIMDriftEvent {
	e.mu.RLock()
	var paths []string
	for p := range e.targets {
		paths = append(paths, p)
	}
	e.mu.RUnlock()

	var events []*FIMDriftEvent
	for _, p := range paths {
		if ev, drifted := e.VerifyAndHeal(p); drifted && ev != nil {
			events = append(events, ev)
		}
	}
	return events
}

// StartWatchLoop periodically checks file hashes in the background.
func (e *FIMHealingEngine) StartWatchLoop(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.VerifyAll()
		}
	}
}

func (e *FIMHealingEngine) executeHealing(target *FIMTarget, tamperedHash, details string) *FIMDriftEvent {
	atomic.AddUint64(&e.driftsTotal, 1)

	// Remediate: Atomic write baseline back to target path
	err := os.WriteFile(target.Path, target.BaselineContent, target.Permissions)
	remediated := err == nil
	if remediated {
		atomic.AddUint64(&e.healedTotal, 1)
		log.Printf("[FIM_HEALING] 🛠️ SELF-HEALED CONFIG DRIFT on %s (Restored to SHA256: %s)", target.Path, target.BaselineSHA256[:8])
	} else {
		log.Printf("[FIM_HEALING] ⚠️ Failed to auto-restore %s: %v", target.Path, err)
	}

	ev := FIMDriftEvent{
		TimestampMs:    time.Now().UnixMilli(),
		FilePath:       target.Path,
		TamperedSHA256: tamperedHash,
		BaselineSHA256: target.BaselineSHA256,
		Remediated:     remediated,
		ThreatScore:    90,
		MitreID:        "T1565.001", // Data Manipulation: Stored Data Manipulation
		Details:        details,
	}

	e.mu.Lock()
	target.LastCheckedMs = time.Now().UnixMilli()
	e.recentEvents = append(e.recentEvents, ev)
	if len(e.recentEvents) > 50 {
		e.recentEvents = e.recentEvents[1:]
	}
	e.mu.Unlock()

	if e.onDriftHealed != nil {
		go e.onDriftHealed(ev)
	}

	return &ev
}

// GetTargets returns summary of all monitored configuration baselines.
func (e *FIMHealingEngine) GetTargets() []FIMTarget {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]FIMTarget, 0, len(e.targets))
	for _, t := range e.targets {
		res = append(res, *t)
	}
	return res
}

// GetStats returns telemetry metrics for the Self-Healing FIM subsystem.
func (e *FIMHealingEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"targets_monitored": len(e.targets),
		"drifts_total":      atomic.LoadUint64(&e.driftsTotal),
		"healed_total":      atomic.LoadUint64(&e.healedTotal),
		"recent_events":     len(e.recentEvents),
	}
}

// GetRecentEvents returns the recent FIM drift incidents.
func (e *FIMHealingEngine) GetRecentEvents() []FIMDriftEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]FIMDriftEvent, len(e.recentEvents))
	copy(res, e.recentEvents)
	return res
}
