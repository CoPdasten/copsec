package rules

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultSigmaHQTarballURL is the official upstream SigmaHQ repository archive endpoint.
	DefaultSigmaHQTarballURL = "https://api.github.com/repos/SigmaHQ/sigma/tarball/master"

	// DefaultStorageDir is the system directory for cached rules.
	DefaultStorageDir = "/var/lib/copsec/rules"
)

// Allowed core directory patterns to stream and filter strictly.
var CoreDirectories = []string{
	"rules/linux/process_creation/",
	"rules/web/web_servers/",
	"rules/linux/builtin/auth/",
	"rules/network/",
}

// SyncStatus holds live sync pipeline metrics.
type SyncStatus struct {
	LastSyncTime time.Time `json:"last_sync_time"`
	SyncedCount  int       `json:"synced_count"`
	TotalRules   int       `json:"total_rules"`
	StorageDir   string    `json:"storage_dir"`
	Status       string    `json:"status"` // IDLE, SYNCING, SUCCESS, ERROR
	LastError    string    `json:"last_error,omitempty"`
}

// Syncer coordinates streaming, filtering, storing, and compiling SigmaHQ rules.
type Syncer struct {
	mu         sync.RWMutex
	client     *http.Client
	tarballURL string
	storageDir string
	matcher    *Matcher
	status     SyncStatus
}

var (
	defaultSyncer *Syncer
	syncerOnce    sync.Once
)

// GetDefaultSyncer returns the singleton Syncer instance.
func GetDefaultSyncer() *Syncer {
	syncerOnce.Do(func() {
		defaultSyncer = NewSyncer(DefaultSigmaHQTarballURL, DefaultStorageDir, GetDefaultMatcher())
	})
	return defaultSyncer
}

// NewSyncer creates a new Syncer instance.
func NewSyncer(tarballURL, storageDir string, matcher *Matcher) *Syncer {
	if tarballURL == "" {
		tarballURL = DefaultSigmaHQTarballURL
	}
	if storageDir == "" {
		storageDir = DefaultStorageDir
	}
	if matcher == nil {
		matcher = GetDefaultMatcher()
	}

	// Validate / initialize storage directory with fallback
	resolvedDir := resolveStorageDirectory(storageDir)

	s := &Syncer{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		tarballURL: tarballURL,
		storageDir: resolvedDir,
		matcher:    matcher,
		status: SyncStatus{
			StorageDir: resolvedDir,
			Status:     "IDLE",
		},
	}

	// Load previously cached disk rules on startup
	s.loadRulesFromDisk()

	return s
}

func resolveStorageDirectory(preferredDir string) string {
	if err := os.MkdirAll(preferredDir, 0750); err == nil {
		testFile := filepath.Join(preferredDir, ".perm_test")
		if err := os.WriteFile(testFile, []byte("ok"), 0640); err == nil {
			_ = os.Remove(testFile)
			return preferredDir
		}
	}

	// Fallback 1: Local data/rules
	localDir := "./data/rules"
	if err := os.MkdirAll(localDir, 0750); err == nil {
		return localDir
	}

	// Fallback 2: System temporary directory
	tempDir := filepath.Join(os.TempDir(), "copsec", "rules")
	_ = os.MkdirAll(tempDir, 0750)
	return tempDir
}

// GetStatus returns a snapshot of current sync metrics.
func (s *Syncer) GetStatus() SyncStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.status
	if s.matcher != nil {
		st.TotalRules = len(s.matcher.ListRules())
	}
	return st
}

// IsCoreDirectory checks whether a path belongs to one of the 4 designated core directories.
func IsCoreDirectory(path string) bool {
	normalized := strings.ReplaceAll(path, "\\", "/")
	for _, core := range CoreDirectories {
		if strings.Contains(normalized, core) {
			return true
		}
	}
	return false
}

// Sync pulls the latest rules tarball, filters the 4 core directories, and updates the in-memory cache.
func (s *Syncer) Sync(ctx context.Context, customURL ...string) (*SyncStatus, error) {
	s.mu.Lock()
	if s.status.Status == "SYNCING" {
		s.mu.Unlock()
		return nil, fmt.Errorf("sync is already in progress")
	}
	s.status.Status = "SYNCING"
	s.status.LastError = ""
	s.mu.Unlock()

	urlToFetch := s.tarballURL
	if len(customURL) > 0 && customURL[0] != "" {
		urlToFetch = customURL[0]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlToFetch, nil)
	if err != nil {
		s.recordError(fmt.Sprintf("failed to create request: %v", err))
		return nil, err
	}
	req.Header.Set("User-Agent", "CoPSeC-Controller/2.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordError(fmt.Sprintf("http request failed: %v", err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("github api returned status %d", resp.StatusCode)
		s.recordError(errMsg)
		return nil, fmt.Errorf("%s", errMsg)
	}

	return s.ProcessTarballStream(resp.Body)
}

// ProcessTarballStream unpacks, filters, saves, and compiles rules from a gzipped tar stream.
func (s *Syncer) ProcessTarballStream(r io.Reader) (*SyncStatus, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		s.recordError(fmt.Sprintf("gzip decompression failed: %v", err))
		return nil, err
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)
	syncedCount := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.recordError(fmt.Sprintf("tar read error: %v", err))
			return nil, err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		fileName := header.Name
		if !strings.HasSuffix(fileName, ".yml") && !strings.HasSuffix(fileName, ".yaml") {
			continue
		}

		// Strictly filter for the 4 core directories
		if !IsCoreDirectory(fileName) {
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			continue
		}

		// Compile rule
		rule, err := ParseSigmaRule(string(content), "[SIGMAHQ]")
		if err != nil {
			continue
		}

		// Persist YAML file to storage directory with strict Zip-Slip / Path-Traversal protection
		cleanFileName := filepath.Clean(filepath.ToSlash(fileName))
		if strings.Contains(cleanFileName, "..") || strings.HasPrefix(cleanFileName, "/") || strings.HasPrefix(cleanFileName, "\\") {
			continue
		}
		targetPath := filepath.Clean(filepath.Join(s.storageDir, cleanFileName))
		if !strings.HasPrefix(targetPath, filepath.Clean(s.storageDir)+string(filepath.Separator)) {
			continue
		}
		destSubDir := filepath.Dir(targetPath)
		_ = os.MkdirAll(destSubDir, 0750)
		_ = os.WriteFile(targetPath, content, 0640)
		rule.FilePath = targetPath

		// Register into in-memory Matcher
		s.matcher.AddRule(rule)
		syncedCount++
	}

	s.mu.Lock()
	s.status.Status = "SUCCESS"
	s.status.LastSyncTime = time.Now()
	s.status.SyncedCount = syncedCount
	s.status.TotalRules = len(s.matcher.ListRules())
	statusCopy := s.status
	s.mu.Unlock()

	log.Printf("[SIGMAHQ_SYNC] Ingested and compiled %d SigmaHQ rules from 4 core directories (Total in-memory: %d)", syncedCount, statusCopy.TotalRules)
	return &statusCopy, nil
}

func (s *Syncer) loadRulesFromDisk() {
	if s.storageDir == "" {
		return
	}

	_ = filepath.Walk(s.storageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rule, err := ParseSigmaRule(string(data), "[SIGMAHQ]")
		if err == nil {
			rule.FilePath = path
			s.matcher.AddRule(rule)
		}
		return nil
	})
}

func (s *Syncer) recordError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Status = "ERROR"
	s.status.LastError = msg
	log.Printf("[SIGMAHQ_SYNC_ERROR] %s", msg)
}
