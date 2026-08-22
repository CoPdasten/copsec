package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	copsecproto "github.com/copsec/collector/proto"
)

// LogEntry encapsulates normalized log record information across sources.
type LogEntry struct {
	Source    string `json:"source"`    // "nginx", "ssh", "syslog"
	Line      string `json:"line"`      // Raw line text
	Timestamp int64  `json:"timestamp"` // Unix timestamp in milliseconds
}

// LogSourceConfig defines a log file target to be watched.
type LogSourceConfig struct {
	Source string
	Path   string
}

// MultiLogCollector coordinates concurrent log tailers and streams entries to a central channel.
type MultiLogCollector struct {
	sources       []LogSourceConfig
	offsetManager *OffsetManager
	filter        *PreRoutingFilter
	logChan       chan LogEntry
	tailers       []*Tailer
	client        *ControllerClient

	// Metrics
	totalLinesRead    uint64
	totalLinesDropped uint64
	totalLinesPassed  uint64
}

// NewMultiLogCollector creates a new MultiLogCollector.
func NewMultiLogCollector(sources []LogSourceConfig, offsetFilePath, whitelistPath string, client *ControllerClient) *MultiLogCollector {
	om := NewOffsetManager(offsetFilePath)
	filter := NewPreRoutingFilter(whitelistPath)
	logChan := make(chan LogEntry, 1024)

	var tailers []*Tailer
	for _, src := range sources {
		t := NewTailer(src.Source, src.Path, om, logChan)
		tailers = append(tailers, t)
	}

	return &MultiLogCollector{
		sources:       sources,
		offsetManager: om,
		filter:        filter,
		logChan:       logChan,
		tailers:       tailers,
		client:        client,
	}
}

// Start launches all source tailers and the filtered consumer pipeline.
func (c *MultiLogCollector) Start(ctx context.Context) {
	var wg sync.WaitGroup

	// Start Controller Client background workers if configured
	if c.client != nil {
		wg.Add(1)
		go c.client.Start(ctx, &wg)
	}

	// Launch individual Tailer goroutines per log source
	for _, t := range c.tailers {
		wg.Add(1)
		go t.Start(ctx, &wg)
	}

	// Launch central consumer / pre-routing filter worker
	wg.Add(1)
	go c.runPipeline(ctx, &wg)

	log.Printf("[INFO] Multi-Log Collector active. Monitoring %d sources (Buffer: 1024).", len(c.tailers))
	wg.Wait()

	// Final flush on exit
	_ = c.offsetManager.Flush()
	log.Printf("[INFO] Multi-Log Collector stopped. Stats: Read=%d, Dropped=%d, Passed=%d",
		atomic.LoadUint64(&c.totalLinesRead),
		atomic.LoadUint64(&c.totalLinesDropped),
		atomic.LoadUint64(&c.totalLinesPassed))
}

// runPipeline consumes from logChan, applies Phase 1 Fast-Path filtering, and dispatches valid entries.
func (c *MultiLogCollector) runPipeline(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC_RECOVER] Collector pipeline recovered: %v", r)
		}
	}()

	metricsTicker := time.NewTicker(30 * time.Second)
	defer metricsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-metricsTicker.C:
			log.Printf("[METRICS] Processed: Read=%d | Dropped(Fast-Path)=%d | Passed=%d",
				atomic.LoadUint64(&c.totalLinesRead),
				atomic.LoadUint64(&c.totalLinesDropped),
				atomic.LoadUint64(&c.totalLinesPassed))

		case entry, ok := <-c.logChan:
			if !ok {
				return
			}
			atomic.AddUint64(&c.totalLinesRead, 1)

			// Phase 1 Fast-Path Short-Circuit Filter
			drop, _ := c.filter.ShouldDrop(entry)
			if drop {
				atomic.AddUint64(&c.totalLinesDropped, 1)
				continue
			}

			atomic.AddUint64(&c.totalLinesPassed, 1)
			c.dispatch(entry)
		}
	}
}

// dispatch handles the passed candidate suspicious log entry and forwards to Controller gRPC Client.
func (c *MultiLogCollector) dispatch(entry LogEntry) {
	ip := ExtractIP(entry.Line)
	var clientIP string
	if ip != nil {
		clientIP = ip.String()
	}

	statusCode := int32(ExtractHTTPStatus(entry.Line))

	event := &copsecproto.LogEvent{
		Source:      entry.Source,
		RawLine:     entry.Line,
		ClientIp:    clientIP,
		StatusCode:  statusCode,
		TimestampMs: entry.Timestamp,
	}

	if c.client != nil {
		c.client.Submit(event)
	}
}

// GetFilter returns the PreRoutingFilter instance.
func (c *MultiLogCollector) GetFilter() *PreRoutingFilter {
	return c.filter
}
