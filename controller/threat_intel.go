package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatIntelEntry stores details of a threat intelligence match.
type ThreatIntelEntry struct {
	Indicator   string    `json:"indicator"`
	Category    string    `json:"category"` // TOR_EXIT_NODE, SCANNER_POOL, ABUSIVE_HOST, BOTNET_C2
	Confidence  int       `json:"confidence"`
	SourceFeed  string    `json:"source_feed"`
	Description string    `json:"description"`
	AddedAt     time.Time `json:"added_at"`
}

// ThreatIntelEngine provides high-performance in-memory lookup for curated IP blocklists and CIDRs.
type ThreatIntelEngine struct {
	mu           sync.RWMutex
	exactIPs     map[string]*ThreatIntelEntry
	subnetBlocks []*threatCIDRBlock
	totalHits    uint64
	feedSources  map[string]int
}

type threatCIDRBlock struct {
	ipNet *net.IPNet
	entry *ThreatIntelEntry
}

var (
	globalIntelEngine *ThreatIntelEngine
	intelOnce         sync.Once
)

// GetDefaultThreatIntel returns the singleton ThreatIntelEngine instance.
func GetDefaultThreatIntel() *ThreatIntelEngine {
	intelOnce.Do(func() {
		globalIntelEngine = NewThreatIntelEngine()
	})
	return globalIntelEngine
}

// NewThreatIntelEngine initializes the in-memory lookup structures with curated threat feeds.
func NewThreatIntelEngine() *ThreatIntelEngine {
	engine := &ThreatIntelEngine{
		exactIPs:     make(map[string]*ThreatIntelEntry),
		subnetBlocks: make([]*threatCIDRBlock, 0),
		feedSources:  make(map[string]int),
	}
	engine.loadCuratedFeeds()
	return engine
}

// loadCuratedFeeds initializes curated Tor exit nodes, scanner pools, and abusive CIDRs.
func (tie *ThreatIntelEngine) loadCuratedFeeds() {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	// 1. Curated Tor Exit Nodes Feed
	torExits := []string{
		"185.220.101.5",
		"185.220.101.6",
		"185.220.101.7",
		"185.220.101.8",
		"185.220.101.9",
		"185.220.101.10",
		"185.220.102.4",
		"185.220.102.5",
		"185.220.102.6",
		"185.220.102.7",
		"198.96.155.3",
		"198.98.56.136",
		"199.249.230.70",
		"199.249.230.71",
		"199.249.230.87",
		"199.249.230.88",
		"171.25.193.20",
		"171.25.193.25",
		"171.25.193.77",
		"176.10.99.200",
		"176.10.99.201",
		"176.10.99.202",
		"176.10.99.203",
		"176.10.99.204",
		"176.10.99.205",
		"185.246.188.66",
		"185.246.188.67",
		"185.246.188.68",
		"185.246.188.69",
		"185.246.188.70",
		"185.246.188.71",
	}

	for _, ip := range torExits {
		tie.exactIPs[ip] = &ThreatIntelEntry{
			Indicator:   ip,
			Category:    "TOR_EXIT_NODE",
			Confidence:  95,
			SourceFeed:  "Curated-TorProject-Exits",
			Description: "Active Tor Onion Router Exit Node (Anonymized Proxy)",
			AddedAt:     time.Now(),
		}
	}
	tie.feedSources["Curated-TorProject-Exits"] = len(torExits)

	// 2. Curated Global Scanner Pools (Censys, Shodan, Masscan abusive nodes)
	scannerPools := []string{
		"162.142.125.0/24", // Censys Scanner Pool
		"167.94.138.0/24",  // Censys Scanner Pool
		"167.94.145.0/24",  // Censys Scanner Pool
		"167.94.146.0/24",  // Censys Scanner Pool
		"167.248.133.0/24", // Censys Scanner Pool
		"198.20.69.0/24",   // Shodan Scanner Pool
		"198.20.70.0/24",   // Shodan Scanner Pool
		"198.20.87.0/24",   // Shodan Scanner Pool
		"198.20.99.0/24",   // Shodan Scanner Pool
		"209.222.82.0/24",  // Shodan Scanner Pool
		"66.240.205.34",    // Shodan Scanner Node
		"66.240.236.119",   // Shodan Scanner Node
		"71.6.135.131",     // Shodan Scanner Node
		"71.6.165.200",     // Shodan Scanner Node
		"71.6.167.142",     // Shodan Scanner Node
		"82.221.105.6",     // Shodan Scanner Node
		"82.221.105.7",     // Shodan Scanner Node
		"85.25.43.94",      // Shodan Scanner Node
		"85.25.103.50",     // Shodan Scanner Node
		"93.120.27.62",     // Shodan Scanner Node
		"94.102.49.190",    // Shodan Scanner Node
		"185.180.143.0/24", // Known Masscan / Mirai Spray subnet
		"194.26.29.0/24",   // High-Entropy Scanner CIDR
		"45.154.255.0/24",  // Bulletproof Scanning Range
		"45.143.200.0/24",  // Shadowserver Spray Range
	}

	for _, ind := range scannerPools {
		if strings.Contains(ind, "/") {
			if _, ipNet, err := net.ParseCIDR(ind); err == nil {
				tie.subnetBlocks = append(tie.subnetBlocks, &threatCIDRBlock{
					ipNet: ipNet,
					entry: &ThreatIntelEntry{
						Indicator:   ind,
						Category:    "SCANNER_POOL",
						Confidence:  90,
						SourceFeed:  "Curated-Scanner-Pools",
						Description: "Automated Internet-Wide Port Scanner / Probe Range",
						AddedAt:     time.Now(),
					},
				})
			}
		} else {
			tie.exactIPs[ind] = &ThreatIntelEntry{
				Indicator:   ind,
				Category:    "SCANNER_POOL",
				Confidence:  90,
				SourceFeed:  "Curated-Scanner-Pools",
				Description: "Automated Internet-Wide Port Scanner Node",
				AddedAt:     time.Now(),
			}
		}
	}
	tie.feedSources["Curated-Scanner-Pools"] = len(scannerPools)

	// 3. Curated Abusive Hosts & C2 Infrastructure
	abusiveHosts := []string{
		"194.165.16.0/22",  // Bulletproof Hosting / Malicious C2 Pool
		"193.142.146.0/24", // Darkgate / CobaltStrike C2 Range
		"45.33.32.156",     // Scanme Nmap host (sample)
		"185.220.103.5",    // Known C2 proxy
		"185.220.103.6",    // Known C2 proxy
		"194.26.29.112",    // Brute-force botnet node
		"194.26.29.113",    // Brute-force botnet node
		"91.240.118.172",   // Web Exploit Dropper
		"194.38.20.11",     // Reverse shell listener
		"194.38.20.12",     // Reverse shell listener
	}

	for _, ind := range abusiveHosts {
		if strings.Contains(ind, "/") {
			if _, ipNet, err := net.ParseCIDR(ind); err == nil {
				tie.subnetBlocks = append(tie.subnetBlocks, &threatCIDRBlock{
					ipNet: ipNet,
					entry: &ThreatIntelEntry{
						Indicator:   ind,
						Category:    "ABUSIVE_HOST",
						Confidence:  98,
						SourceFeed:  "Curated-Abuse-C2",
						Description: "Known Malicious Infrastructure / Botnet C2 / Exploit Dropper",
						AddedAt:     time.Now(),
					},
				})
			}
		} else {
			tie.exactIPs[ind] = &ThreatIntelEntry{
				Indicator:   ind,
				Category:    "ABUSIVE_HOST",
				Confidence:  98,
				SourceFeed:  "Curated-Abuse-C2",
				Description: "Known Malicious Infrastructure / Botnet C2 / Exploit Dropper",
				AddedAt:     time.Now(),
			}
		}
	}
	tie.feedSources["Curated-Abuse-C2"] = len(abusiveHosts)

	log.Printf("[THREAT_INTEL] Initialized in-memory threat feeds: %d exact IPs, %d CIDR blocks across %d feeds",
		len(tie.exactIPs), len(tie.subnetBlocks), len(tie.feedSources))
}

// MatchIP checks an incoming IP against the loaded Threat Intelligence feeds.
func (tie *ThreatIntelEngine) MatchIP(ipStr string) (*ThreatIntelEntry, bool) {
	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP == "" || isProtectedIP(cleanIP) {
		return nil, false
	}

	tie.mu.RLock()
	defer tie.mu.RUnlock()

	// 1. O(1) Fast-Path Exact Match
	if entry, found := tie.exactIPs[cleanIP]; found {
		atomic.AddUint64(&tie.totalHits, 1)
		return entry, true
	}

	// 2. Subnet / CIDR Range Match
	parsed := net.ParseIP(cleanIP)
	if parsed == nil {
		return nil, false
	}

	for _, block := range tie.subnetBlocks {
		if block.ipNet.Contains(parsed) {
			atomic.AddUint64(&tie.totalHits, 1)
			return block.entry, true
		}
	}

	return nil, false
}

// IngestFeedFile parses a flat list of IPs or CIDRs from a local file or custom feed.
func (tie *ThreatIntelEngine) IngestFeedFile(path, feedName, category string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	tie.mu.Lock()
	defer tie.mu.Unlock()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		indicator := parts[0]

		if isProtectedIP(indicator) {
			continue
		}

		if strings.Contains(indicator, "/") {
			if _, ipNet, err := net.ParseCIDR(indicator); err == nil {
				tie.subnetBlocks = append(tie.subnetBlocks, &threatCIDRBlock{
					ipNet: ipNet,
					entry: &ThreatIntelEntry{
						Indicator:   indicator,
						Category:    category,
						Confidence:  90,
						SourceFeed:  feedName,
						Description: fmt.Sprintf("Feed: %s [%s]", feedName, category),
						AddedAt:     time.Now(),
					},
				})
				count++
			}
		} else if net.ParseIP(indicator) != nil {
			tie.exactIPs[indicator] = &ThreatIntelEntry{
				Indicator:   indicator,
				Category:    category,
				Confidence:  90,
				SourceFeed:  feedName,
				Description: fmt.Sprintf("Feed: %s [%s]", feedName, category),
				AddedAt:     time.Now(),
			}
			count++
		}
	}

	tie.feedSources[feedName] = count
	log.Printf("[THREAT_INTEL] Ingested %d indicators from feed '%s'", count, feedName)
	return count, nil
}

// FetchRemoteFeed fetches and ingests an HTTP(S) threat intelligence feed.
func (tie *ThreatIntelEngine) FetchRemoteFeed(url, feedName, category string) (int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feed server returned status %d", resp.StatusCode)
	}

	tie.mu.Lock()
	defer tie.mu.Unlock()

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		indicator := parts[0]

		if isProtectedIP(indicator) {
			continue
		}

		if strings.Contains(indicator, "/") {
			if _, ipNet, err := net.ParseCIDR(indicator); err == nil {
				tie.subnetBlocks = append(tie.subnetBlocks, &threatCIDRBlock{
					ipNet: ipNet,
					entry: &ThreatIntelEntry{
						Indicator:   indicator,
						Category:    category,
						Confidence:  90,
						SourceFeed:  feedName,
						Description: fmt.Sprintf("Remote Feed: %s [%s]", feedName, category),
						AddedAt:     time.Now(),
					},
				})
				count++
			}
		} else if net.ParseIP(indicator) != nil {
			tie.exactIPs[indicator] = &ThreatIntelEntry{
				Indicator:   indicator,
				Category:    category,
				Confidence:  90,
				SourceFeed:  feedName,
				Description: fmt.Sprintf("Remote Feed: %s [%s]", feedName, category),
				AddedAt:     time.Now(),
			}
			count++
		}
	}

	tie.feedSources[feedName] = count
	log.Printf("[THREAT_INTEL] Downloaded & Ingested %d indicators from remote feed '%s'", count, feedName)
	return count, nil
}

// GetStats returns current in-memory threat intelligence statistics.
func (tie *ThreatIntelEngine) GetStats() map[string]interface{} {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	return map[string]interface{}{
		"exact_ips_count":   len(tie.exactIPs),
		"cidr_blocks_count": len(tie.subnetBlocks),
		"total_hits":        atomic.LoadUint64(&tie.totalHits),
		"feeds":             tie.feedSources,
	}
}
