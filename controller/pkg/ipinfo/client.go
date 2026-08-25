package ipinfo

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultIPInfoToken is the fallback pre-configured token for live IPinfo.io lookups.
const DefaultIPInfoToken = "5d61b28f40a2d8"

// ASNInfo contains Autonomous System Number metadata from IPinfo.
type ASNInfo struct {
	ASN    string `json:"asn,omitempty"`
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	Route  string `json:"route,omitempty"`
	Type   string `json:"type,omitempty"` // "hosting", "isp", "business", "edu"
}

// CompanyInfo contains corporate ownership metadata.
type CompanyInfo struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	Type   string `json:"type,omitempty"`
}

// PrivacyInfo contains anonymization service flags.
type PrivacyInfo struct {
	VPN     bool   `json:"vpn,omitempty"`
	Proxy   bool   `json:"proxy,omitempty"`
	Tor     bool   `json:"tor,omitempty"`
	Relay   bool   `json:"relay,omitempty"`
	Hosting bool   `json:"hosting,omitempty"`
	Service string `json:"service,omitempty"`
}

// IPInfoResponse represents the enriched threat intelligence and geolocation record.
type IPInfoResponse struct {
	IP             string       `json:"ip"`
	Hostname       string       `json:"hostname,omitempty"`
	Anycast        bool         `json:"anycast,omitempty"`
	City           string       `json:"city,omitempty"`
	Region         string       `json:"region,omitempty"`
	Country        string       `json:"country,omitempty"`
	CountryName    string       `json:"country_name,omitempty"`
	Loc            string       `json:"loc,omitempty"` // "lat,lon"
	Org            string       `json:"org,omitempty"` // "AS215790 Limited Network LTD"
	Postal         string       `json:"postal,omitempty"`
	Timezone       string       `json:"timezone,omitempty"`
	ASN            *ASNInfo     `json:"asn,omitempty"`
	Company        *CompanyInfo `json:"company,omitempty"`
	Privacy        *PrivacyInfo `json:"privacy,omitempty"`
	Latitude       float64      `json:"latitude"`
	Longitude      float64      `json:"longitude"`
	FlagEmoji      string       `json:"flag_emoji"`
	IsHosting      bool         `json:"is_hosting"`
	IsVPN          bool         `json:"is_vpn"`
	IsProxy        bool         `json:"is_proxy"`
	IsTor          bool         `json:"is_tor"`
	IsRelay        bool         `json:"is_relay"`
	IsAnycast      bool         `json:"is_anycast"`
	Classification string       `json:"classification"` // "Hosting / Datacenter", "VPN / Proxy", "Tor Exit Node", "Residential / ISP"
	CachedAtMs     int64        `json:"cached_at_ms"`
	Source         string       `json:"source"` // "ipinfo_live", "lru_cache", "synthetic_fallback"
}

type cacheEntry struct {
	key       string
	value     *IPInfoResponse
	expiresAt time.Time
}

// LRUCache provides a thread-safe in-memory cache with capacity limits and TTL eviction.
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	evictList *list.List
}

// NewLRUCache creates an LRU cache with maximum items and TTL.
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	if capacity <= 0 {
		capacity = 10000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &LRUCache{
		capacity:  capacity,
		ttl:       ttl,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

// Get retrieves a valid, non-expired cache entry.
func (c *LRUCache) Get(key string) (*IPInfoResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, found := c.items[key]
	if !found {
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.removeElement(elem)
		return nil, false
	}

	c.evictList.MoveToFront(elem)
	return entry.value, true
}

// Set stores a new entry or updates an existing entry with TTL.
func (c *LRUCache) Set(key string, value *IPInfoResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if elem, found := c.items[key]; found {
		c.evictList.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = now.Add(c.ttl)
		return
	}

	if c.evictList.Len() >= c.capacity {
		c.evictOldest()
	}

	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: now.Add(c.ttl),
	}
	elem := c.evictList.PushFront(entry)
	c.items[key] = elem
}

func (c *LRUCache) evictOldest() {
	elem := c.evictList.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *LRUCache) removeElement(elem *list.Element) {
	c.evictList.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

// Len returns the current count of elements in the cache.
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.evictList.Len()
}

// Client coordinates live IPinfo lookups, rate limiting, and LRU cache management.
type Client struct {
	mu           sync.RWMutex
	token        string
	baseURL      string
	httpClient   *http.Client
	cache        *LRUCache
	asyncChan    chan string
	rateLimitExp time.Time
	onEnriched   func(resp *IPInfoResponse)
}

var (
	defaultClient *Client
	clientOnce    sync.Once
)

// GetDefaultClient returns the singleton IPinfo client.
func GetDefaultClient() *Client {
	clientOnce.Do(func() {
		token := os.Getenv("IPINFO_TOKEN")
		if token == "" {
			token = os.Getenv("COPSEC_IPINFO_TOKEN")
		}
		if token == "" {
			token = DefaultIPInfoToken
		}
		defaultClient = NewClient(token)
	})
	return defaultClient
}

// NewClient initializes the IPinfo intelligence client with a background worker pool.
func NewClient(token string) *Client {
	if token == "" {
		token = os.Getenv("IPINFO_TOKEN")
		if token == "" {
			token = os.Getenv("COPSEC_IPINFO_TOKEN")
		}
		if token == "" {
			token = DefaultIPInfoToken
		}
	}

	c := &Client{
		token:      strings.TrimSpace(token),
		baseURL:    "https://ipinfo.io",
		httpClient: &http.Client{Timeout: 5 * time.Second},
		cache:      NewLRUCache(10000, 24*time.Hour),
		asyncChan:  make(chan string, 2048),
	}

	// Start asynchronous background enrichment worker pool
	for i := 0; i < 4; i++ {
		go c.worker()
	}

	log.Printf("[INFO] IPinfo Threat Intelligence Client initialized (Token Configured: %v)", c.token != "")
	return c
}

// GetCached returns the cached IPInfoResponse if present and valid.
func (c *Client) GetCached(ip string) (*IPInfoResponse, bool) {
	cleanIP := cleanIPAddress(ip)
	if isPrivateOrExcluded(cleanIP) {
		return nil, false
	}
	return c.cache.Get(cleanIP)
}

// SetToken updates the IPinfo API token dynamically.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = strings.TrimSpace(token)
}

// SetBaseURL overrides the API endpoint (useful for mock testing).
func (c *Client) SetBaseURL(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = strings.TrimSuffix(baseURL, "/")
}

// SetOnEnriched registers a callback invoked when an asynchronous lookup completes.
func (c *Client) SetOnEnriched(cb func(resp *IPInfoResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEnriched = cb
}

func (c *Client) worker() {
	for ip := range c.asyncChan {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Lookup(ctx, ip)
		cancel()
		if err == nil && resp != nil {
			c.mu.RLock()
			cb := c.onEnriched
			c.mu.RUnlock()
			if cb != nil {
				cb(resp)
			}
		}
	}
}

// LookupAsync enqueues an IP for non-blocking asynchronous enrichment.
func (c *Client) LookupAsync(ip string) {
	cleanIP := cleanIPAddress(ip)
	if isPrivateOrExcluded(cleanIP) {
		return
	}

	// If already in cache, skip enqueueing
	if _, cached := c.cache.Get(cleanIP); cached {
		return
	}

	select {
	case c.asyncChan <- cleanIP:
	default:
		// Queue full, drop non-critical background task
	}
}

// Lookup queries IPinfo synchronously or returns cached metadata.
func (c *Client) Lookup(ctx context.Context, ipStr string) (*IPInfoResponse, error) {
	cleanIP := cleanIPAddress(ipStr)
	if cleanIP == "" || cleanIP == "-" {
		return nil, fmt.Errorf("empty IP address")
	}

	// 1. Check if Private / RFC1918 / Loopback / CGNAT
	if isPrivateOrExcluded(cleanIP) {
		return &IPInfoResponse{
			IP:             cleanIP,
			Country:        "LOC",
			City:           "Internal",
			Region:         "Private Subnet",
			Org:            "RFC1918 Local Host",
			FlagEmoji:      "🏠",
			Classification: "Local / Private Network",
			CachedAtMs:     time.Now().UnixMilli(),
			Source:         "private_network",
		}, nil
	}

	// 2. Check LRU Cache
	if cached, ok := c.cache.Get(cleanIP); ok {
		cached.Source = "lru_cache"
		return cached, nil
	}

	// 3. Check rate-limit backoff
	c.mu.RLock()
	inBackoff := time.Now().Before(c.rateLimitExp)
	token := c.token
	baseURL := c.baseURL
	c.mu.RUnlock()

	if inBackoff {
		return nil, fmt.Errorf("ipinfo api in rate-limit backoff cooldown")
	}

	// 4. Perform live HTTP lookup
	url := fmt.Sprintf("%s/%s/json", baseURL, cleanIP)
	if token != "" {
		url += fmt.Sprintf("?token=%s", token)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CoPSeC-SOC-Engine/2.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		// Rate limit reached, set 5-minute backoff
		c.mu.Lock()
		c.rateLimitExp = time.Now().Add(5 * time.Minute)
		c.mu.Unlock()
		log.Printf("[WARN] IPinfo.io rate limit reached (HTTP 429). Entering 5-minute cooldown.")
		return nil, fmt.Errorf("ipinfo rate limit exceeded (HTTP 429)")
	}

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ipinfo api status %d: %s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ipinfoResp IPInfoResponse
	if err := json.Unmarshal(body, &ipinfoResp); err != nil {
		return nil, fmt.Errorf("failed to parse ipinfo response: %v", err)
	}

	// Parse coordinates from "loc": "lat,lon"
	if ipinfoResp.Loc != "" {
		parts := strings.Split(ipinfoResp.Loc, ",")
		if len(parts) == 2 {
			lat, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lon, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			ipinfoResp.Latitude = lat
			ipinfoResp.Longitude = lon
		}
	}

	// Set flag emoji & country name
	ipinfoResp.FlagEmoji = countryCodeToEmoji(ipinfoResp.Country)
	ipinfoResp.CountryName = CountryCodeToName(ipinfoResp.Country)
	ipinfoResp.CachedAtMs = time.Now().UnixMilli()
	ipinfoResp.Source = "ipinfo_live"

	// Derive Hosting / VPN / Proxy / Classification flags
	c.deriveSecurityContext(&ipinfoResp)

	// Save to LRU cache
	c.cache.Set(cleanIP, &ipinfoResp)

	return &ipinfoResp, nil
}

func (c *Client) deriveSecurityContext(resp *IPInfoResponse) {
	orgLower := strings.ToLower(resp.Org)
	hostLower := strings.ToLower(resp.Hostname)

	if resp.CountryName == "" {
		resp.CountryName = CountryCodeToName(resp.Country)
	}

	// Check Privacy object if available (IPinfo paid plans)
	if resp.Privacy != nil {
		resp.IsVPN = resp.Privacy.VPN
		resp.IsProxy = resp.Privacy.Proxy
		resp.IsTor = resp.Privacy.Tor
		resp.IsRelay = resp.Privacy.Relay
		resp.IsHosting = resp.Privacy.Hosting
	}

	// Check ASN object
	if resp.ASN != nil {
		if resp.ASN.Type == "hosting" {
			resp.IsHosting = true
		}
	}

	// Heuristic datacenter / hosting classification from org name
	if strings.Contains(orgLower, "amazon") || strings.Contains(orgLower, "aws") ||
		strings.Contains(orgLower, "digitalocean") || strings.Contains(orgLower, "hetzner") ||
		strings.Contains(orgLower, "ovh") || strings.Contains(orgLower, "linode") ||
		strings.Contains(orgLower, "akamai") || strings.Contains(orgLower, "google cloud") ||
		strings.Contains(orgLower, "microsoft") || strings.Contains(orgLower, "azure") ||
		strings.Contains(orgLower, "vultr") || strings.Contains(orgLower, "cloudflare") ||
		strings.Contains(orgLower, "leaseweb") || strings.Contains(orgLower, "scaleway") ||
		strings.Contains(orgLower, "alibaba") || strings.Contains(orgLower, "oracle") ||
		strings.Contains(orgLower, "hosting") || strings.Contains(orgLower, "datacenter") ||
		strings.Contains(orgLower, "serverius") || strings.Contains(orgLower, "choopa") ||
		strings.Contains(orgLower, "limited network") || strings.Contains(orgLower, "m247") ||
		strings.Contains(orgLower, "hostkey") || strings.Contains(orgLower, "contabo") ||
		strings.Contains(orgLower, "worldstream") || strings.Contains(orgLower, "cogent") {
		resp.IsHosting = true
	}

	// Check Tor / Proxy indicators in hostname
	if strings.Contains(hostLower, "tor-exit") || strings.Contains(hostLower, "tor.relay") ||
		strings.Contains(orgLower, "tor exit") || strings.Contains(hostLower, "vpn") ||
		strings.Contains(orgLower, "vpn") || strings.Contains(hostLower, "proxy") {
		if strings.Contains(hostLower, "tor-exit") || strings.Contains(orgLower, "tor exit") {
			resp.IsTor = true
		}
		resp.IsProxy = true
	}

	// Determine final analyst classification badge
	if resp.IsTor {
		resp.Classification = "Tor Exit Node"
	} else if resp.IsVPN {
		resp.Classification = "VPN Gateway"
	} else if resp.IsProxy {
		resp.Classification = "Anonymizing Proxy"
	} else if resp.IsHosting {
		resp.Classification = "Hosting / VPS / Datacenter"
	} else if resp.Company != nil && resp.Company.Type == "business" {
		resp.Classification = "Corporate / Business Network"
	} else {
		resp.Classification = "Residential / Consumer ISP"
	}
}

func cleanIPAddress(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")
	if idx := strings.Index(ipStr, "/"); idx != -1 {
		ipStr = ipStr[:idx]
	}
	ipStr = strings.TrimSpace(ipStr)
	if parsed := net.ParseIP(ipStr); parsed != nil {
		return parsed.String()
	}
	return ipStr
}

func isPrivateOrExcluded(ipStr string) bool {
	if ipStr == "" || ipStr == "-" || ipStr == "127.0.0.1" || ipStr == "local" || ipStr == "localhost" || ipStr == "::1" {
		return true
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return true
	}

	// CGNAT 100.64.0.0/10
	ip4 := parsed.To4()
	if ip4 != nil && ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
		return true
	}

	return false
}

func countryCodeToEmoji(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return "🌐"
	}
	if code == "LO" || code == "LAN" || code == "PRIV" || code == "LOC" {
		return "🏠"
	}
	if code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "🌐"
	}
	r1 := rune(code[0]-'A') + 0x1F1E6
	r2 := rune(code[1]-'A') + 0x1F1E6
	return string([]rune{r1, r2})
}

// CountryCodeToName maps ISO 3166-1 alpha-2 codes to clean English country names.
func CountryCodeToName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	names := map[string]string{
		"NL": "The Netherlands",
		"DE": "Germany",
		"US": "United States",
		"GB": "United Kingdom",
		"FR": "France",
		"TR": "Turkey",
		"RU": "Russian Federation",
		"CN": "China",
		"IN": "India",
		"BR": "Brazil",
		"JP": "Japan",
		"SG": "Singapore",
		"CA": "Canada",
		"AU": "Australia",
		"ES": "Spain",
		"IT": "Italy",
		"PL": "Poland",
		"UA": "Ukraine",
		"SE": "Sweden",
		"CH": "Switzerland",
		"RO": "Romania",
		"BG": "Bulgaria",
		"IR": "Iran",
		"KP": "North Korea",
		"VN": "Vietnam",
		"ID": "Indonesia",
		"KR": "South Korea",
		"HK": "Hong Kong",
		"TW": "Taiwan",
		"FI": "Finland",
		"NO": "Norway",
		"DK": "Denmark",
		"BE": "Belgium",
		"AT": "Austria",
		"CZ": "Czech Republic",
		"IL": "Israel",
		"ZA": "South Africa",
		"MX": "Mexico",
		"AR": "Argentina",
		"CL": "Chile",
		"CO": "Colombia",
		"NZ": "New Zealand",
		"LOC": "Local Host",
		"LAN": "Local Network",
	}
	if name, ok := names[code]; ok {
		return name
	}
	if len(code) == 2 {
		return code
	}
	return "Unknown Origin"
}
