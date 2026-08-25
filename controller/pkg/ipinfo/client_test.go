package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLRUCacheOperations(t *testing.T) {
	cache := NewLRUCache(2, 500*time.Millisecond)

	resp1 := &IPInfoResponse{IP: "1.1.1.1", Org: "AS13335 Cloudflare"}
	resp2 := &IPInfoResponse{IP: "8.8.8.8", Org: "AS15169 Google"}
	resp3 := &IPInfoResponse{IP: "9.9.9.9", Org: "AS19281 Quad9"}

	// 1. Insert 2 entries
	cache.Set("1.1.1.1", resp1)
	cache.Set("8.8.8.8", resp2)

	if cache.Len() != 2 {
		t.Fatalf("Expected cache len 2, got %d", cache.Len())
	}

	// 2. Access 1.1.1.1 to make it most recently used
	val, ok := cache.Get("1.1.1.1")
	if !ok || val.IP != "1.1.1.1" {
		t.Fatalf("Expected 1.1.1.1 in cache")
	}

	// 3. Insert 3rd entry -> should evict 8.8.8.8 (least recently used)
	cache.Set("9.9.9.9", resp3)

	if _, ok := cache.Get("8.8.8.8"); ok {
		t.Errorf("Expected 8.8.8.8 to be evicted")
	}
	if _, ok := cache.Get("1.1.1.1"); !ok {
		t.Errorf("Expected 1.1.1.1 to still be present")
	}

	// 4. Test TTL expiration
	time.Sleep(600 * time.Millisecond)
	if _, ok := cache.Get("1.1.1.1"); ok {
		t.Errorf("Expected 1.1.1.1 to expire after TTL")
	}
}

func TestPrivateAndExcludedIPs(t *testing.T) {
	client := NewClient("")

	// Private, loopback, CGNAT
	ips := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.10", "100.64.0.1", "local", "-", ""}
	for _, ip := range ips {
		resp, err := client.Lookup(context.Background(), ip)
		if ip == "" || ip == "-" {
			if err == nil {
				t.Errorf("Expected error for empty IP, got nil")
			}
			continue
		}
		if err != nil {
			t.Fatalf("Lookup failed for private IP %s: %v", ip, err)
		}
		if resp.Country != "LOC" || resp.Source != "private_network" {
			t.Errorf("Expected private classification for %s, got %+v", ip, resp)
		}
	}
}

func TestMockLiveIPInfoLookup(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"ip": "198.51.100.44",
			"hostname": "ec2-198-51-100-44.compute-1.amazonaws.com",
			"anycast": false,
			"city": "Ashburn",
			"region": "Virginia",
			"country": "US",
			"loc": "39.0438,-77.4874",
			"org": "AS16509 Amazon.com, Inc.",
			"postal": "20147",
			"timezone": "America/New_York"
		}`))
	}))
	defer mockServer.Close()

	client := NewClient("mock-token")
	client.SetBaseURL(mockServer.URL)

	resp, err := client.Lookup(context.Background(), "198.51.100.44:443")
	if err != nil || resp == nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if resp.City != "Ashburn" || resp.Country != "US" {
		t.Errorf("Expected Ashburn, US, got %s, %s", resp.City, resp.Country)
	}
	if resp.Latitude != 39.0438 || resp.Longitude != -77.4874 {
		t.Errorf("Expected coordinates 39.0438, -77.4874, got %f, %f", resp.Latitude, resp.Longitude)
	}
	if !resp.IsHosting {
		t.Errorf("Expected Amazon AWS to be identified as Hosting/Datacenter")
	}
	if resp.Classification != "Hosting / VPS / Datacenter" {
		t.Errorf("Expected classification Hosting/VPS/Datacenter, got %s", resp.Classification)
	}

	// Verify second lookup uses cache
	cached, err := client.Lookup(context.Background(), "198.51.100.44")
	if err != nil || cached.Source != "lru_cache" {
		t.Errorf("Expected second lookup to hit LRU cache")
	}
}

func TestRateLimit429Backoff(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "rate limit exceeded"}`))
	}))
	defer mockServer.Close()

	client := NewClient("")
	client.SetBaseURL(mockServer.URL)

	_, err := client.Lookup(context.Background(), "203.0.113.88")
	if err == nil {
		t.Fatalf("Expected error on HTTP 429 rate limit")
	}

	// Immediate next query should fail fast due to backoff
	_, err2 := client.Lookup(context.Background(), "203.0.113.89")
	if err2 == nil {
		t.Fatalf("Expected immediate fail due to active rate-limit cooldown")
	}
}

func TestAsyncLookupWorker(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"ip": "203.0.113.50",
			"city": "Frankfurt",
			"region": "Hesse",
			"country": "DE",
			"loc": "50.1109,8.6821",
			"org": "AS24940 Hetzner Online GmbH"
		}`))
	}))
	defer mockServer.Close()

	client := NewClient("")
	client.SetBaseURL(mockServer.URL)

	enrichedChan := make(chan *IPInfoResponse, 1)
	client.SetOnEnriched(func(resp *IPInfoResponse) {
		enrichedChan <- resp
	})

	client.LookupAsync("203.0.113.50")

	select {
	case resp := <-enrichedChan:
		if resp.IP != "203.0.113.50" || resp.Country != "DE" {
			t.Errorf("Async lookup returned unexpected data: %+v", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for async enrichment")
	}
}

func TestLiveIPInfoNetherlandsKerkradeMapping(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"ip": "45.154.255.88",
			"city": "Kerkrade",
			"region": "Limburg",
			"country": "NL",
			"loc": "50.8658,6.0625",
			"org": "AS215790 Limited Network LTD",
			"postal": "6461",
			"timezone": "Europe/Amsterdam"
		}`))
	}))
	defer mockServer.Close()

	client := NewClient("5d61b28f40a2d8")
	client.SetBaseURL(mockServer.URL)

	resp, err := client.Lookup(context.Background(), "45.154.255.88")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if resp.Country != "NL" || resp.CountryName != "The Netherlands" {
		t.Errorf("Expected NL / The Netherlands, got %s / %s", resp.Country, resp.CountryName)
	}
	if resp.City != "Kerkrade" || resp.Region != "Limburg" {
		t.Errorf("Expected Kerkrade / Limburg, got %s / %s", resp.City, resp.Region)
	}
	if resp.Org != "AS215790 Limited Network LTD" {
		t.Errorf("Expected AS215790 Limited Network LTD, got %s", resp.Org)
	}
	if resp.Latitude != 50.8658 || resp.Longitude != 6.0625 {
		t.Errorf("Expected coords 50.8658, 6.0625, got %f, %f", resp.Latitude, resp.Longitude)
	}
	if !resp.IsHosting {
		t.Errorf("Expected Limited Network to be flagged as Hosting")
	}
	if resp.FlagEmoji != "🇳🇱" {
		t.Errorf("Expected flag 🇳🇱, got %s", resp.FlagEmoji)
	}
}

func TestIPv6IPInfoLookup(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"ip": "2a01:4f8:c010:d56::1",
			"city": "Dunkirk",
			"region": "Hauts-de-France",
			"country": "FR",
			"loc": "51.0343,2.3768",
			"org": "AS24940 Hetzner Online GmbH",
			"postal": "59140",
			"timezone": "Europe/Paris"
		}`))
	}))
	defer mockServer.Close()

	client := NewClient("5d61b28f40a2d8")
	client.SetBaseURL(mockServer.URL)

	// Test IPv6 with port and brackets
	resp, err := client.Lookup(context.Background(), "[2a01:4f8:c010:d56::1]:443")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if resp.City != "Dunkirk" || resp.Region != "Hauts-de-France" || resp.Postal != "59140" {
		t.Errorf("Expected Dunkirk, Hauts-de-France, 59140, got %s, %s, %s", resp.City, resp.Region, resp.Postal)
	}
	if resp.Country != "FR" || resp.CountryName != "France" {
		t.Errorf("Expected France, got %s / %s", resp.Country, resp.CountryName)
	}
	if !resp.IsHosting {
		t.Errorf("Expected Hetzner IPv6 to be identified as Hosting")
	}
}
