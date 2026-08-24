package geoip

import (
	"testing"
)

func TestGeoIPLookup(t *testing.T) {
	engine := GetDefaultEngine()

	tests := []struct {
		ip          string
		expectedCC  string
		expectPriv  bool
	}{
		{"127.0.0.1", "LOC", true},
		{"::1", "LOC", true},
		{"10.0.0.5", "LOC", true},
		{"192.168.1.100", "LOC", true},
		{"172.16.0.1", "LOC", true},
		{"198.51.100.45", "US", false},
		{"203.0.113.88", "DE", false},
		{"176.236.10.20", "TR", false},
		{"42.1.2.3", "CN", false},
		{"88.198.50.60", "DE", false},
	}

	for _, tt := range tests {
		loc := engine.Lookup(tt.ip)
		if loc == nil {
			t.Fatalf("Lookup for %s returned nil", tt.ip)
		}
		if loc.CountryCode != tt.expectedCC {
			t.Errorf("Lookup(%s) CountryCode = %s, expected %s", tt.ip, loc.CountryCode, tt.expectedCC)
		}
		if loc.IsPrivate != tt.expectPriv {
			t.Errorf("Lookup(%s) IsPrivate = %v, expected %v", tt.ip, loc.IsPrivate, tt.expectPriv)
		}
		if loc.FlagEmoji == "" {
			t.Errorf("Lookup(%s) FlagEmoji is empty", tt.ip)
		}
	}
}

func TestAttackOriginDensity(t *testing.T) {
	engine := NewEngine()
	engine.Lookup("198.51.100.1") // US
	engine.Lookup("198.51.100.2") // US
	engine.Lookup("203.0.113.1")  // DE

	stats := engine.GetAttackOriginDensity(5)
	if len(stats) == 0 {
		t.Fatalf("Expected attack origin stats, got 0")
	}

	if stats[0].CountryCode != "US" {
		t.Errorf("Expected top attacking country US, got %s", stats[0].CountryCode)
	}
	if stats[0].AttackCount != 2 {
		t.Errorf("Expected US attack count 2, got %d", stats[0].AttackCount)
	}
}
