package whitelist

import (
	"testing"
)

// MockStorage implements StorageProvider for testing.
type MockStorage struct {
	entries []Entry
	nextID  int64
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		entries: make([]Entry, 0),
		nextID:  1,
	}
}

func (m *MockStorage) GetAllWhitelistEntries() ([]Entry, error) {
	return m.entries, nil
}

func (m *MockStorage) AddWhitelistEntry(cidrOrIP, description, addedBy string, createdAtMs int64) (int64, error) {
	for _, e := range m.entries {
		if e.CIDROrIP == cidrOrIP {
			return e.ID, nil
		}
	}
	id := m.nextID
	m.nextID++
	m.entries = append(m.entries, Entry{
		ID:          id,
		CIDROrIP:    cidrOrIP,
		Description: description,
		AddedBy:     addedBy,
		CreatedAtMs: createdAtMs,
	})
	return id, nil
}

func (m *MockStorage) DeleteWhitelistEntry(id int64, cidrOrIP string) error {
	var remaining []Entry
	for _, e := range m.entries {
		if (id > 0 && e.ID == id) || (cidrOrIP != "" && e.CIDROrIP == cidrOrIP) {
			continue
		}
		remaining = append(remaining, e)
	}
	m.entries = remaining
	return nil
}

func TestMixedCIDRWhitelistMatching(t *testing.T) {
	mock := NewMockStorage()
	engine := NewEngine(mock)
	engine.SetStorage(mock)

	// Add subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.1.50/32
	testSubnets := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.1.50/32"}
	for _, s := range testSubnets {
		_, err := engine.AddEntry(s, "Test Subnet", "UNIT_TEST")
		if err != nil {
			t.Fatalf("Failed to add subnet %s: %v", s, err)
		}
	}

	testCases := []struct {
		ip       string
		expected bool
	}{
		// 10.0.0.0/8
		{"10.0.0.1", true},
		{"10.254.1.99", true},
		{"11.0.0.1", false},

		// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
		{"172.16.0.5", true},
		{"172.24.100.1", true},
		{"172.31.255.254", true},
		{"172.32.0.1", false},
		{"172.15.255.255", false},

		// 192.168.1.50/32
		{"192.168.1.50", true},
		{"192.168.1.51", false},

		// Auto-seeded loopback
		{"127.0.0.1", true},
		{"::1", true},

		// Public non-whitelisted IP
		{"203.0.113.42", false},
	}

	for _, tc := range testCases {
		res := engine.IsWhitelisted(tc.ip)
		if res != tc.expected {
			t.Errorf("IsWhitelisted(%s) = %v; expected %v", tc.ip, res, tc.expected)
		}
	}
}

func TestSelfHarmLoopbackDeletionPrevention(t *testing.T) {
	mock := NewMockStorage()
	engine := NewEngine(mock)
	engine.SetStorage(mock)

	// Attempting to delete loopback should be rejected
	err := engine.DeleteEntry(0, "127.0.0.1/32")
	if err == nil {
		t.Fatal("Expected error when attempting to delete 127.0.0.1/32, got nil")
	}

	err = engine.DeleteEntry(0, "::1/128")
	if err == nil {
		t.Fatal("Expected error when attempting to delete ::1/128, got nil")
	}

	// Loopback should remain whitelisted
	if !engine.IsWhitelisted("127.0.0.1") {
		t.Error("Loopback 127.0.0.1 must remain whitelisted")
	}
	if !engine.IsWhitelisted("::1") {
		t.Error("Loopback ::1 must remain whitelisted")
	}
}

func TestDynamicAddAndDelete(t *testing.T) {
	mock := NewMockStorage()
	engine := NewEngine(mock)
	engine.SetStorage(mock)

	testIP := "198.51.100.77"
	if engine.IsWhitelisted(testIP) {
		t.Fatalf("IP %s should not be whitelisted initially", testIP)
	}

	entry, err := engine.AddEntry(testIP, "Temp Office", "ADMIN")
	if err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	if !engine.IsWhitelisted(testIP) {
		t.Fatalf("IP %s must be whitelisted after addition", testIP)
	}

	// Delete by IP
	err = engine.DeleteEntry(entry.ID, entry.CIDROrIP)
	if err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}

	if engine.IsWhitelisted(testIP) {
		t.Fatalf("IP %s must no longer be whitelisted after deletion", testIP)
	}
}
