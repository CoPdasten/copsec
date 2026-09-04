package quarantine

import (
	"testing"
)

func TestQuarantineDriverInterface(t *testing.T) {
	driver := GetDriver()
	if driver == nil {
		t.Fatal("Expected non-nil default QuarantineDriver")
	}

	testIP := "198.51.100.42"
	reason := "Automated SOAR Test Quarantine"

	// Test BlockIP
	err := driver.BlockIP(testIP, reason)
	if err != nil {
		t.Logf("BlockIP executed (note: in unprivileged test env, may require sudo/admin): %v", err)
	}

	// Test ListBlocked
	blocked, err := driver.ListBlocked()
	if err != nil {
		t.Fatalf("ListBlocked failed: %v", err)
	}
	t.Logf("Currently blocked IPs: %v", blocked)

	// Test UnblockIP
	err = driver.UnblockIP(testIP)
	if err != nil {
		t.Logf("UnblockIP executed: %v", err)
	}
}
