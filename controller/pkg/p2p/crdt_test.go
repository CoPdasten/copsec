package p2p

import (
	"testing"
	"time"
)

func TestCRDTSwarmJailLWWConvergence(t *testing.T) {
	var localBans []CRDTBanEntry
	jailA := NewCRDTSwarmJail("node-A", func(entry CRDTBanEntry) {
		localBans = append(localBans, entry)
	})
	jailB := NewCRDTSwarmJail("node-B", nil)

	// 1. Node A adds Ban
	added := jailA.Add(CRDTBanEntry{
		TargetIP:     "198.51.100.99",
		ThreatScore:  90,
		TTLSeconds:   3600,
		OriginNodeID: "node-A",
	})
	if !added {
		t.Fatal("Expected Add to succeed on Node A")
	}

	if jailA.Count() != 1 {
		t.Fatalf("Expected 1 active ban in Node A, got %d", jailA.Count())
	}

	// 2. Node B merges Node A's state
	addSetA, remSetA := jailA.ExportState()
	newlyBanned := jailB.Merge(addSetA, remSetA)
	if len(newlyBanned) != 1 {
		t.Fatalf("Expected 1 newly banned IP on Node B after merge, got %d", len(newlyBanned))
	}
	if jailB.Count() != 1 {
		t.Fatalf("Expected Node B to converge to 1 ban, got %d", jailB.Count())
	}

	// 3. Node B unbans (Remove)
	time.Sleep(2 * time.Millisecond)
	jailB.Remove("198.51.100.99", "False positive manual unban")
	if jailB.Count() != 0 {
		t.Fatalf("Expected 0 active bans in Node B after removal, got %d", jailB.Count())
	}

	// 4. Node A merges Node B's state -> Node A converges to 0 bans
	addSetB, remSetB := jailB.ExportState()
	jailA.Merge(addSetB, remSetB)
	if jailA.Count() != 0 {
		t.Fatalf("Expected Node A to converge to 0 bans after LWW Remove merge, got %d", jailA.Count())
	}
}
