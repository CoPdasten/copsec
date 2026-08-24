package threat

import (
	"sync"
	"testing"
	"time"
)

func TestTier1InstantCritical(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	assessment := engine.Evaluate("198.51.100.10", 95, "sigma-linux-revshell", "T1059.004", 200, "AS15169 Google LLC")
	if assessment.Action != ActionInstantBan {
		t.Errorf("Expected ActionInstantBan for Tier 1 Reverse Shell, got %s", assessment.Action)
	}
	if assessment.FinalScore < 95 {
		t.Errorf("Expected score >= 95, got %d", assessment.FinalScore)
	}
	if assessment.Tier != "TIER_1_CRITICAL" {
		t.Errorf("Expected TIER_1_CRITICAL, got %s", assessment.Tier)
	}
}

func TestTier2DeceptionTrap(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	assessment := engine.Evaluate("198.51.100.20", 85, "honeypot_ssh_probe", "T1190", 200, "AS14061 DigitalOcean")
	if assessment.Action != ActionInstantBan {
		t.Errorf("Expected ActionInstantBan for Honeypot trap interaction, got %s", assessment.Action)
	}
	if assessment.Tier != "TIER_2_DECEPTION" {
		t.Errorf("Expected TIER_2_DECEPTION, got %s", assessment.Tier)
	}
}

func TestTier3SSHAuthBurstAccumulation(t *testing.T) {
	engine := NewScoringEngine(80, 60)
	targetIP := "203.0.113.50"

	// 1st SSH Failure: Base +25 -> Score 25
	ev1 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev1.FinalScore != 25 {
		t.Errorf("1st attempt: expected score 25, got %d", ev1.FinalScore)
	}
	if ev1.Action != ActionAllow {
		t.Errorf("1st attempt: expected ActionAllow, got %s", ev1.Action)
	}

	// 2nd SSH Failure: +25 * 1.5 = +37.5 -> Score ~63 (Tarpit threshold reached)
	ev2 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev2.FinalScore < 60 || ev2.FinalScore > 65 {
		t.Errorf("2nd attempt: expected score ~63, got %d", ev2.FinalScore)
	}
	if ev2.Action != ActionTarpit {
		t.Errorf("2nd attempt: expected ActionTarpit, got %s", ev2.Action)
	}

	// 3rd SSH Failure: +25 * 1.5^2 = +56.25 -> Score > 100 -> Instant Ban!
	ev3 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev3.FinalScore < 80 {
		t.Errorf("3rd attempt: expected score >= 80, got %d", ev3.FinalScore)
	}
	if ev3.Action != ActionInstantBan {
		t.Errorf("3rd attempt: expected ActionInstantBan, got %s", ev3.Action)
	}
}

func TestDatacenterASNMultiplier(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	// Standard ISP
	standard := engine.Evaluate("198.51.100.30", 10, "web_scan", "T1595", 404, "Residential Comcast")
	// Cloud Datacenter ASN (DigitalOcean -> 1.3x)
	dc := engine.Evaluate("198.51.100.31", 10, "web_scan", "T1595", 404, "AS14061 DigitalOcean LLC")

	if dc.FinalScore <= standard.FinalScore {
		t.Errorf("Expected datacenter ASN score (%d) to be higher than standard ISP (%d)", dc.FinalScore, standard.FinalScore)
	}
	if dc.RiskMultiplier != 1.3 {
		t.Errorf("Expected 1.3x risk multiplier, got %.1f", dc.RiskMultiplier)
	}
}

func TestWhitelistedEntityProtection(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	_ = engine.AddWhitelistCIDR("10.0.0.0/8")
	_ = engine.AddWhitelistCIDR("192.168.1.100")

	res1 := engine.Evaluate("127.0.0.1", 100, "sigma-linux-revshell", "T1059.004", 200, "Local")
	if !res1.IsWhitelisted || res1.FinalScore != 0 || res1.Action != ActionAllow {
		t.Errorf("Expected localhost 127.0.0.1 to be protected, got %+v", res1)
	}

	res2 := engine.Evaluate("10.0.5.22", 100, "sigma-linux-revshell", "T1059.004", 200, "Internal LAN")
	if !res2.IsWhitelisted || res2.FinalScore != 0 || res2.Action != ActionAllow {
		t.Errorf("Expected internal 10.0.5.22 to be protected, got %+v", res2)
	}
}

func TestHalfLifeScoreDecay(t *testing.T) {
	engine := NewScoringEngine(80, 60)
	targetIP := "198.51.100.77"

	// 1. Initial event gives score 40
	ev1 := engine.Evaluate(targetIP, 40, "generic_probe", "T1595", 200, "Standard")
	if ev1.FinalScore != 40 {
		t.Fatalf("Expected score 40, got %d", ev1.FinalScore)
	}

	// 2. Manipulate LastSeenMs to simulate 3 minutes (180s = 1 half life) of inactivity
	shard := engine.getShard(targetIP)
	shard.mu.Lock()
	state := shard.entities[targetIP]
	state.LastSeenMs = time.Now().Add(-180 * time.Second).UnixMilli()
	shard.mu.Unlock()

	// 3. New benign query -> previous score 40 should have decayed to ~20
	ev2 := engine.Evaluate(targetIP, 5, "minor_probe", "T1595", 200, "Standard")
	if ev2.DecayedScore < 18.0 || ev2.DecayedScore > 22.0 {
		t.Errorf("Expected decayed score ~20, got %.1f", ev2.DecayedScore)
	}
}

func TestConcurrentScoringThreadSafety(t *testing.T) {
	engine := NewScoringEngine(80, 60)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "198.51.100.99"
			_ = engine.Evaluate(ip, 10, "concurrent_test", "T1190", 200, "AS1234")
		}(i)
	}
	wg.Wait()

	state, exists := engine.GetEntityState("198.51.100.99")
	if !exists || state.TotalIncidents != 50 {
		t.Errorf("Expected 50 incidents recorded concurrently, got %v", state)
	}
}
