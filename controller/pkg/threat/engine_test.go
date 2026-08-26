package threat

import (
	"sync"
	"testing"
	"time"

	"github.com/copsec/controller/pkg/models"
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
	if assessment.Severity != models.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %s", assessment.Severity)
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
	if assessment.Severity != models.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %s", assessment.Severity)
	}
}

func TestTier3SSHAuthBurstAccumulation(t *testing.T) {
	engine := NewScoringEngine(80, 60)
	targetIP := "203.0.113.50"

	// 1st SSH Failure: Base +25 -> Score 25 (Severity LOW)
	ev1 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev1.FinalScore != 25 {
		t.Errorf("1st attempt: expected score 25, got %d", ev1.FinalScore)
	}
	if ev1.Action != ActionAllow {
		t.Errorf("1st attempt: expected ActionAllow, got %s", ev1.Action)
	}
	if ev1.Severity != models.SeverityLow {
		t.Errorf("1st attempt: expected SeverityLow, got %s", ev1.Severity)
	}

	// 2nd SSH Failure: +25 * 1.5 = +37.5 -> Score ~63 (Tarpit threshold reached, Severity HIGH)
	ev2 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev2.FinalScore < 60 || ev2.FinalScore > 65 {
		t.Errorf("2nd attempt: expected score ~63, got %d", ev2.FinalScore)
	}
	if ev2.Action != ActionTarpit {
		t.Errorf("2nd attempt: expected ActionTarpit, got %s", ev2.Action)
	}
	if ev2.Severity != models.SeverityHigh {
		t.Errorf("2nd attempt: expected SeverityHigh, got %s", ev2.Severity)
	}

	// 3rd SSH Failure: +25 * 1.5^2 = +56.25 -> Score > 100 -> Instant Ban! (Severity CRITICAL)
	ev3 := engine.Evaluate(targetIP, 25, "ssh_auth_fail", "T1110.001", 200, "AS1234 Standard ISP")
	if ev3.FinalScore < 80 {
		t.Errorf("3rd attempt: expected score >= 80, got %d", ev3.FinalScore)
	}
	if ev3.Action != ActionInstantBan {
		t.Errorf("3rd attempt: expected ActionInstantBan, got %s", ev3.Action)
	}
	if ev3.Severity != models.SeverityCritical {
		t.Errorf("3rd attempt: expected SeverityCritical, got %s", ev3.Severity)
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

func TestImmutableWhitelistProtectionAndGating(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	// 1. Recursive Public DNS Resolvers
	publicDNSList := []string{
		"1.1.1.1",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.4.4",
		"9.9.9.9",
		"208.67.222.222",
		"213.186.33.99",
		"213.186.33.100",
		"2001:41d0:3:163::1",
	}

	for _, dnsIP := range publicDNSList {
		res := engine.Evaluate(dnsIP, 100, "c2_dns_exfil", "T1071", 200, "Public Resolver")
		if !res.IsWhitelisted || res.FinalScore != 0 || res.Action != ActionAllow || res.Severity != models.SeverityInfo || res.MitreID != "" {
			t.Errorf("Expected public DNS %s to be whitelisted with 0 score, INFO severity, empty MitreID, got %+v", dnsIP, res)
		}
		if !engine.IsWhitelisted(dnsIP) {
			t.Errorf("IsWhitelisted(%s) should be true", dnsIP)
		}
	}

	// 2. Local & Loopback, RFC1918, Tailscale
	localList := []string{
		"127.0.0.1",
		"127.0.0.53",
		"::1",
		"10.0.0.1",
		"10.254.1.99",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.1",
		"192.168.100.50",
		"100.64.0.1",
		"100.127.255.254",
		"100.64.10.5",
	}

	for _, localIP := range localList {
		res := engine.Evaluate(localIP, 100, "sigma-linux-revshell", "T1059.004", 200, "Internal/Tailscale")
		if !res.IsWhitelisted || res.FinalScore != 0 || res.Action != ActionAllow || res.Severity != models.SeverityInfo || res.MitreID != "" {
			t.Errorf("Expected local/RFC1918/Tailscale IP %s to be protected with 0 score, INFO severity, empty MitreID, got %+v", localIP, res)
		}
		if !engine.IsWhitelisted(localIP) {
			t.Errorf("IsWhitelisted(%s) should be true", localIP)
		}
	}
}

func TestStandardDNSAndGenericAuditDenoising(t *testing.T) {
	engine := NewScoringEngine(80, 60)

	// Standard port 53 DNS query from non-whitelisted WAN IP: must not be assigned T1190 or elevated score
	dnsEv := engine.Evaluate("198.51.100.60", 0, "suricata_dns", "T1190", 200, "Standard ISP")
	if dnsEv.FinalScore != 0 || dnsEv.Severity != models.SeverityInfo || dnsEv.MitreID != "" {
		t.Errorf("Expected standard DNS traffic to have 0 score, INFO severity, and empty MitreID, got %+v", dnsEv)
	}

	// Generic audit event: must not be assigned T1190
	auditEv := engine.Evaluate("198.51.100.61", 20, "audit_event", "T1190", 200, "Standard ISP")
	if auditEv.MitreID == "T1190" {
		t.Errorf("Generic audit event must not be assigned T1190, got %+v", auditEv)
	}
}

func TestHalfLifeScoreDecay(t *testing.T) {
	engine := NewScoringEngine(80, 60)
	targetIP := "198.51.100.77"

	// 1. Initial event gives score 40 (Severity MEDIUM)
	ev1 := engine.Evaluate(targetIP, 40, "generic_probe", "T1595", 200, "Standard")
	if ev1.FinalScore != 40 || ev1.Severity != models.SeverityMedium {
		t.Fatalf("Expected score 40 and SeverityMedium, got score %d, severity %s", ev1.FinalScore, ev1.Severity)
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
