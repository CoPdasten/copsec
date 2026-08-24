package dns

import (
	"testing"
)

func TestDNSSinkholeDGAndExfilDetection(t *testing.T) {
	engine := NewDNSSinkholeEngine(nil)

	// 1. C2 Known Suffix
	ev1, sinkholed1 := engine.InspectDomain("c2-beacon.oastify.com", "A", 1234)
	if !sinkholed1 || ev1 == nil {
		t.Fatalf("Expected C2 suffix domain to be sinkholed")
	}
	if ev1.AnomalyType != "C2_IOC_MATCH" {
		t.Errorf("Expected anomaly type C2_IOC_MATCH, got %s", ev1.AnomalyType)
	}
	if ev1.SinkholedTo != "0.0.0.0" {
		t.Errorf("Expected sinkholed IP 0.0.0.0, got %s", ev1.SinkholedTo)
	}

	// 2. DNS Tunneling Payload
	ev2, sinkholed2 := engine.InspectDomain("4f68656c6c6f20776f726c64207365637265742070617373776f7264.tunnel.attacker.com", "TXT", 5678)
	if !sinkholed2 || ev2 == nil {
		t.Fatalf("Expected DNS Tunneling payload to be sinkholed")
	}
	if ev2.AnomalyType != "DNS_TUNNELING" {
		t.Errorf("Expected anomaly type DNS_TUNNELING, got %s", ev2.AnomalyType)
	}

	// 3. DGA High Entropy Domain
	ev3, sinkholed3 := engine.InspectDomain("xk7q9zj2w8m4p1v6n3b5.xyz", "A", 9999)
	if !sinkholed3 || ev3 == nil {
		t.Fatalf("Expected DGA high-entropy domain to be sinkholed")
	}
	if ev3.AnomalyType != "DGA_DOMAIN" {
		t.Errorf("Expected anomaly type DGA_DOMAIN, got %s", ev3.AnomalyType)
	}

	// 4. Benign Domain
	ev4, sinkholed4 := engine.InspectDomain("api.github.com", "A", 100)
	if sinkholed4 || ev4 != nil {
		t.Errorf("Expected benign domain to not be sinkholed")
	}
}
