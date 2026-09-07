package deception

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCanaryTokenGeneration(t *testing.T) {
	engine := NewCanaryEngine(nil)

	// 1. AWS Key Generation
	awsKey := engine.GenerateAWSKey("test_aws")
	if !strings.HasPrefix(awsKey, "AKIA") {
		t.Fatalf("Expected AWS key starting with AKIA, got %s", awsKey)
	}
	if len(awsKey) != 20 {
		t.Fatalf("Expected AWS key length 20, got %d (%s)", len(awsKey), awsKey)
	}

	token, ok := engine.GetToken(awsKey)
	if !ok || token.TokenType != CanaryTypeAWSKey {
		t.Fatalf("Token not found or invalid type: %+v", token)
	}

	// 2. API Token Generation
	apiToken := engine.GenerateAPIToken("test_api")
	if !strings.HasPrefix(apiToken, "copsec_canary_live_") {
		t.Fatalf("Expected API token starting with copsec_canary_live_, got %s", apiToken)
	}
	if len(apiToken) != 19+32 {
		t.Fatalf("Expected API token length 51, got %d (%s)", len(apiToken), apiToken)
	}

	// 3. Pseudo-DB Connection String
	dbConn := engine.GenerateDBConnString("postgres", "test_db")
	if !strings.HasPrefix(dbConn, "postgres://") {
		t.Fatalf("Expected postgres connection string, got %s", dbConn)
	}
}

func TestCanaryDetectionAndTrigger(t *testing.T) {
	engine := NewCanaryEngine(nil)

	awsKey := engine.GenerateAWSKey("aws_metadata")
	apiToken := engine.GenerateAPIToken("api_metadata")
	dbConn := engine.GenerateDBConnString("mysql", "db_metadata")

	var triggeredTokens []string
	var mu sync.Mutex

	engine.SetTriggerCallback(func(token *CanaryToken, clientIP string, location string) {
		mu.Lock()
		defer mu.Unlock()
		triggeredTokens = append(triggeredTokens, token.TokenValue)
	})

	// 1. Inspect in string
	content := "DEBUG log: found credentials " + awsKey + " inside env file"
	tok, hit := engine.InspectString(content, "192.168.1.50", "FileContent")
	if !hit || tok.TokenValue != awsKey {
		t.Fatalf("Failed to detect AWS canary token in raw text: hit=%v, tok=%+v", hit, tok)
	}

	if tok.TriggeredCount != 1 {
		t.Fatalf("Expected TriggeredCount 1, got %d", tok.TriggeredCount)
	}

	// 2. Inspect HTTP Request with Header
	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.RemoteAddr = "10.0.0.5:43210"

	tok, hit = engine.InspectHTTPRequest(req)
	if !hit || tok.TokenValue != apiToken {
		t.Fatalf("Failed to detect API token in HTTP Authorization header: hit=%v, tok=%+v", hit, tok)
	}

	// 3. Inspect HTTP Request with Query Parameter
	req2 := httptest.NewRequest("GET", "/api/v1/data?db_conn="+dbConn, nil)
	req2.RemoteAddr = "172.16.0.9:54321"

	tok, hit = engine.InspectHTTPRequest(req2)
	if !hit || tok.TokenValue != dbConn {
		t.Fatalf("Failed to detect DB connection string in query param: hit=%v, tok=%+v", hit, tok)
	}

	// 4. Inspect HTTP Request Body
	bodyContent := `{"database_uri": "` + dbConn + `"}`
	req3 := httptest.NewRequest("POST", "/api/v1/config", bytes.NewBufferString(bodyContent))
	req3.Header.Set("Content-Type", "application/json")
	req3.RemoteAddr = "192.168.1.100:12345"

	tok, hit = engine.InspectHTTPRequest(req3)
	if !hit || tok.TokenValue != dbConn {
		t.Fatalf("Failed to detect token in HTTP body: hit=%v, tok=%+v", hit, tok)
	}

	mu.Lock()
	if len(triggeredTokens) != 4 {
		t.Fatalf("Expected 4 trigger events, got %d: %v", len(triggeredTokens), triggeredTokens)
	}
	mu.Unlock()
}

func TestCanaryDecoyHeaderInjection(t *testing.T) {
	engine := NewCanaryEngine(nil)

	header := make(http.Header)
	engine.InjectDecoyHeaders(header)

	debugToken := header.Get("X-Debug-Session-Token")
	if !strings.HasPrefix(debugToken, "copsec_canary_live_") {
		t.Fatalf("Expected injected X-Debug-Session-Token header, got %s", debugToken)
	}

	configKey := header.Get("X-Backend-Config-Key")
	if !strings.HasPrefix(configKey, "AKIA") {
		t.Fatalf("Expected injected X-Backend-Config-Key header, got %s", configKey)
	}

	// Verify both injected tokens are active and detectable
	if _, ok := engine.GetToken(debugToken); !ok {
		t.Fatalf("Injected debugToken not registered in CanaryEngine")
	}
	if _, ok := engine.GetToken(configKey); !ok {
		t.Fatalf("Injected configKey not registered in CanaryEngine")
	}
}
