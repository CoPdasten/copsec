package dpi

import (
	"strings"
	"sync"
	"sync/atomic"
)

// RuleCategory represents the classification taxonomy for Layer 7 threat signatures.
type RuleCategory string

const (
	CategoryRCEDeserialization RuleCategory = "RCE_DESERIALIZATION"
	CategoryCommandInjection   RuleCategory = "COMMAND_INJECTION"
	CategorySQLInjection       RuleCategory = "SQL_INJECTION"
	CategoryPathTraversal      RuleCategory = "PATH_TRAVERSAL"
	CategoryWebShell           RuleCategory = "WEB_SHELL"
	CategorySSRFMetadata       RuleCategory = "SSRF_METADATA"
	CategoryXSSSSTI            RuleCategory = "XSS_SSTI"
	CategoryCustomZeroDay      RuleCategory = "CUSTOM_ZERO_DAY"
)

// Rule defines an enterprise Layer 7 DPI detection signature.
type Rule struct {
	ID       string       `json:"id" yaml:"id"`
	Name     string       `json:"name" yaml:"name"`
	Pattern  string       `json:"pattern" yaml:"pattern"`
	Category RuleCategory `json:"category" yaml:"category"`
	Severity string       `json:"severity,omitempty" yaml:"severity,omitempty"`
}

// MatchResult captures the structured verdict of an Aho-Corasick trie match.
type MatchResult struct {
	MatchedPattern string       `json:"matched_pattern"`
	RuleID         string       `json:"rule_id"`
	RuleName       string       `json:"rule_name"`
	Category       RuleCategory `json:"category"`
	Offset         int          `json:"offset"`
}

// trieNode represents a state in the compiled Aho-Corasick DFA.
type trieNode struct {
	children [256]*trieNode
	fail     *trieNode
	matches  []*Rule
}

// trieState holds an immutable compiled Aho-Corasick state machine.
type trieState struct {
	root  *trieNode
	rules []Rule
}

// toLowerTable provides zero-allocation instant byte lowercase normalization.
var toLowerTable [256]byte

func init() {
	for i := 0; i < 256; i++ {
		if i >= 'A' && i <= 'Z' {
			toLowerTable[i] = byte(i + ('a' - 'A'))
		} else {
			toLowerTable[i] = byte(i)
		}
	}
}

// AhoCorasickEngine provides high-performance, thread-safe, single-pass O(N) multi-pattern matching.
type AhoCorasickEngine struct {
	mu    sync.RWMutex
	state atomic.Pointer[trieState]
}

var (
	defaultEngine *AhoCorasickEngine
	engineOnce    sync.Once
)

// GetDefaultEngine returns the singleton instance of the deterministic Aho-Corasick DPI engine.
func GetDefaultEngine() *AhoCorasickEngine {
	engineOnce.Do(func() {
		defaultEngine = NewAhoCorasickEngine(GetEmbeddedSignatures())
	})
	return defaultEngine
}

// NewAhoCorasickEngine compiles a new thread-safe Aho-Corasick matcher from the provided rule set.
func NewAhoCorasickEngine(rules []Rule) *AhoCorasickEngine {
	engine := &AhoCorasickEngine{}
	compiled := compileTrie(rules)
	engine.state.Store(compiled)
	return engine
}

// Scan performs single-pass deterministic O(N) traversal over raw byte stream.
// Returns the first matched signature verdict and true, or empty verdict and false.
func (e *AhoCorasickEngine) Scan(data []byte) (MatchResult, bool) {
	st := e.state.Load()
	if st == nil || st.root == nil || len(data) == 0 {
		return MatchResult{}, false
	}

	curr := st.root
	for i := 0; i < len(data); i++ {
		b := toLowerTable[data[i]]
		curr = curr.children[b]
		if len(curr.matches) > 0 {
			first := curr.matches[0]
			return MatchResult{
				MatchedPattern: first.Pattern,
				RuleID:         first.ID,
				RuleName:       first.Name,
				Category:       first.Category,
				Offset:         i - len(first.Pattern) + 1,
			}, true
		}
	}

	return MatchResult{}, false
}

// ScanAll traverses raw bytes in single-pass O(N) and returns all matched signature verdicts.
func (e *AhoCorasickEngine) ScanAll(data []byte) []MatchResult {
	st := e.state.Load()
	if st == nil || st.root == nil || len(data) == 0 {
		return nil
	}

	var results []MatchResult
	curr := st.root
	for i := 0; i < len(data); i++ {
		b := toLowerTable[data[i]]
		curr = curr.children[b]
		for _, m := range curr.matches {
			results = append(results, MatchResult{
				MatchedPattern: m.Pattern,
				RuleID:         m.ID,
				RuleName:       m.Name,
				Category:       m.Category,
				Offset:         i - len(m.Pattern) + 1,
			})
		}
	}

	return results
}

// BuildFailurePointers re-compiles failure pointers and swaps in updated rules safely.
func (e *AhoCorasickEngine) BuildFailurePointers(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	compiled := compileTrie(rules)
	e.state.Store(compiled)
}

// AddRule safely injects a new rule and atomically recompiles the state machine.
func (e *AhoCorasickEngine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.GetRules()
	updated := append(current, rule)
	compiled := compileTrie(updated)
	e.state.Store(compiled)
}

// GetRules returns a copy of active inspection rules.
func (e *AhoCorasickEngine) GetRules() []Rule {
	st := e.state.Load()
	if st == nil {
		return nil
	}
	res := make([]Rule, len(st.rules))
	copy(res, st.rules)
	return res
}

// RuleCount returns the total number of active deterministic signatures.
func (e *AhoCorasickEngine) RuleCount() int {
	st := e.state.Load()
	if st == nil {
		return 0
	}
	return len(st.rules)
}

// compileTrie builds an Aho-Corasick Trie and converts it into a single-pass DFA via BFS failure pointers.
func compileTrie(rules []Rule) *trieState {
	root := &trieNode{}
	cleanRules := make([]Rule, 0, len(rules))

	for _, r := range rules {
		normPattern := strings.ToLower(strings.TrimSpace(r.Pattern))
		if normPattern == "" {
			continue
		}

		ruleCopy := r
		ruleCopy.Pattern = normPattern
		cleanRules = append(cleanRules, ruleCopy)

		curr := root
		for i := 0; i < len(normPattern); i++ {
			b := normPattern[i]
			if curr.children[b] == nil {
				curr.children[b] = &trieNode{}
			}
			curr = curr.children[b]
		}
		curr.matches = append(curr.matches, &ruleCopy)
	}

	// BFS-driven Failure Pointer Construction (Trie -> Deterministic Automaton)
	queue := make([]*trieNode, 0, 1024)

	// Level 1: Direct root children
	for b := 0; b < 256; b++ {
		if root.children[b] != nil {
			root.children[b].fail = root
			queue = append(queue, root.children[b])
		} else {
			root.children[b] = root
		}
	}

	// Level 2+: Propagate failure pointers and build deterministic jump transitions
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for b := 0; b < 256; b++ {
			child := curr.children[b]
			if child != nil {
				child.fail = curr.fail.children[b]
				if len(child.fail.matches) > 0 {
					child.matches = append(child.matches, child.fail.matches...)
				}
				queue = append(queue, child)
			} else {
				// Precompute next transition so runtime scan never loops through fail pointers
				curr.children[b] = curr.fail.children[b]
			}
		}
	}

	return &trieState{
		root:  root,
		rules: cleanRules,
	}
}

// GetEmbeddedSignatures returns the enterprise Layer 7 DPI baseline signature database.
func GetEmbeddedSignatures() []Rule {
	return []Rule{
		// 1. RCE & Deserialization
		{
			ID:       "RCE_SHELLSHOCK_01",
			Name:     "CVE-2014-6271 Shellshock Function Definition Exploit",
			Pattern:  "() { :;};",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "RCE_SHELLSHOCK_02",
			Name:     "CVE-2014-6271 Shellshock Variant Payload",
			Pattern:  "() { _; }",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "RCE_LOG4J_LDAP",
			Name:     "CVE-2021-44228 Log4j JNDI LDAP Injection",
			Pattern:  "${jndi:ldap:",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "RCE_LOG4J_RMI",
			Name:     "CVE-2021-44228 Log4j JNDI RMI Injection",
			Pattern:  "${jndi:rmi:",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "RCE_LOG4J_DNS",
			Name:     "CVE-2021-44228 Log4j JNDI DNS Exfiltration",
			Pattern:  "${jndi:dns:",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "RCE_LOG4J_NIS",
			Name:     "CVE-2021-44228 Log4j JNDI NIS Probe",
			Pattern:  "${jndi:nis:",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "JAVA_DESER_COMMONS",
			Name:     "Java Deserialization CommonsCollections Gadget",
			Pattern:  "org.apache.commons.collections",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "JAVA_DESER_TRANSFORMER",
			Name:     "Java Deserialization InvokeTransformer Remote Code Invocation",
			Pattern:  "invoketransformer",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "JAVA_DESER_YSOSERIAL",
			Name:     "Ysoserial Java Deserialization Payload Fingerprint",
			Pattern:  "ysoserial",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "JAVA_PROCESS_RUNTIME",
			Name:     "Java Process Spawning getruntime().exec",
			Pattern:  "getruntime().exec",
			Category: CategoryRCEDeserialization,
			Severity: "HIGH",
		},
		{
			ID:       "JAVA_PROCESS_BUILDER",
			Name:     "Java Process Spawning ProcessBuilder",
			Pattern:  "processbuilder",
			Category: CategoryRCEDeserialization,
			Severity: "HIGH",
		},
		{
			ID:       "THINKPHP_RCE_APP",
			Name:     "ThinkPHP Remote Code Execution think\\app",
			Pattern:  "think\\app",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},
		{
			ID:       "THINKPHP_RCE_INVOKE",
			Name:     "ThinkPHP Remote Code Execution invokefunction",
			Pattern:  "invokefunction",
			Category: CategoryRCEDeserialization,
			Severity: "CRITICAL",
		},

		// 2. Command Injection & Reverse Shells
		{
			ID:       "CMD_SH",
			Name:     "Direct Unix Shell Execution /bin/sh",
			Pattern:  "/bin/sh",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_BASH",
			Name:     "Direct Unix Shell Execution /bin/bash",
			Pattern:  "/bin/bash",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_POWERSHELL_EXE",
			Name:     "PowerShell Process Execution powershell.exe",
			Pattern:  "powershell.exe",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_POWERSHELL_ENC",
			Name:     "PowerShell Encoded Command Payload powershell -enc",
			Pattern:  "powershell -enc",
			Category: CategoryCommandInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "CMD_WINDOWS_C",
			Name:     "Windows Command Prompt Shell cmd.exe /c",
			Pattern:  "cmd.exe /c",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_CURL_SILENT",
			Name:     "Command Staging Download curl -s",
			Pattern:  "curl -s",
			Category: CategoryCommandInjection,
			Severity: "MEDIUM",
		},
		{
			ID:       "CMD_WGET_HTTP",
			Name:     "Command Staging Download wget http",
			Pattern:  "wget http",
			Category: CategoryCommandInjection,
			Severity: "MEDIUM",
		},
		{
			ID:       "CMD_CERTUTIL_URLCACHE",
			Name:     "Windows LOLBin Download certutil.exe -urlcache",
			Pattern:  "certutil.exe -urlcache",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "REV_BASH_TCP",
			Name:     "Linux Bash Interactive Reverse Shell /dev/tcp/",
			Pattern:  "/dev/tcp/",
			Category: CategoryCommandInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "REV_NETCAT_EXEC",
			Name:     "Netcat Inbound Execution nc -e",
			Pattern:  "nc -e",
			Category: CategoryCommandInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "REV_NETCAT_LISTEN",
			Name:     "Netcat Listener Binding nc -lvnp",
			Pattern:  "nc -lvnp",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_CAT_PASSWD",
			Name:     "Credential Reconnaissance cat /etc/passwd",
			Pattern:  "cat /etc/passwd",
			Category: CategoryCommandInjection,
			Severity: "HIGH",
		},
		{
			ID:       "CMD_CAT_SHADOW",
			Name:     "Password Hash Reconnaissance cat /etc/shadow",
			Pattern:  "cat /etc/shadow",
			Category: CategoryCommandInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "CMD_WHOAMI",
			Name:     "Privilege Reconnaissance whoami",
			Pattern:  "whoami",
			Category: CategoryCommandInjection,
			Severity: "LOW",
		},

		// 3. Advanced SQL Injection (SQLi)
		{
			ID:       "SQLI_UNION_SELECT",
			Name:     "SQL Injection UNION SELECT Exfiltration",
			Pattern:  "union select",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_UNION_ALL_SELECT",
			Name:     "SQL Injection UNION ALL SELECT Exfiltration",
			Pattern:  "union all select",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_ORDER_BY",
			Name:     "SQL Injection Column Enumeration ORDER BY",
			Pattern:  "order by",
			Category: CategorySQLInjection,
			Severity: "MEDIUM",
		},
		{
			ID:       "SQLI_INFO_SCHEMA",
			Name:     "SQL Injection Database Schema Enumeration information_schema",
			Pattern:  "information_schema",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_SQLITE_MASTER",
			Name:     "SQLite Schema Enumeration sqlite_master",
			Pattern:  "sqlite_master",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_WAITFOR_DELAY",
			Name:     "MSSQL Blind Time-Based Injection waitfor delay",
			Pattern:  "waitfor delay",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_SLEEP",
			Name:     "MySQL Blind Time-Based Injection sleep(",
			Pattern:  "sleep(",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_BENCHMARK",
			Name:     "MySQL Time-Based Blind Injection benchmark(",
			Pattern:  "benchmark(",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_PG_SLEEP",
			Name:     "PostgreSQL Blind Time-Based Injection pg_sleep",
			Pattern:  "pg_sleep",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_OR_1_EQUALS_1_SINGLE",
			Name:     "SQL Tautology Authentication Bypass ' or 1=1",
			Pattern:  "' or 1=1",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_OR_1_EQUALS_1_DOUBLE",
			Name:     "SQL Tautology Authentication Bypass \" or 1=1",
			Pattern:  "\" or 1=1",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_OR_1_EQUALS_1_QUOTED",
			Name:     "SQL Tautology Authentication Bypass ' or '1'='1",
			Pattern:  "' or '1'='1",
			Category: CategorySQLInjection,
			Severity: "HIGH",
		},
		{
			ID:       "SQLI_LOAD_FILE",
			Name:     "MySQL Arbitrary Local File Read load_file(",
			Pattern:  "load_file(",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_INTO_OUTFILE",
			Name:     "MySQL Arbitrary Web Shell Write into outfile",
			Pattern:  "into outfile",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},
		{
			ID:       "SQLI_INTO_DUMPFILE",
			Name:     "MySQL Binary Web Shell Write into dumpfile",
			Pattern:  "into dumpfile",
			Category: CategorySQLInjection,
			Severity: "CRITICAL",
		},

		// 4. Path Traversal & File Inclusion (LFI/RFI)
		{
			ID:       "LFI_DOT_DOT_SLASH",
			Name:     "Directory Traversal Sequence ../../",
			Pattern:  "../../",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_DOT_DOT_BACKSLASH",
			Name:     "Windows Directory Traversal Sequence ..\\..\\",
			Pattern:  "..\\..\\",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_URL_ENCODED_SLASH",
			Name:     "URL-Encoded Directory Traversal Sequence ..%2f..%2f",
			Pattern:  "..%2f..%2f",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_URL_ENCODED_BACKSLASH",
			Name:     "URL-Encoded Windows Directory Traversal ..%5c..%5c",
			Pattern:  "..%5c..%5c",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_ETC_PASSWD",
			Name:     "Arbitrary File Disclosure /etc/passwd",
			Pattern:  "/etc/passwd",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_ETC_SHADOW",
			Name:     "Arbitrary File Disclosure /etc/shadow",
			Pattern:  "/etc/shadow",
			Category: CategoryPathTraversal,
			Severity: "CRITICAL",
		},
		{
			ID:       "LFI_ETC_HOSTS",
			Name:     "Internal Network Enumeration /etc/hosts",
			Pattern:  "/etc/hosts",
			Category: CategoryPathTraversal,
			Severity: "MEDIUM",
		},
		{
			ID:       "LFI_WIN_BOOT_INI",
			Name:     "Windows Boot Configuration Disclosure c:\\boot.ini",
			Pattern:  "c:\\boot.ini",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_WIN_WIN_INI",
			Name:     "Windows Core Configuration Disclosure c:\\windows\\win.ini",
			Pattern:  "c:\\windows\\win.ini",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_WIN_SYSTEM32",
			Name:     "Windows System Directory Traversal c:\\windows\\system32",
			Pattern:  "c:\\windows\\system32",
			Category: CategoryPathTraversal,
			Severity: "HIGH",
		},
		{
			ID:       "LFI_PHP_FILTER",
			Name:     "PHP Stream Wrapper Source Code Disclosure php://filter",
			Pattern:  "php://filter",
			Category: CategoryPathTraversal,
			Severity: "CRITICAL",
		},
		{
			ID:       "LFI_PHP_INPUT",
			Name:     "PHP Stream Wrapper Code Execution php://input",
			Pattern:  "php://input",
			Category: CategoryPathTraversal,
			Severity: "CRITICAL",
		},
		{
			ID:       "LFI_DATA_PLAIN",
			Name:     "Data URI Remote Code Injection data://text/plain",
			Pattern:  "data://text/plain",
			Category: CategoryPathTraversal,
			Severity: "CRITICAL",
		},

		// 5. Web Shells & Backdoors
		{
			ID:       "WS_EVAL_BASE64",
			Name:     "PHP Web Shell Dynamic Evaluation eval(base64_decode",
			Pattern:  "eval(base64_decode",
			Category: CategoryWebShell,
			Severity: "CRITICAL",
		},
		{
			ID:       "WS_EVAL_POST",
			Name:     "PHP Web Shell POST Ingestion eval($_post",
			Pattern:  "eval($_post",
			Category: CategoryWebShell,
			Severity: "CRITICAL",
		},
		{
			ID:       "WS_EVAL_GET",
			Name:     "PHP Web Shell GET Ingestion eval($_get",
			Pattern:  "eval($_get",
			Category: CategoryWebShell,
			Severity: "CRITICAL",
		},
		{
			ID:       "WS_ASSERT_POST",
			Name:     "PHP Assert Dynamic Execution assert($_post",
			Pattern:  "assert($_post",
			Category: CategoryWebShell,
			Severity: "CRITICAL",
		},
		{
			ID:       "WS_SHELL_EXEC",
			Name:     "PHP OS Command Execution shell_exec(",
			Pattern:  "shell_exec(",
			Category: CategoryWebShell,
			Severity: "HIGH",
		},
		{
			ID:       "WS_PASSTHRU",
			Name:     "PHP OS Command Execution passthru(",
			Pattern:  "passthru(",
			Category: CategoryWebShell,
			Severity: "HIGH",
		},
		{
			ID:       "WS_POPEN",
			Name:     "PHP Process Pipeline Opening popen(",
			Pattern:  "popen(",
			Category: CategoryWebShell,
			Severity: "HIGH",
		},
		{
			ID:       "WS_JSP_PAGE_IMPORT",
			Name:     "JSP Web Shell Directive <%@ page import",
			Pattern:  "<%@ page import",
			Category: CategoryWebShell,
			Severity: "CRITICAL",
		},
		{
			ID:       "WS_JSP_ROOT",
			Name:     "JSP XML Syntax Root Injection jsp:root",
			Pattern:  "jsp:root",
			Category: CategoryWebShell,
			Severity: "HIGH",
		},

		// 6. SSRF & Cloud Metadata Exploits
		{
			ID:       "SSRF_CLOUD_METADATA_IP",
			Name:     "AWS / DigitalOcean Cloud Instance Metadata Exfiltration 169.254.169.254",
			Pattern:  "169.254.169.254",
			Category: CategorySSRFMetadata,
			Severity: "CRITICAL",
		},
		{
			ID:       "SSRF_GCP_METADATA",
			Name:     "GCP Cloud Instance Metadata Exfiltration metadata.google.internal",
			Pattern:  "metadata.google.internal",
			Category: CategorySSRFMetadata,
			Severity: "CRITICAL",
		},
		{
			ID:       "SSRF_FILE_URI",
			Name:     "SSRF Local File Read Scheme file:///",
			Pattern:  "file:///",
			Category: CategorySSRFMetadata,
			Severity: "HIGH",
		},
		{
			ID:       "SSRF_GOPHER_URI",
			Name:     "SSRF Internal Port / Protocol Smuggling gopher://",
			Pattern:  "gopher://",
			Category: CategorySSRFMetadata,
			Severity: "CRITICAL",
		},
		{
			ID:       "SSRF_DICT_URI",
			Name:     "SSRF Service Banner Enumeration dict://",
			Pattern:  "dict://",
			Category: CategorySSRFMetadata,
			Severity: "HIGH",
		},

		// 7. XSS & Template Injection (SSTI)
		{
			ID:       "XSS_SCRIPT_TAG",
			Name:     "Cross-Site Scripting Script Tag Injection <script",
			Pattern:  "<script",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "XSS_JAVASCRIPT_PSEUDO",
			Name:     "Cross-Site Scripting Pseudo-Protocol javascript:",
			Pattern:  "javascript:",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "XSS_DOCUMENT_COOKIE",
			Name:     "Cross-Site Scripting Session Hijacking document.cookie",
			Pattern:  "document.cookie",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "XSS_ONERROR_HANDLER",
			Name:     "HTML Event Handler Injection onerror=",
			Pattern:  "onerror=",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "XSS_ONLOAD_HANDLER",
			Name:     "HTML Event Handler Injection onload=",
			Pattern:  "onload=",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "SSTI_CONFIG_ITEMS",
			Name:     "Server-Side Template Injection Jinja2 / Flask {{config.items()}}",
			Pattern:  "{{config.items()}}",
			Category: CategoryXSSSSTI,
			Severity: "CRITICAL",
		},
		{
			ID:       "SSTI_JINJA_MATH",
			Name:     "Server-Side Template Injection Math Probe {{7*7}}",
			Pattern:  "{{7*7}}",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "SSTI_RUBY_MATH",
			Name:     "Ruby ERB Template Injection Math Probe #{7*7}",
			Pattern:  "#{7*7}",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
		{
			ID:       "SSTI_JAVA_EL_MATH",
			Name:     "Java Expression Language / Spring SSTI Math Probe ${7*7}",
			Pattern:  "${7*7}",
			Category: CategoryXSSSSTI,
			Severity: "HIGH",
		},
	}
}
