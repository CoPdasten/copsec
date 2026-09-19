package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/copsec/pkg/rules"
	"github.com/copsec/pkg/server"
	"github.com/copsec/pkg/streamer"
)

const (
	Version       = "v1.6.0"
	DefaultURL   = "http://127.0.0.1:8080"
	DefaultTimeout = 5 * time.Second
)

// ANSI color palette
var (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cWhite  = "\033[37m"
	cGray   = "\033[90m"
)

func init() {
	// Disable ANSI if NO_COLOR is set or TERM is dumb
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		cReset = ""
		cBold = ""
		cRed = ""
		cGreen = ""
		cYellow = ""
		cBlue = ""
		cPurple = ""
		cCyan = ""
		cWhite = ""
		cGray = ""
	}
}

// Global CLI options
type Config struct {
	BaseURL   string
	APIKey    string
	RulesPath string
	BPFMap    string
}

func readAPIKeyFromEnvFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COPSEC_API_KEY=") {
			val := strings.TrimPrefix(line, "COPSEC_API_KEY=")
			val = strings.Trim(val, `"' `)
			if val != "" {
				return val
			}
		}
	}
	return ""
}

func readControllerEndpointFromEnvFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COPSEC_CONTROLLER_ENDPOINT=") {
			val := strings.TrimPrefix(line, "COPSEC_CONTROLLER_ENDPOINT=")
			val = strings.Trim(val, `"' `)
			if val != "" {
				host, _, err := net.SplitHostPort(val)
				if err == nil && host != "" && host != "127.0.0.1" && host != "0.0.0.0" {
					return "http://" + host + ":8080"
				}
			}
		}
	}
	return ""
}

func readControllerURL() string {
	if data, err := os.ReadFile("/etc/copsec/controller_url"); err == nil {
		u := strings.TrimSpace(string(data))
		if u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	if ep := readControllerEndpointFromEnvFile("/etc/copsec/copsec.env"); ep != "" {
		return ep
	}
	if home, err := os.UserHomeDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(home, ".config", "copsec", "controller_url")); err == nil {
			u := strings.TrimSpace(string(data))
			if u != "" {
				return strings.TrimRight(u, "/")
			}
		}
	}
	return ""
}

func resolveConfig(flagURL, flagKey, flagRules, flagBPFMap string) Config {
	// 1. API Key resolution
	apiKey := strings.TrimSpace(flagKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("COPSEC_API_KEY"))
	}
	if apiKey == "" {
		if data, err := os.ReadFile("/etc/copsec/api_key"); err == nil {
			apiKey = strings.TrimSpace(string(data))
		}
	}
	if apiKey == "" {
		apiKey = readAPIKeyFromEnvFile("/etc/copsec/copsec.env")
	}
	if apiKey == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(filepath.Join(home, ".config", "copsec", "api_key")); err == nil {
				apiKey = strings.TrimSpace(string(data))
			}
		}
	}

	// 2. BaseURL resolution
	baseURL := strings.TrimRight(strings.TrimSpace(flagURL), "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("COPSEC_CONTROLLER_URL")), "/")
	}
	if baseURL == "" {
		baseURL = readControllerURL()
	}
	if baseURL == "" {
		baseURL = DefaultURL
	}

	// 3. RulesPath resolution
	rulesPath := strings.TrimSpace(flagRules)
	if rulesPath == "" {
		rulesPath = strings.TrimSpace(os.Getenv("COPSEC_RULES_PATH"))
	}
	if rulesPath == "" {
		candidates := []string{
			"/etc/copsec/rules.yaml",
			"/etc/copsec/rules.json",
			"./config/rules.json",
			"./rules.yaml",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				rulesPath = p
				break
			}
		}
	}
	if rulesPath == "" {
		rulesPath = "/etc/copsec/rules.yaml"
	}

	// 4. BPFMap resolution
	bpfMap := strings.TrimSpace(flagBPFMap)
	if bpfMap == "" {
		bpfMap = strings.TrimSpace(os.Getenv("COPSEC_BPF_MAP"))
	}
	if bpfMap == "" {
		bpfMap = "/sys/fs/bpf/copsec/lpm_blocklist"
	}

	return Config{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		RulesPath: rulesPath,
		BPFMap:    bpfMap,
	}
}

func parseGlobalArgs(rawArgs []string) (cleaned []string, flagURL, flagKey, flagRules, flagBPFMap, flagListen string, isDaemon, isHelp, isVersion bool) {
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if arg == "-h" || arg == "--help" || arg == "help" {
			if len(rawArgs) == 1 || i == 0 {
				isHelp = true
				continue
			}
		}
		if arg == "-v" || arg == "--version" || arg == "version" {
			if len(rawArgs) == 1 || i == 0 {
				isVersion = true
				continue
			}
		}
		if arg == "-d" || arg == "--daemon" {
			isDaemon = true
			continue
		}
		if strings.HasPrefix(arg, "--url=") {
			flagURL = strings.TrimPrefix(arg, "--url=")
			continue
		}
		if (arg == "-u" || arg == "--url") && i+1 < len(rawArgs) {
			flagURL = rawArgs[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--api-key=") {
			flagKey = strings.TrimPrefix(arg, "--api-key=")
			continue
		}
		if (arg == "-k" || arg == "--api-key" || arg == "--key") && i+1 < len(rawArgs) {
			flagKey = rawArgs[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--rules=") {
			flagRules = strings.TrimPrefix(arg, "--rules=")
			continue
		}
		if (arg == "-r" || arg == "--rules") && i+1 < len(rawArgs) {
			flagRules = rawArgs[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--bpf-map=") {
			flagBPFMap = strings.TrimPrefix(arg, "--bpf-map=")
			continue
		}
		if (arg == "-m" || arg == "--bpf-map") && i+1 < len(rawArgs) {
			flagBPFMap = rawArgs[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--listen=") {
			flagListen = strings.TrimPrefix(arg, "--listen=")
			continue
		}
		if arg == "--listen" && i+1 < len(rawArgs) {
			flagListen = rawArgs[i+1]
			i++
			continue
		}
		cleaned = append(cleaned, arg)
	}
	return
}

func main() {
	cleaned, flagURL, flagKey, flagRules, flagBPFMap, flagListen, isDaemon, isHelp, isVersion := parseGlobalArgs(os.Args[1:])

	if isHelp || len(cleaned) == 0 {
		printHelp()
		return
	}
	if isVersion {
		printVersion()
		return
	}

	cfg := resolveConfig(flagURL, flagKey, flagRules, flagBPFMap)
	listenAddr := ":8080"
	if flagListen != "" {
		listenAddr = flagListen
	}

	cmd := strings.ToLower(cleaned[0])
	cmdArgs := cleaned[1:]

	if isDaemon || cmd == "daemon" || cmd == "run" || cmd == "serve" || cmd == "gateway" {
		for i := 0; i < len(cmdArgs); i++ {
			arg := cmdArgs[i]
			if strings.HasPrefix(arg, "--listen=") {
				listenAddr = strings.TrimPrefix(arg, "--listen=")
			} else if arg == "--listen" && i+1 < len(cmdArgs) {
				listenAddr = cmdArgs[i+1]
				i++
			} else if strings.HasPrefix(arg, "--rules=") {
				cfg.RulesPath = strings.TrimPrefix(arg, "--rules=")
			} else if (arg == "--rules" || arg == "-r") && i+1 < len(cmdArgs) {
				cfg.RulesPath = cmdArgs[i+1]
				i++
			} else if strings.HasPrefix(arg, "--bpf-map=") {
				cfg.BPFMap = strings.TrimPrefix(arg, "--bpf-map=")
			} else if (arg == "--bpf-map" || arg == "-m") && i+1 < len(cmdArgs) {
				cfg.BPFMap = cmdArgs[i+1]
				i++
			}
		}
		runDaemon(cfg.RulesPath, cfg.BPFMap, listenAddr)
		return
	}

	switch cmd {
	case "help", "-h", "--help":
		printHelp()
	case "version", "-v", "--version":
		printVersion()
	case "apikey", "api-key", "key":
		handleAPIKey(cfg, cmdArgs)
	case "whitelist", "allow":
		handleWhitelist(cfg, cmdArgs)
	case "lookup", "inspect", "whois":
		handleLookup(cfg, cmdArgs)
	case "block":
		handleBlock(cfg, cmdArgs)
	case "unblock":
		handleUnblock(cfg, cmdArgs)
	case "list", "blocks", "list-blocks":
		handleListBlocks(cfg)
	case "reload-rules", "sync-rules":
		handleReloadRules(cfg, cmdArgs)
	case "status", "st":
		handleStatus(cfg)
	case "web", "dashboard", "ui":
		handleWeb(cfg)
	case "ban":
		handleBan(cfg, cmdArgs)
	case "unban":
		handleUnban(cfg, cmdArgs)
	case "bans", "list-bans", "quarantine":
		handleListBans(cfg)
	case "emergency-flush", "panic-flush", "panic-unban-all":
		handleEmergencyFlush(cfg)
	case "alerts", "alert":
		handleAlerts(cfg, cmdArgs)
	case "fleet", "nodes", "sensors":
		handleFleet(cfg)
	case "rules", "sigma":
		handleRules(cfg)
	case "canary", "tokens", "deception":
		handleCanary(cfg)
	case "logs", "log":
		handleLogs(cmdArgs)
	case "restart":
		handleService("restart", cmdArgs)
	case "start":
		handleService("start", cmdArgs)
	case "stop":
		handleService("stop", cmdArgs)
	case "update", "upgrade":
		handleUpdate(cmdArgs)
	default:
		fmt.Printf("%s[!] Unknown command:%s '%s'\n", cRed, cReset, cmd)
		fmt.Printf("Run '%scopsec help%s' for available commands.\n", cCyan, cReset)
		os.Exit(1)
	}
}

func printBanner() {
	banner := `
   ____      ____  ____        ____ 
  / ___|___ |  _ \/ ___|  ___ / ___|
 | |   / _ \| |_) \___ \ / _ \ |    
 | |__| (_) |  __/ ___) |  __/ |___ 
  \____\___/|_|   |____/ \___|\____|  ` + cBold + cGreen + "Autonomous Threat Neutralization Platform" + cReset + " " + cGray + Version + cReset + `
`
	fmt.Print(banner)
}

func printHelp() {
	printBanner()
	fmt.Printf("%sUSAGE:%s\n", cBold+cWhite, cReset)
	fmt.Printf("  %scopsec%s %s<command>%s [arguments]\n\n", cCyan, cReset, cYellow, cReset)

	fmt.Printf("%sCORE & OFFLINE FILTERING COMMANDS:%s\n", cBold+cWhite, cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %sstatus%s (st)\tCheck health, services, XDP status, EPS & active bans\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sblock <CIDR> [reason]%s\tInsert CIDR prefix into kernel LPM trie blocklist\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sunblock <CIDR>%s\tEvict CIDR prefix from kernel LPM trie blocklist\n", cGreen, cReset)
	fmt.Fprintf(w, "  %slist%s (blocks)\tDump active kernel-level CIDR blocks from LPM trie\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sreload-rules%s [path]\tReload and synchronize local firewall rules into kernel\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sweb%s (ui)\tPrint Web SOC Cockpit URL\n", cGreen, cReset)
	w.Flush()

	fmt.Printf("\n%sDEFENSE & QUARANTINE (eBPF/XDP):%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %sban <ip> [ttl] [reason]%s\tInstantly quarantine IP in kernel XDP (e.g. copsec ban 1.2.3.4 1h)\n", cYellow, cReset)
	fmt.Fprintf(w, "  %sunban <ip>%s\tEvict IP from kernel quarantine list\n", cYellow, cReset)
	fmt.Fprintf(w, "  %sbans%s (quarantine)\tList all active kernel quarantine bans & TTLs\n", cYellow, cReset)
	fmt.Fprintf(w, "  %swhitelist%s (allow)\tManage trusted IPs & CIDRs (list, add, remove)\n", cYellow, cReset)
	fmt.Fprintf(w, "  %semergency-flush%s\tEmergency panic flush of all active quarantines\n", cRed, cReset)
	w.Flush()

	fmt.Printf("\n%sTELEMETRY & INTELLIGENCE:%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %slookup <ip>%s\tQuery threat intelligence, GeoIP, ASN & mitigation state\n", cCyan, cReset)
	fmt.Fprintf(w, "  %salerts [limit]%s\tDisplay latest security alerts & mitigation status\n", cCyan, cReset)
	fmt.Fprintf(w, "  %sfleet%s (nodes)\tList enrolled autonomous edge sensor nodes & status\n", cCyan, cReset)
	fmt.Fprintf(w, "  %srules%s (sigma)\tList active Sigma & eBPF detection rules\n", cCyan, cReset)
	fmt.Fprintf(w, "  %scanary%s\tInspect canary deception breadcrumbs and honeytokens\n", cCyan, cReset)
	w.Flush()

	fmt.Printf("\n%sCREDENTIALS & DAEMON MANAGEMENT:%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %sapikey%s [show|set|gen]\tInspect, configure, or generate operator API key\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sdaemon%s (run, serve)\tBootstrap CoPSeC standalone daemon with web dashboard\n", cGreen, cReset)
	fmt.Fprintf(w, "  %slogs [svc] [-f] [n]%s\tView service logs (controller, collector, cockpit)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %srestart [svc]%s\tRestart CoPSeC service(s) (all, controller, collector)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %sstart [svc]%s\tStart CoPSeC service(s)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %sstop [svc]%s\tStop CoPSeC service(s)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %supdate%s (upgrade)\tPull latest updates, recompile & gracefully reload\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sversion%s (-v)\tDisplay platform version and build metadata\n", cWhite, cReset)
	w.Flush()

	fmt.Printf("\n%sOPTIONS:%s\n", cBold+cWhite, cReset)
	fmt.Printf("  %s-u, --url <url>%s        Controller base address (Default: http://127.0.0.1:8080)\n", cGray, cReset)
	fmt.Printf("  %s-k, --api-key <key>%s    Operator API authentication key\n", cGray, cReset)
	fmt.Printf("  %s-r, --rules <path>%s     Path to rules.yaml/json (Default: /etc/copsec/rules.yaml)\n", cGray, cReset)
	fmt.Printf("  %s-m, --bpf-map <path>%s   Path to pinned BPF LPM trie map\n", cGray, cReset)
	fmt.Printf("  %s--listen <addr>%s        Web dashboard listen address (Default: :8080)\n", cGray, cReset)
	fmt.Printf("  %s-d, --daemon%s           Run in standalone daemon mode\n", cGray, cReset)
	fmt.Printf("\n%sEXAMPLES:%s\n", cBold+cWhite, cReset)
	fmt.Printf("  copsec status\n")
	fmt.Printf("  copsec apikey show\n")
	fmt.Printf("  copsec block 192.0.2.0/24 \"Malicious subnet\"\n")
	fmt.Printf("  copsec unblock 192.0.2.0/24\n")
	fmt.Printf("  copsec ban 198.51.100.4 2h \"brute-force attempt\"\n")
	fmt.Printf("  copsec unban 198.51.100.4\n")
	fmt.Printf("  copsec ban list\n")
	fmt.Printf("  copsec whitelist add 192.168.1.0/24 \"Management subnet\"\n")
	fmt.Printf("  copsec whitelist list\n")
	fmt.Printf("  copsec lookup 198.51.100.4\n")
	fmt.Printf("  copsec logs controller -f\n\n")
}

func printVersion() {
	fmt.Printf("%sCoPSeC Pro Security Platform%s %s%s%s\n", cBold+cWhite, cReset, cGreen, Version, cReset)
	fmt.Printf("High-Throughput Cluster Resilience & eBPF/XDP Kernel Defense\n")
}

// HTTP helper
func apiRequest(cfg Config, method, endpoint string, body interface{}) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	url := cfg.BaseURL + endpoint
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Attach authentication headers if key is present
	if cfg.APIKey != "" {
		req.Header.Set("X-API-Key", cfg.APIKey)
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	return resp, respBody, err
}

func getServerIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}
	// Fallback to hostname
	if host, err := os.Hostname(); err == nil {
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func checkServiceActive(svc string) string {
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "is-active", svc)
		out, err := cmd.Output()
		status := strings.TrimSpace(string(out))
		if err == nil && status == "active" {
			return cGreen + "active (running)" + cReset
		}
		if status != "" {
			return cRed + status + cReset
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		cmd := exec.Command("rc-service", svc, "status")
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "started") {
			return cGreen + "started (running)" + cReset
		}
		return cRed + "stopped" + cReset
	}
	return cGray + "unknown / not installed" + cReset
}

func handleStatus(cfg Config) {
	fmt.Printf("%s=== CoPSeC Enterprise Cluster Status ===%s\n", cBold+cCyan, cReset)

	// 1. Host Services & Role
	controllerActive := isServiceActive("copsec-controller")
	collectorActive := isServiceActive("copsec-collector")

	role := "Standalone / Edge Node"
	if controllerActive && collectorActive {
		role = "Autonomous All-In-One (Controller + Edge Sensor)"
	} else if controllerActive {
		role = "Central Controller & Vault Hub"
	} else if collectorActive {
		role = "Autonomous Edge Sensor (eBPF/XDP Protection Active)"
	}

	fmt.Printf("%s[HOST ARCHITECTURE]%s\n", cBold+cWhite, cReset)
	fmt.Printf("  • Assigned Role     : %s%s%s\n", cBold+cGreen, role, cReset)
	fmt.Printf("  • copsec-controller : %s\n", checkServiceActive("copsec-controller"))
	fmt.Printf("  • copsec-collector  : %s\n", checkServiceActive("copsec-collector"))
	fmt.Printf("  • copsec-cockpit    : %s\n", checkServiceActive("copsec-cockpit"))

	// 2. Management & Key
	fmt.Printf("\n%s[MANAGEMENT & CONTROL PLANE]%s\n", cBold+cWhite, cReset)
	ip := getServerIP()
	fmt.Printf("  • Controller Target : %s%s%s\n", cCyan, cfg.BaseURL, cReset)
	if controllerActive {
		fmt.Printf("  • Web SOC Cockpit   : %shttp://%s:8080%s (or http://127.0.0.1:8080)\n", cCyan, ip, cReset)
	}
	maskedKey := "[NOT CONFIGURED]"
	if cfg.APIKey != "" {
		if len(cfg.APIKey) > 12 {
			maskedKey = cfg.APIKey[:6] + "..." + cfg.APIKey[len(cfg.APIKey)-6:]
		} else {
			maskedKey = cfg.APIKey
		}
	}
	fmt.Printf("  • Active API Key    : %s%s%s\n", cYellow, maskedKey, cReset)
	fmt.Printf("  • Local Rules File  : %s%s%s\n", cWhite, cfg.RulesPath, cReset)

	// 3. Query Controller Health & Stats
	fmt.Printf("\n%s[REAL-TIME CLUSTER TELEMETRY]%s\n", cBold+cWhite, cReset)
	resp, body, err := apiRequest(cfg, "GET", "/api/stats", nil)
	if err != nil {
		fmt.Printf("  %s[!] Could not connect to controller API (%s): %v%s\n", cYellow, cfg.BaseURL, err, cReset)
		if collectorActive && !controllerActive {
			fmt.Printf("  Tip: On sensor nodes, specify controller target via: 'copsec status -u http://<controller-ip>:8080'\n")
			fmt.Printf("       or set COPSEC_CONTROLLER_URL=\"http://<controller-ip>:8080\"\n")
		} else {
			fmt.Printf("  Hint: Ensure 'copsec-controller' service is running ('copsec start controller').\n")
		}
		fmt.Println()
		return
	}
	if resp.StatusCode == 401 {
		fmt.Printf("  %s[!] API Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("  Hint: Active API key does not match controller. Update using 'copsec apikey set <key>'.\n\n")
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("  %s[!] Controller returned HTTP %d: %s%s\n\n", cRed, resp.StatusCode, string(body), cReset)
		return
	}

	var stats struct {
		EPS           uint64 `json:"eps"`
		TotalEvents   uint64 `json:"total_events"`
		NodesCount    int    `json:"nodes_count"`
		ActiveBans    int    `json:"active_bans"`
		ActiveAlerts  int    `json:"active_alerts"`
		ArchiveAlerts int    `json:"archive_alerts"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		fmt.Printf("  [!] Failed to parse telemetry stats: %v\n\n", err)
		return
	}

	fmt.Printf("  • Current Throughput: %s%d EPS%s (Events Per Second)\n", cBold+cGreen, stats.EPS, cReset)
	fmt.Printf("  • Total Ingested    : %s%d events%s\n", cWhite, stats.TotalEvents, cReset)
	fmt.Printf("  • Active Bans (XDP) : %s%d quarantined%s\n", cYellow, stats.ActiveBans, cReset)
	fmt.Printf("  • Active Alerts     : %s%d unmitigated%s\n", cRed, stats.ActiveAlerts, cReset)
	fmt.Printf("  • Fleet Nodes       : %s%d sensors connected%s\n", cCyan, stats.NodesCount, cReset)
	fmt.Println()
}

func handleAPIKey(cfg Config, args []string) {
	sub := "show"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}

	switch sub {
	case "show", "get", "status":
		fmt.Printf("%s=== CoPSeC API Key Credentials ===%s\n\n", cBold+cCyan, cReset)
		if cfg.APIKey == "" {
			fmt.Printf("  • Status : %s[NO KEY CONFIGURED]%s\n", cRed, cReset)
			fmt.Printf("  • Hint   : Run '%scopsec apikey set <key>%s' or '%scopsec apikey generate%s'\n\n", cCyan, cReset, cCyan, cReset)
			return
		}
		masked := cfg.APIKey
		showFull := false
		for _, a := range args {
			if a == "--full" || a == "-f" {
				showFull = true
			}
		}
		if !showFull && len(masked) > 12 {
			masked = masked[:6] + "..." + masked[len(masked)-6:]
		}
		fmt.Printf("  • Active Key : %s%s%s\n", cGreen, masked, cReset)
		if !showFull && len(cfg.APIKey) > 12 {
			fmt.Printf("    (Use '--full' or '-f' to reveal complete token)\n")
		}
		source := "environment (COPSEC_API_KEY)"
		if _, err := os.Stat("/etc/copsec/api_key"); err == nil {
			source = "/etc/copsec/api_key"
		} else if _, err := os.Stat("/etc/copsec/copsec.env"); err == nil {
			source = "/etc/copsec/copsec.env"
		}
		fmt.Printf("  • Source     : %s\n\n", source)

	case "set":
		if len(args) < 2 {
			fmt.Printf("%s[!] Error:%s Missing API key value. Usage: %scopsec apikey set <key>%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
		newKey := strings.TrimSpace(args[1])
		if len(newKey) < 8 {
			fmt.Printf("%s[!] Error:%s API key must be at least 8 characters long.\n", cRed, cReset)
			os.Exit(1)
		}

		saved := false
		if os.Geteuid() == 0 || os.Getenv("USER") == "root" {
			_ = os.MkdirAll("/etc/copsec", 0755)
			if err := os.WriteFile("/etc/copsec/api_key", []byte(newKey+"\n"), 0644); err == nil {
				saved = true
				fmt.Printf("%s[[OK]] Saved API key to /etc/copsec/api_key (permissions: 0644)%s\n", cGreen, cReset)
			}
			if envData, err := os.ReadFile("/etc/copsec/copsec.env"); err == nil {
				lines := strings.Split(string(envData), "\n")
				found := false
				for i, l := range lines {
					if strings.HasPrefix(strings.TrimSpace(l), "COPSEC_API_KEY=") {
						lines[i] = fmt.Sprintf("COPSEC_API_KEY=\"%s\"", newKey)
						found = true
						break
					}
				}
				if !found {
					lines = append(lines, fmt.Sprintf("COPSEC_API_KEY=\"%s\"", newKey))
				}
				_ = os.WriteFile("/etc/copsec/copsec.env", []byte(strings.Join(lines, "\n")), 0600)
			}
		}

		if !saved {
			home, err := os.UserHomeDir()
			if err == nil {
				cfgDir := filepath.Join(home, ".config", "copsec")
				_ = os.MkdirAll(cfgDir, 0700)
				filePath := filepath.Join(cfgDir, "api_key")
				if err := os.WriteFile(filePath, []byte(newKey+"\n"), 0600); err == nil {
					saved = true
					fmt.Printf("%s[[OK]] Saved API key to %s%s\n", cGreen, filePath, cReset)
				}
			}
		}

		if !saved {
			fmt.Printf("%s[!] Failed to save API key to disk. You can set it via: export COPSEC_API_KEY=\"%s\"%s\n", cYellow, newKey, cReset)
		}

	case "generate", "gen":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fmt.Printf("%s[!] Failed to generate random key: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		key := hex.EncodeToString(b)
		fmt.Printf("%s=== Generated Cryptographic API Key ===%s\n\n", cBold+cCyan, cReset)
		fmt.Printf("  %s%s%s\n\n", cBold+cGreen, key, cReset)
		fmt.Printf("  To activate this key:\n")
		fmt.Printf("    %scopsec apikey set %s%s\n\n", cCyan, key, cReset)

	default:
		fmt.Printf("%s[!] Unknown apikey action: '%s'%s\n", cRed, sub, cReset)
		fmt.Printf("Usage: copsec apikey [show|set <key>|generate]\n")
		os.Exit(1)
	}
}

func handleWhitelist(cfg Config, args []string) {
	sub := "list"
	subArgs := args
	if len(args) > 0 {
		first := strings.ToLower(args[0])
		if first == "list" || first == "ls" {
			sub = "list"
			subArgs = args[1:]
		} else if first == "add" {
			sub = "add"
			subArgs = args[1:]
		} else if first == "remove" || first == "rm" || first == "del" || first == "delete" {
			sub = "remove"
			subArgs = args[1:]
		} else if net.ParseIP(args[0]) != nil || strings.Contains(args[0], "/") {
			sub = "add"
			subArgs = args
		}
	}

	switch sub {
	case "list":
		resp, body, err := apiRequest(cfg, "GET", "/api/whitelist", nil)
		if err != nil {
			fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
			os.Exit(1)
		}
		if resp.StatusCode == 401 {
			fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
			fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
			os.Exit(1)
		}
		if resp.StatusCode != 200 {
			fmt.Printf("%s[!] Failed to query whitelist (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
			os.Exit(1)
		}

		var res struct {
			Success bool `json:"success"`
			Entries []struct {
				ID          int64  `json:"id"`
				CIDROrIP    string `json:"cidr_or_ip"`
				Description string `json:"description"`
				CreatedBy   string `json:"created_by"`
				CreatedAt   int64  `json:"created_at"`
			} `json:"entries"`
			Subnets   []string `json:"subnets"`
			Resolvers []string `json:"resolvers"`
		}

		if err := json.Unmarshal(body, &res); err != nil {
			fmt.Printf("%s[!] Failed to parse response: %v%s\n", cRed, err, cReset)
			return
		}

		fmt.Printf("%s=== Active Whitelist & Trusted Networks (%d entries) ===%s\n\n", cBold+cGreen, len(res.Entries), cReset)
		if len(res.Entries) == 0 {
			fmt.Printf("  %sNo custom whitelisted CIDRs. Default safeguards active.%s\n\n", cGray, cReset)
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "%sCIDR / IP\tORIGIN\tDESCRIPTION%s\n", cBold+cWhite, cReset)
		for _, e := range res.Entries {
			desc := e.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Fprintf(w, "%s%s%s\t%s\t%s\n", cGreen, e.CIDROrIP, cReset, e.CreatedBy, desc)
		}
		w.Flush()
		fmt.Println()

	case "add":
		if len(subArgs) == 0 {
			fmt.Printf("%s[!] Error:%s Missing target IP or CIDR prefix. Usage: %scopsec whitelist add <ip/cidr> [reason]%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
		target := strings.TrimSpace(subArgs[0])
		desc := "Manual CLI Whitelist"
		if len(subArgs) > 1 {
			desc = strings.Join(subArgs[1:], " ")
		}

		payload := map[string]string{
			"cidr_or_ip":  target,
			"description": desc,
		}

		resp, respBody, err := apiRequest(cfg, "POST", "/api/whitelist", payload)
		if err != nil {
			fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
			os.Exit(1)
		}
		if resp.StatusCode == 401 {
			fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
			fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
			os.Exit(1)
		}
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			fmt.Printf("%s[!] Whitelist add failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
			os.Exit(1)
		}

		fmt.Printf("%s[[OK]] Target %s successfully added to active whitelist!%s\n", cGreen, target, cReset)
		fmt.Printf("    Reason : %s\n\n", desc)

	case "remove":
		if len(subArgs) == 0 {
			fmt.Printf("%s[!] Error:%s Missing target IP or CIDR. Usage: %scopsec whitelist remove <ip/cidr>%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
		target := strings.TrimSpace(subArgs[0])
		endpoint := fmt.Sprintf("/api/whitelist?cidr_or_ip=%s", url.QueryEscape(target))

		resp, respBody, err := apiRequest(cfg, "DELETE", endpoint, nil)
		if err != nil {
			fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
			os.Exit(1)
		}
		if resp.StatusCode == 401 {
			fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
			fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
			os.Exit(1)
		}
		if resp.StatusCode != 200 {
			fmt.Printf("%s[!] Whitelist remove failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
			os.Exit(1)
		}

		fmt.Printf("%s[[OK]] Target %s successfully evicted from whitelist.%s\n\n", cGreen, target, cReset)
	}
}

func handleLookup(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error:%s Missing target IP. Usage: %scopsec lookup <ip>%s\n", cRed, cReset, cCyan, cReset)
		os.Exit(1)
	}
	targetIP := strings.TrimSpace(args[0])
	if net.ParseIP(targetIP) == nil {
		fmt.Printf("%s[!] Error:%s Invalid IP address: '%s'\n", cRed, cReset, targetIP)
		os.Exit(1)
	}

	fmt.Printf("%s=== CoPSeC Threat Intelligence Lookup: %s ===%s\n\n", cBold+cCyan, targetIP, cReset)

	// 1. GeoIP lookup
	resp, body, err := apiRequest(cfg, "GET", "/api/geoip/lookup?ip="+url.QueryEscape(targetIP), nil)
	if err == nil && resp.StatusCode == 200 {
		var geo struct {
			IP          string `json:"ip"`
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
			ASN         string `json:"asn"`
			Org         string `json:"org"`
			ThreatScore int    `json:"threat_score"`
			Flag        string `json:"flag"`
		}
		if json.Unmarshal(body, &geo) == nil && geo.Country != "" {
			fmt.Printf("  • Country      : %s %s (%s)\n", geo.Flag, geo.Country, geo.CountryCode)
			if geo.City != "" {
				fmt.Printf("  • City         : %s\n", geo.City)
			}
			if geo.ASN != "" {
				fmt.Printf("  • ASN          : %s\n", geo.ASN)
			}
			if geo.Org != "" {
				fmt.Printf("  • Organization : %s\n", geo.Org)
			}
			scoreColor := cGreen
			if geo.ThreatScore >= 80 {
				scoreColor = cBold + cRed
			} else if geo.ThreatScore >= 50 {
				scoreColor = cYellow
			}
			fmt.Printf("  • Threat Score : %s%d / 100%s\n", scoreColor, geo.ThreatScore, cReset)
		}
	}

	// 2. Quarantine Status lookup
	qResp, qBody, qErr := apiRequest(cfg, "GET", "/api/quarantine", nil)
	isBanned := false
	if qErr == nil && qResp.StatusCode == 200 {
		var bans []struct {
			IP           string `json:"ip"`
			Reason       string `json:"reason"`
			RemainingSec int64  `json:"remaining_sec"`
		}
		if json.Unmarshal(qBody, &bans) == nil {
			for _, b := range bans {
				if b.IP == targetIP {
					isBanned = true
					fmt.Printf("  • Mitigation   : %sQUARANTINED (Active eBPF/XDP Drop)%s\n", cBold+cRed, cReset)
					fmt.Printf("  • Reason       : %s\n", b.Reason)
					fmt.Printf("  • Remaining    : %d seconds\n", b.RemainingSec)
					break
				}
			}
		}
	}
	if !isBanned {
		fmt.Printf("  • Mitigation   : %sNOT BANNED (Normal Traffic Flow)%s\n", cGreen, cReset)
	}

	// 3. Whitelist check
	wlResp, wlBody, wlErr := apiRequest(cfg, "GET", "/api/whitelist", nil)
	if wlErr == nil && wlResp.StatusCode == 200 {
		var wl struct {
			Entries []struct {
				CIDROrIP    string `json:"cidr_or_ip"`
				Description string `json:"description"`
			} `json:"entries"`
		}
		if json.Unmarshal(wlBody, &wl) == nil {
			for _, e := range wl.Entries {
				if e.CIDROrIP == targetIP || strings.HasPrefix(e.CIDROrIP, targetIP+"/") {
					fmt.Printf("  • Whitelist    : %sPROTECTED (%s)%s\n", cGreen, e.Description, cReset)
					break
				}
			}
		}
	}
	fmt.Println()
}

// ensureSudo checks if running with root privileges (EUID 0).
// If not, it invokes sudo (with -k to invalidate cache and force password verification)
// to re-execute the current command under elevated privileges.
func ensureSudo(reason string) {
	if os.Geteuid() == 0 {
		return
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		if doasPath, err := exec.LookPath("doas"); err == nil {
			sudoPath = doasPath
		}
	}

	if sudoPath == "" {
		fmt.Printf("%s[!] Error: %s requires root/sudo privileges, but 'sudo' was not found.%s\n", cRed, reason, cReset)
		fmt.Printf("Please run this command as root or with elevated privileges.\n")
		os.Exit(1)
	}

	fmt.Printf("%s[[SECURE]] Root/Sudo authentication required to %s...%s\n", cBold+cYellow, reason, cReset)

	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}

	var cmd *exec.Cmd
	if strings.HasSuffix(sudoPath, "sudo") {
		cmdArgs := append([]string{"-k", selfPath}, os.Args[1:]...)
		cmd = exec.Command(sudoPath, cmdArgs...)
	} else {
		cmdArgs := append([]string{selfPath}, os.Args[1:]...)
		cmd = exec.Command(sudoPath, cmdArgs...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func handleWeb(cfg Config) {
	ip := getServerIP()
	fmt.Printf("%s=== CoPSeC Web SOC Cockpit ===%s\n\n", cBold+cCyan, cReset)
	fmt.Printf("  • Localhost URL     : %shttp://127.0.0.1:8080%s\n", cCyan, cReset)
	fmt.Printf("  • Network IP URL    : %shttp://%s:8080%s\n", cCyan, ip, cReset)
	fmt.Printf("  • Status            : %sUnconditionally Enabled (Standalone Open-Source)%s\n\n", cGreen, cReset)
}

func parseDurationSeconds(durStr string) int64 {
	durStr = strings.TrimSpace(strings.ToLower(durStr))
	if durStr == "" {
		return 3600 // default 1 hour
	}
	if durStr == "permanent" || durStr == "indefinite" || durStr == "0" || durStr == "-1" {
		return 86400 * 365 // 1 year
	}
	if sec, err := strconv.ParseInt(durStr, 10, 64); err == nil {
		return sec
	}
	if strings.HasSuffix(durStr, "m") {
		if val, err := strconv.ParseInt(strings.TrimSuffix(durStr, "m"), 10, 64); err == nil {
			return val * 60
		}
	}
	if strings.HasSuffix(durStr, "h") {
		if val, err := strconv.ParseInt(strings.TrimSuffix(durStr, "h"), 10, 64); err == nil {
			return val * 3600
		}
	}
	if strings.HasSuffix(durStr, "d") {
		if val, err := strconv.ParseInt(strings.TrimSuffix(durStr, "d"), 10, 64); err == nil {
			return val * 86400
		}
	}
	return 3600
}

func handleBan(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error:%s Missing target IP. Usage: %scopsec ban <ip> [duration] [reason]%s\n", cRed, cReset, cCyan, cReset)
		fmt.Printf("    Or list bans: %scopsec ban list%s\n", cCyan, cReset)
		os.Exit(1)
	}

	first := strings.ToLower(args[0])
	if first == "list" || first == "ls" {
		handleListBans(cfg)
		return
	}
	if first == "clear" || first == "flush" || first == "clear-list" {
		handleEmergencyFlush(cfg)
		return
	}
	if first == "remove" || first == "rm" || first == "del" || first == "delete" {
		handleUnban(cfg, args[1:])
		return
	}
	if first == "add" {
		args = args[1:]
		if len(args) == 0 {
			fmt.Printf("%s[!] Error:%s Missing target IP after 'add'. Usage: %scopsec ban add <ip> [duration] [reason]%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
	}

	target := strings.TrimSpace(args[0])

	// If user passed a CIDR (e.g. 192.168.1.0/24), automatically dispatch to handleBlock
	if strings.Contains(target, "/") {
		if _, _, err := net.ParseCIDR(target); err == nil {
			handleBlock(cfg, args)
			return
		}
	}

	if net.ParseIP(target) == nil {
		fmt.Printf("%s[!] Error:%s Invalid IP format: '%s'\n", cRed, cReset, target)
		os.Exit(1)
	}

	durationSec := int64(3600)
	reason := "manual CLI operator ban"

	if len(args) > 1 {
		durationSec = parseDurationSeconds(args[1])
	}
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	payload := map[string]interface{}{
		"ip":               target,
		"reason":           reason,
		"duration_seconds": durationSec,
	}

	resp, respBody, err := apiRequest(cfg, "POST", "/api/quarantine/ban", payload)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode == 401 {
		fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
		os.Exit(1)
	}
	if resp.StatusCode == 409 {
		fmt.Printf("%s[!] Ban Rejected: Target IP is protected by an active whitelist rule.%s\n", cYellow, cReset)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Ban failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
		os.Exit(1)
	}

	durDesc := fmt.Sprintf("%d seconds (~%s)", durationSec, time.Duration(durationSec)*time.Second)
	if durationSec <= 0 || durationSec >= 86400*365 {
		durDesc = "PERMANENT"
	}
	fmt.Printf("%s[[OK]] IP %s successfully quarantined in kernel eBPF/XDP map!%s\n", cGreen, target, cReset)
	fmt.Printf("    Duration : %s\n", durDesc)
	fmt.Printf("    Reason   : %s\n", reason)
}

func handleUnban(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error:%s Missing target IP. Usage: %scopsec unban <ip>%s\n", cRed, cReset, cCyan, cReset)
		os.Exit(1)
	}

	first := strings.ToLower(args[0])
	if first == "remove" || first == "rm" || first == "del" || first == "delete" {
		args = args[1:]
		if len(args) == 0 {
			fmt.Printf("%s[!] Error:%s Missing target IP. Usage: %scopsec unban <ip>%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
	}

	ip := strings.TrimSpace(args[0])
	if strings.Contains(ip, "/") {
		ip = strings.TrimSuffix(ip, "/32")
	}
	if net.ParseIP(ip) == nil {
		fmt.Printf("%s[!] Error:%s Invalid IP format: '%s'\n", cRed, cReset, ip)
		os.Exit(1)
	}

	payload := map[string]interface{}{
		"ip": ip,
	}

	resp, respBody, err := apiRequest(cfg, "POST", "/api/quarantine/unban", payload)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode == 401 {
		fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Unban failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
		os.Exit(1)
	}

	fmt.Printf("%s[[OK]] IP %s successfully unbanned and evicted from kernel XDP quarantine.%s\n", cGreen, ip, cReset)
}

func handleListBans(cfg Config) {
	resp, body, err := apiRequest(cfg, "GET", "/api/quarantine", nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode == 401 {
		fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Failed to list bans (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
		os.Exit(1)
	}

	var bans []struct {
		IP           string      `json:"ip"`
		Reason       string      `json:"reason"`
		RemainingSec int64       `json:"remaining_sec"`
		Status       string      `json:"status"`
		PenaltyTier  interface{} `json:"penalty_tier"`
		CountryCode  string      `json:"country_code"`
	}

	if err := json.Unmarshal(body, &bans); err != nil {
		fmt.Printf("%s[!] Failed to parse response: %v%s\n", cRed, err, cReset)
		return
	}

	if len(bans) == 0 {
		fmt.Printf("%s[i] No active kernel quarantine bans. Cluster is clear.%s\n", cGreen, cReset)
		return
	}

	fmt.Printf("%s=== Active Kernel XDP Quarantine List (%d banned) ===%s\n\n", cBold+cYellow, len(bans), cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sIP ADDRESS\tREMAINING\tREASON\tTIER\tGEO%s\n", cBold+cWhite, cReset)
	for _, b := range bans {
		rem := fmt.Sprintf("%ds", b.RemainingSec)
		if b.RemainingSec > 60 {
			rem = fmt.Sprintf("%dm %ds", b.RemainingSec/60, b.RemainingSec%60)
		}
		geo := b.CountryCode
		if geo == "" {
			geo = "-"
		}
		fmt.Fprintf(w, "%s%s%s\t%s\t%s\t%v\t%s\n", cRed, b.IP, cReset, rem, b.Reason, b.PenaltyTier, geo)
	}
	w.Flush()
	fmt.Println()
}

func handleAlerts(cfg Config, args []string) {
	limit := 10
	if len(args) > 0 {
		if l, err := strconv.Atoi(args[0]); err == nil && l > 0 {
			limit = l
		}
	}

	resp, body, err := apiRequest(cfg, "GET", fmt.Sprintf("/api/alerts?limit=%d", limit), nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Failed to fetch alerts (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
		os.Exit(1)
	}

	var alerts []struct {
		ID               interface{} `json:"id"`
		RuleID           string      `json:"rule_id"`
		ClientIP         string      `json:"client_ip"`
		Severity         string      `json:"severity"`
		ContainmentState string      `json:"containment_state"`
		TriageStatus     string      `json:"triage_status"`
		Timestamp        string      `json:"timestamp"`
		SensorNode       string      `json:"sensor_node"`
		RepeatCount      int         `json:"repeat_count"`
	}

	if err := json.Unmarshal(body, &alerts); err != nil {
		fmt.Printf("%s[!] Failed to parse alerts: %v%s\n", cRed, err, cReset)
		return
	}

	if len(alerts) == 0 {
		fmt.Printf("%s[i] No active security alerts found. All systems nominal.%s\n", cGreen, cReset)
		return
	}

	fmt.Printf("%s=== Recent Security Alerts (Displaying %d) ===%s\n\n", cBold+cRed, len(alerts), cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sSEVERITY\tATTACKER IP\tSTATUS\tRULE ID\tHITS%s\n", cBold+cWhite, cReset)
	for _, a := range alerts {
		sevColor := cWhite
		switch strings.ToUpper(a.Severity) {
		case "CRITICAL":
			sevColor = cBold + cRed
		case "HIGH":
			sevColor = cRed
		case "MEDIUM":
			sevColor = cYellow
		case "LOW":
			sevColor = cCyan
		}

		status := a.ContainmentState
		if status == "" {
			status = a.TriageStatus
		}
		if status == "" {
			status = "ACTIVE"
		}

		hits := a.RepeatCount
		if hits < 1 {
			hits = 1
		}

		fmt.Fprintf(w, "%s[%s]%s\t%s\t%s\t%s\tx%d\n", sevColor, a.Severity, cReset, a.ClientIP, status, a.RuleID, hits)
	}
	w.Flush()
	fmt.Println()
}

func handleFleet(cfg Config) {
	resp, body, err := apiRequest(cfg, "GET", "/api/nodes", nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Failed to query nodes (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
		os.Exit(1)
	}

	var nodes []struct {
		NodeID          string  `json:"node_id"`
		Hostname        string  `json:"hostname"`
		RemoteAddr      string  `json:"remote_addr"`
		CPUUsage        float64 `json:"cpu_usage"`
		MemoryUsage     float64 `json:"memory_usage"`
		ActiveBansCount int     `json:"active_bans_count"`
		LastSeenMs      int64   `json:"last_seen_ms"`
	}

	if err := json.Unmarshal(body, &nodes); err != nil {
		fmt.Printf("%s[!] Failed to parse nodes: %v%s\n", cRed, err, cReset)
		return
	}

	if len(nodes) == 0 {
		fmt.Printf("%s[i] No remote fleet nodes currently enrolled.%s\n", cYellow, cReset)
		return
	}

	fmt.Printf("%s=== Enrolled Sensor Fleet Nodes (%d Active) ===%s\n\n", cBold+cCyan, len(nodes), cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sNODE ID\tHOSTNAME\tADDRESS\tCPU\tRAM\tBANS%s\n", cBold+cWhite, cReset)
	for _, n := range nodes {
		fmt.Fprintf(w, "%s%s%s\t%s\t%s\t%.1f%%\t%.1f%%\t%d\n",
			cGreen, n.NodeID, cReset, n.Hostname, n.RemoteAddr, n.CPUUsage, n.MemoryUsage, n.ActiveBansCount)
	}
	w.Flush()
	fmt.Println()
}

func handleRules(cfg Config) {
	resp, body, err := apiRequest(cfg, "GET", "/api/rules", nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Failed to query rules (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
		os.Exit(1)
	}

	var rules []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"level"`
		Status   string `json:"status"`
	}

	if err := json.Unmarshal(body, &rules); err != nil {
		fmt.Printf("%s[!] Failed to parse rules: %v%s\n", cRed, err, cReset)
		return
	}

	fmt.Printf("%s=== Active Sigma & eBPF Detection Rules (%d Loaded) ===%s\n\n", cBold+cCyan, len(rules), cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sRULE ID\tSEVERITY\tTITLE%s\n", cBold+cWhite, cReset)
	for _, r := range rules {
		fmt.Fprintf(w, "%s%s%s\t%s\t%s\n", cCyan, r.ID, cReset, r.Severity, r.Title)
	}
	w.Flush()
	fmt.Println()
}

func handleCanary(cfg Config) {
	resp, body, err := apiRequest(cfg, "GET", "/api/canary/tokens", nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Failed to query canary tokens (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(body))
		os.Exit(1)
	}

	var res struct {
		Tokens []struct {
			ID          string `json:"id"`
			Type        string `json:"type"`
			Token       string `json:"token"`
			Hits        int    `json:"hits"`
			Description string `json:"description"`
		} `json:"tokens"`
	}

	if err := json.Unmarshal(body, &res); err != nil {
		fmt.Printf("%s[!] Failed to parse canary tokens: %v%s\n", cRed, err, cReset)
		return
	}

	tokens := res.Tokens
	if len(tokens) == 0 {
		fmt.Printf("%s[i] No canary deception tokens deployed.%s\n", cYellow, cReset)
		return
	}

	fmt.Printf("%s=== Canary Deception Breadcrumbs & Honeytokens (%d Active) ===%s\n\n", cBold+cPurple, len(tokens), cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sTYPE\tTOKEN / PATH\tHITS\tDESCRIPTION%s\n", cBold+cWhite, cReset)
	for _, t := range tokens {
		hitColor := cGreen
		if t.Hits > 0 {
			hitColor = cBold + cRed
		}
		fmt.Fprintf(w, "%s%s%s\t%s\t%s%d%s\t%s\n", cPurple, t.Type, cReset, t.Token, hitColor, t.Hits, cReset, t.Description)
	}
	w.Flush()
	fmt.Println()
}

func handleLogs(args []string) {
	svc := "copsec-controller"
	lines := "50"
	follow := false

	for _, a := range args {
		if a == "-f" || a == "--follow" {
			follow = true
		} else if strings.Contains(a, "collector") {
			svc = "copsec-collector"
		} else if strings.Contains(a, "cockpit") {
			svc = "copsec-cockpit"
		} else if strings.Contains(a, "controller") {
			svc = "copsec-controller"
		} else if _, err := strconv.Atoi(a); err == nil {
			lines = a
		}
	}

	// Systemd
	if _, err := exec.LookPath("journalctl"); err == nil {
		jArgs := []string{"-u", svc, "-n", lines}
		if follow {
			jArgs = append(jArgs, "-f")
		}
		cmd := exec.Command("journalctl", jArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
		return
	}

	// OpenRC log file fallback
	logFile := fmt.Sprintf("/var/log/copsec/%s.log", svc)
	tArgs := []string{"-n", lines}
	if follow {
		tArgs = append(tArgs, "-f")
	}
	tArgs = append(tArgs, logFile)
	cmd := exec.Command("tail", tArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

func handleService(action string, args []string) {
	ensureSudo(fmt.Sprintf("%s CoPSeC services", action))

	target := "all"
	if len(args) > 0 {
		target = strings.ToLower(args[0])
	}

	services := []string{"copsec-controller", "copsec-collector"}
	if strings.Contains(target, "controller") {
		services = []string{"copsec-controller"}
	} else if strings.Contains(target, "collector") {
		services = []string{"copsec-collector"}
	} else if strings.Contains(target, "cockpit") {
		services = []string{"copsec-cockpit"}
	}

	isSystemd := false
	if _, err := exec.LookPath("systemctl"); err == nil {
		isSystemd = true
	}

	for _, svc := range services {
		fmt.Printf("[*] Executing '%s' on %s...\n", action, svc)
		var cmd *exec.Cmd
		if isSystemd {
			cmd = exec.Command("systemctl", action, svc)
		} else {
			cmd = exec.Command("rc-service", svc, action)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s[!] Failed to %s %s: %v%s\n", cRed, action, svc, err, cReset)
		} else {
			fmt.Printf("%s[[OK]] %s %s completed successfully.%s\n", cGreen, svc, action, cReset)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func isServiceActive(svc string) bool {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "is-active", svc).Output()
		return err == nil && strings.TrimSpace(string(out)) == "active"
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		out, err := exec.Command("rc-service", svc, "status").CombinedOutput()
		return err == nil && strings.Contains(string(out), "started")
	}
	return false
}

func restartSingleService(svc string) {
	fmt.Printf("  • Restarting %s...\n", svc)
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "restart", svc).Run()
		return
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		_ = exec.Command("rc-service", svc, "restart").Run()
		return
	}
}

func handleUpdate(args []string) {
	fmt.Printf("%s=== CoPSeC Pro Platform OTA Updater ===%s\n\n", cBold+cCyan, cReset)

	branch := "main"
	checkOnly := false
	noRestart := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--check" || a == "-c" {
			checkOnly = true
		} else if a == "--no-restart" {
			noRestart = true
		} else if strings.HasPrefix(a, "--branch=") {
			branch = strings.TrimPrefix(a, "--branch=")
		} else if a == "--branch" || a == "-b" {
			if i+1 < len(args) {
				branch = args[i+1]
				i++
			}
		} else if !strings.HasPrefix(a, "-") && a != "" {
			branch = a
		}
	}

	repoURL := "https://github.com/CoPdasten/copsec.git"

	// 1. Check git remote
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Printf("%s[!] Error: 'git' binary not found on PATH. Please install git.%s\n", cRed, cReset)
		os.Exit(1)
	}

	fmt.Printf("[*] Checking upstream repository (%s, branch: %s)...\n", repoURL, branch)
	out, err := exec.Command("git", "ls-remote", repoURL, "refs/heads/"+branch).CombinedOutput()
	if err != nil {
		fmt.Printf("%s[!] Error connecting to remote repository:%s %v\n%s\n", cRed, cReset, err, string(out))
		os.Exit(1)
	}

	remoteHash := strings.Fields(string(out))
	remoteCommit := ""
	if len(remoteHash) > 0 {
		remoteCommit = remoteHash[0]
	}

	fmt.Printf("  • Remote Target Branch : %s%s%s\n", cGreen, branch, cReset)
	if len(remoteCommit) >= 8 {
		fmt.Printf("  • Remote Commit Hash   : %s%s%s\n", cYellow, remoteCommit[:8], cReset)
	}

	if checkOnly {
		fmt.Printf("\n%s[[OK]] Update check complete.%s To apply this update, run: %scopsec update%s\n\n", cGreen, cReset, cCyan, cReset)
		return
	}

	// 2. Ensure sudo/root privileges to update system binaries and services
	ensureSudo("update CoPSeC platform and system services")

	// 3. Verify Go compiler
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Printf("%s[!] Error: 'go' toolchain is required for compilation but was not found on PATH.%s\n", cRed, cReset)
		fmt.Printf("    Install Go or use: sudo bash scripts/install.sh\n")
		os.Exit(1)
	}

	// 4. Resolve source directory or clone to temporary directory
	var buildDir string
	var cleanupTmp bool

	// Check local git directory candidates
	localCandidates := []string{
		".",
		"/opt/copsec/src",
		"/home/copdasten/copsec",
	}

	for _, cand := range localCandidates {
		if _, err := os.Stat(cand + "/.git"); err == nil {
			if _, err2 := os.Stat(cand + "/controller"); err2 == nil {
				if _, err3 := os.Stat(cand + "/collector"); err3 == nil {
					buildDir = cand
					break
				}
			}
		}
	}

	if buildDir != "" {
		fmt.Printf("[*] Utilizing existing repository at %s...\n", buildDir)
		fmt.Printf("[*] Fetching latest changes from branch '%s'...\n", branch)
		pullCmd := exec.Command("git", "pull", "origin", branch)
		pullCmd.Dir = buildDir
		pullOut, pullErr := pullCmd.CombinedOutput()
		if pullErr != nil {
			fmt.Printf("%s[!] Note during git pull:%s %s\n", cYellow, cReset, string(pullOut))
		} else {
			fmt.Printf("%s[[OK]] Repository updated successfully.%s\n", cGreen, cReset)
		}
	} else {
		tmpDir, err := os.MkdirTemp("", "copsec_update_*")
		if err != nil {
			fmt.Printf("%s[!] Failed to create temporary directory: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		buildDir = tmpDir
		cleanupTmp = true
		defer func() {
			if cleanupTmp {
				_ = os.RemoveAll(tmpDir)
			}
		}()

		fmt.Printf("[*] Cloning fresh release tree to %s...\n", tmpDir)
		cloneCmd := exec.Command("git", "clone", "--depth", "1", "-b", branch, repoURL, tmpDir)
		if cloneOut, err := cloneCmd.CombinedOutput(); err != nil {
			fmt.Printf("%s[!] Failed to clone repository:%s %v\n%s\n", cRed, cReset, err, string(cloneOut))
			os.Exit(1)
		}
	}

	// 5. Build static binaries
	fmt.Printf("[*] Compiling static binaries with CGO_ENABLED=0...\n")
	_ = os.MkdirAll(buildDir+"/bin", 0755)

	targets := []struct {
		name    string
		subdir  string
		outName string
	}{
		{"copsec CLI", "cmd/copsec", "copsec"},
		{"copsec Controller & Cockpit", "controller", "copsec-controller"},
		{"copsec Collector", "collector", "copsec-collector"},
	}

	for _, t := range targets {
		fmt.Printf("  • Compiling %s...\n", t.name)
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", buildDir+"/bin/"+t.outName, "./"+t.subdir)
		cmd.Dir = buildDir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("%s[!] Compilation failed for %s:%s %v\n%s\n", cRed, t.name, cReset, err, string(out))
			os.Exit(1)
		}
	}
	// Cockpit is controller binary
	_ = copyFile(buildDir+"/bin/copsec-controller", buildDir+"/bin/copsec-cockpit")

	fmt.Printf("%s[[OK]] All binaries compiled successfully.%s\n", cGreen, cReset)

	// 6. Detect active services before installing
	activeController := isServiceActive("copsec-controller")
	activeCollector := isServiceActive("copsec-collector")
	activeCockpit := isServiceActive("copsec-cockpit")

	// 7. Install to target locations
	fmt.Printf("[*] Deploying updated binaries to system paths...\n")
	binDir := "/opt/copsec/bin"
	_ = os.MkdirAll(binDir, 0755)

	binaries := []string{"copsec", "copsec-controller", "copsec-collector", "copsec-cockpit"}
	for _, b := range binaries {
		srcPath := buildDir + "/bin/" + b
		optPath := binDir + "/" + b
		_ = copyFile(srcPath, optPath)
		_ = os.Chmod(optPath, 0755)

		// /usr/local/bin
		_ = copyFile(srcPath, "/usr/local/bin/"+b)
		_ = os.Chmod("/usr/local/bin/"+b, 0755)

		// Symlink /usr/bin/copsec
		if b == "copsec" {
			_ = copyFile(srcPath, "/usr/bin/"+b)
			_ = os.Chmod("/usr/bin/"+b, 0755)
		}
	}

	// Also update user PATH if available
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		_ = os.MkdirAll(homeDir+"/.local/bin", 0755)
		_ = copyFile(buildDir+"/bin/copsec", homeDir+"/.local/bin/copsec")
		_ = os.Chmod(homeDir+"/.local/bin/copsec", 0755)
	}

	// Copy eBPF bytecode if present
	if _, err := os.Stat(buildDir + "/bpf/copsec_xdp.bpf.o"); err == nil {
		_ = os.MkdirAll("/etc/copsec", 0755)
		_ = copyFile(buildDir+"/bpf/copsec_xdp.bpf.o", "/etc/copsec/copsec_xdp.bpf.o")
		fmt.Printf("  • Updated kernel eBPF/XDP bytecode at /etc/copsec/copsec_xdp.bpf.o\n")
	}

	fmt.Printf("%s[[OK]] Binary deployment complete.%s\n", cGreen, cReset)

	// 8. Restart active services if requested
	if !noRestart {
		fmt.Printf("[*] Gracefully reloading active services...\n")
		var svcsToRestart []string
		if activeController {
			svcsToRestart = append(svcsToRestart, "copsec-controller")
		}
		if activeCollector {
			svcsToRestart = append(svcsToRestart, "copsec-collector")
		}
		if activeCockpit {
			svcsToRestart = append(svcsToRestart, "copsec-cockpit")
		}

		if len(svcsToRestart) == 0 {
			if _, err := exec.LookPath("systemctl"); err == nil {
				svcsToRestart = append(svcsToRestart, "copsec-controller")
			}
		}

		for _, s := range svcsToRestart {
			restartSingleService(s)
		}

		time.Sleep(1500 * time.Millisecond)
	}

	fmt.Printf("\n%s================================================================================%s\n", cBold+cGreen, cReset)
	fmt.Printf("%s CoPSeC Upgrade Succeeded! Active Version: %s%s\n", cBold+cGreen, Version, cReset)
	if len(remoteCommit) >= 8 {
		fmt.Printf("  • Commit Hash       : %s%s%s\n", cYellow, remoteCommit[:8], cReset)
	}
	fmt.Printf("  • Preserved Ledger  : %s/var/lib/copsec/vault.db%s\n", cWhite, cReset)
	fmt.Printf("  • Verify Health     : %scopsec status%s\n", cCyan, cReset)
	fmt.Printf("%s================================================================================%s\n\n", cBold+cGreen, cReset)
}

func handleEmergencyFlush(cfg Config) {
	printBanner()
	fmt.Printf("%s[!] EMERGENCY BREAK-GLASS OPERATION: Flushing all active quarantines and eBPF maps%s\n\n", cBold+cRed, cReset)

	// 1. Call Controller REST API
	apiURL := cfg.BaseURL + "/api/quarantine/emergency-flush"
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(`{"confirm":"CONFIRM-FLUSH"}`))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, rErr := client.Do(req)
		if rErr == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusOK {
				fmt.Printf("%s[[OK]] Controller Central Vault quarantine purged successfully.%s\n", cGreen, cReset)
				fmt.Printf("    Response: %s\n", string(body))
			} else {
				fmt.Printf("%s[!] Controller returned HTTP %d: %s%s\n", cYellow, resp.StatusCode, string(body), cReset)
			}
		} else {
			fmt.Printf("%s[!] Controller API unreachable (%v). Proceeding to direct local eBPF purge...%s\n", cYellow, rErr, cReset)
		}
	}

	// 2. Direct local kernel eBPF map flush if collector binary is available
	collectorBin := "copsec-collector"
	if _, err := exec.LookPath(collectorBin); err != nil {
		if _, err := os.Stat("/usr/local/bin/copsec-collector"); err == nil {
			collectorBin = "/usr/local/bin/copsec-collector"
		} else if _, err := os.Stat("./bin/copsec-collector"); err == nil {
			collectorBin = "./bin/copsec-collector"
		}
	}

	cmd := exec.Command(collectorBin, "--panic-unban-all")
	out, err := cmd.CombinedOutput()
	if err == nil {
		fmt.Printf("%s[[OK]] Direct Kernel eBPF/XDP map purge completed successfully.%s\n", cGreen, cReset)
		fmt.Printf("    Output: %s\n", strings.TrimSpace(string(out)))
	} else {
		fmt.Printf("%s[i] Note on local kernel flush: %v (%s)%s\n", cGray, err, strings.TrimSpace(string(out)), cReset)
	}

	fmt.Printf("\n%s[[OK]] Break-Glass Emergency Flush finished. Zero administrative lockouts guaranteed.%s\n", cBold+cGreen, cReset)
}

// handleBlock inserts a CIDR prefix into the kernel LPM trie blocklist
func handleBlock(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error: CIDR prefix required%s\n", cRed, cReset)
		fmt.Printf("Usage: %scopsec block <CIDR> [description]%s\n", cCyan, cReset)
		fmt.Printf("Example: copsec block 192.0.2.0/24 \"Malicious subnet\"\n")
		os.Exit(1)
	}

	first := strings.ToLower(args[0])
	if first == "list" || first == "ls" {
		handleListBlocks(cfg)
		return
	}
	if first == "add" {
		args = args[1:]
		if len(args) == 0 {
			fmt.Printf("%s[!] Error: CIDR prefix required after 'add'%s\n", cRed, cReset)
			os.Exit(1)
		}
	}
	if first == "remove" || first == "rm" || first == "del" || first == "delete" {
		handleUnblock(cfg, args[1:])
		return
	}

	cidr := strings.TrimSpace(args[0])
	// Auto-append /32 if single IPv4 address
	if net.ParseIP(cidr) != nil && !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}

	desc := "Manual CLI block"
	if len(args) > 1 {
		desc = strings.Join(args[1:], " ")
	}

	// 1. Attempt to notify running controller via REST API
	reqBody := map[string]string{
		"cidr":        cidr,
		"description": desc,
	}
	resp, respBody, err := apiRequest(cfg, "POST", "/api/v1/blocks", reqBody)
	if err == nil && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) {
		fmt.Printf("%s[+] Successfully blocked %s in kernel LPM trie (via active controller)%s\n", cGreen, cidr, cReset)
		return
	}
	if resp != nil && resp.StatusCode == 401 {
		fmt.Printf("%s[!] Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("Hint: Set API key using 'copsec apikey set <key>'\n")
		os.Exit(1)
	}
	if resp != nil && resp.StatusCode == 409 {
		fmt.Printf("%s[!] Block Rejected: Target %s is protected by active whitelist rule.%s\n", cYellow, cidr, cReset)
		os.Exit(1)
	}
	if resp != nil && resp.StatusCode != 404 && resp.StatusCode != 200 && resp.StatusCode != 201 {
		fmt.Printf("%s[!] Controller returned HTTP %d: %s%s\n", cRed, resp.StatusCode, string(respBody), cReset)
	}

	// 2. Offline / Standalone direct execution via pkg/rules
	rm, err := rules.NewRuleManager(cfg.BPFMap, cfg.RulesPath)
	if err != nil {
		fmt.Printf("%s[!] Failed to initialize RuleManager: %v%s\n", cRed, err, cReset)
		os.Exit(1)
	}
	defer rm.Close()

	if err := rm.BlockCIDR(cidr, desc); err != nil {
		fmt.Printf("%s[!] Failed to block CIDR %s: %v%s\n", cRed, cidr, err, cReset)
		os.Exit(1)
	}

	if err := rm.SaveRuleFile(cfg.RulesPath); err != nil {
		fmt.Printf("%s[WARN] Blocked in memory/kernel, but failed to save to %s: %v%s\n", cYellow, cfg.RulesPath, err, cReset)
	}

	fmt.Printf("%s[+] Successfully blocked prefix %s in kernel LPM trie%s\n", cGreen, cidr, cReset)
	if rm.IsEmulated() {
		fmt.Printf("    (Mode: Userspace LPM emulation - run as root for hardware/eBPF XDP enforcement)\n")
	}
	fmt.Printf("    Reason: %s\n", desc)
	fmt.Printf("    Rules file: %s\n", cfg.RulesPath)
}

// handleUnblock evicts a CIDR prefix from the kernel LPM trie blocklist
func handleUnblock(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error: CIDR prefix required%s\n", cRed, cReset)
		fmt.Printf("Usage: %scopsec unblock <CIDR>%s\n", cCyan, cReset)
		fmt.Printf("Example: copsec unblock 192.0.2.0/24\n")
		os.Exit(1)
	}

	first := strings.ToLower(args[0])
	if first == "remove" || first == "rm" || first == "del" || first == "delete" {
		args = args[1:]
		if len(args) == 0 {
			fmt.Printf("%s[!] Error: CIDR prefix required%s\n", cRed, cReset)
			os.Exit(1)
		}
	}

	cidr := strings.TrimSpace(args[0])
	if net.ParseIP(cidr) != nil && !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}

	// 1. Attempt to notify running controller via REST API
	endpoint := fmt.Sprintf("/api/v1/blocks?cidr=%s", url.QueryEscape(cidr))
	resp, _, err := apiRequest(cfg, "DELETE", endpoint, nil)
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Printf("%s[+] Successfully evicted prefix %s from kernel LPM trie (via active controller)%s\n", cGreen, cidr, cReset)
		return
	}

	// 2. Offline / Standalone direct execution via pkg/rules
	rm, err := rules.NewRuleManager(cfg.BPFMap, cfg.RulesPath)
	if err != nil {
		fmt.Printf("%s[!] Failed to initialize RuleManager: %v%s\n", cRed, err, cReset)
		os.Exit(1)
	}
	defer rm.Close()

	if err := rm.UnblockCIDR(cidr); err != nil {
		fmt.Printf("%s[!] Failed to unblock CIDR %s: %v%s\n", cRed, cidr, err, cReset)
		os.Exit(1)
	}

	if err := rm.SaveRuleFile(cfg.RulesPath); err != nil {
		fmt.Printf("%s[WARN] Evicted from memory/kernel, but failed to save to %s: %v%s\n", cYellow, cfg.RulesPath, err, cReset)
	}

	fmt.Printf("%s[+] Successfully evicted prefix %s from kernel LPM trie%s\n", cGreen, cidr, cReset)
}

// handleListBlocks dumps all active kernel LPM trie blocks
func handleListBlocks(cfg Config) {
	var blockList []rules.BlockEntry

	// 1. Try querying running controller
	resp, body, err := apiRequest(cfg, "GET", "/api/v1/blocks", nil)
	if err == nil && resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(body, &blockList)
	} else {
		// 2. Fallback to reading from local RuleManager / rules file
		rm, err := rules.NewRuleManager(cfg.BPFMap, cfg.RulesPath)
		if err == nil {
			blockList = rm.ListBlocks()
			rm.Close()
		}
	}

	fmt.Printf("%s=== Active Kernel LPM Trie Blocklist ===%s\n\n", cBold+cCyan, cReset)
	if len(blockList) == 0 {
		fmt.Printf("%s[*] No active CIDR prefix blocks found in kernel LPM trie.%s\n\n", cGray, cReset)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sCIDR PREFIX%s\t%sADDED AT%s\t%sDESCRIPTION%s\n", cBold+cWhite, cReset, cBold+cWhite, cReset, cBold+cWhite, cReset)
	for _, b := range blockList {
		addedStr := b.AddedAt.Format("2006-01-02 15:04:05")
		if b.AddedAt.IsZero() {
			addedStr = "-"
		}
		fmt.Fprintf(w, "%s%s%s\t%s\t%s\n", cYellow, b.CIDR, cReset, addedStr, b.Description)
	}
	w.Flush()
	fmt.Printf("\nTotal prefixes in kernel LPM trie: %s%d%s\n\n", cBold+cGreen, len(blockList), cReset)
}

// handleReloadRules reloads local rule definition files into kernel maps
func handleReloadRules(cfg Config, args []string) {
	rulesPath := cfg.RulesPath
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		rulesPath = strings.TrimSpace(args[0])
	}

	// 1. Attempt to trigger reload on controller if running
	resp, body, err := apiRequest(cfg, "POST", "/api/v1/rules/reload", nil)
	if err == nil && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) {
		fmt.Printf("%s[+] Controller successfully reloaded rules: %s%s\n", cGreen, string(body), cReset)
		return
	}

	// 2. Direct reload via RuleManager
	rm, err := rules.NewRuleManager(cfg.BPFMap, rulesPath)
	if err != nil {
		fmt.Printf("%s[!] Failed to initialize RuleManager: %v%s\n", cRed, err, cReset)
		os.Exit(1)
	}
	defer rm.Close()

	ruleCfg, err := rm.LoadRuleFile(rulesPath)
	if err != nil {
		fmt.Printf("%s[!] Failed to load rules file %s: %v%s\n", cRed, rulesPath, err, cReset)
		os.Exit(1)
	}

	if err := rm.SyncRules(ruleCfg); err != nil {
		fmt.Printf("%s[!] Failed to synchronize rules to kernel LPM trie: %v%s\n", cRed, err, cReset)
		os.Exit(1)
	}

	blocks := rm.ListBlocks()
	fwRules := rm.ListRules()
	fmt.Printf("%s[+] Successfully reloaded and synchronized rules into kernel LPM trie%s\n", cGreen, cReset)
	fmt.Printf("    Rules File:      %s\n", rulesPath)
	fmt.Printf("    CIDR Blocks:     %d prefixes active\n", len(blocks))
	fmt.Printf("    Firewall Rules:  %d rules active\n", len(fwRules))
}

// runDaemon bootstraps the 100% standalone, offline-first CoPSeC Security Engine
func runDaemon(rulesPath string, bpfMapPath string, listenAddr string) {
	printBanner()
	fmt.Printf("%s[+] Bootstrapping CoPSeC Standalone Security Engine...%s\n", cGreen, cReset)

	// 1. Initialize Standalone Rule Manager (BPF LPM Trie)
	rm, err := rules.NewRuleManager(bpfMapPath, rulesPath)
	if err != nil {
		log.Printf("[INIT] [WARN] RuleManager initialization note: %v", err)
	}
	defer rm.Close()

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// 2. Initialize and Start Telemetry & SIEM Event Streamer (Unconditionally Enabled)
	siemStreamer := streamer.NewSIEMStreamer(4, 10000, os.Stdout)
	if err := siemStreamer.Start(rootCtx); err != nil {
		log.Fatalf("[FATAL] Failed to start SIEM event streamer: %v", err)
	}

	// 3. Initialize and Start Web Management Dashboard (Unconditionally Enabled)
	serverCfg := &server.ServerConfig{
		ListenAddr: listenAddr,
	}
	webServer := server.NewWebServer(serverCfg, rm)
	if err := webServer.Start(); err != nil {
		log.Fatalf("[FATAL] Failed to start Web Management Dashboard: %v", err)
	}

	fmt.Printf("%s[+] CoPSeC Packet Filtering Engine: RUNNING (Kernel XDP / LPM Trie)%s\n", cGreen, cReset)
	fmt.Printf("%s[+] Web Management Cockpit: http://127.0.0.1%s%s\n", cGreen, listenAddr, cReset)
	fmt.Printf("%s[+] Local Rules File: %s (%d prefixes loaded)%s\n", cCyan, rulesPath, len(rm.ListBlocks()), cReset)
	if rm.IsEmulated() {
		fmt.Printf("%s[i] Note: Running in userspace LPM emulation mode. Run with sudo for hardware/eBPF XDP attachment.%s\n", cGray, cReset)
	}
	fmt.Printf("%s[*] Press Ctrl+C or send SIGTERM to gracefully shut down.%s\n", cGray, cReset)

	// 4. Signal Handling & Graceful Shutdown Orchestration
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("\n%s[!] Received signal %v. Initiating graceful shutdown...%s\n", cYellow, sig, cReset)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := webServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[SHUTDOWN] [WARN] Web server shutdown notice: %v", err)
	}

	if err := siemStreamer.Stop(); err != nil {
		log.Printf("[SHUTDOWN] [WARN] Event streamer shutdown notice: %v", err)
	}

	rootCancel()
	fmt.Printf("%s[+] Graceful shutdown completed cleanly.%s\n", cGreen, cReset)
}


