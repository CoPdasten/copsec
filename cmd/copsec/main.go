package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
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
	BaseURL string
	APIKey  string
}

func resolveConfig() Config {
	baseURL := strings.TrimRight(os.Getenv("COPSEC_CONTROLLER_URL"), "/")
	if baseURL == "" {
		baseURL = DefaultURL
	}

	apiKey := strings.TrimSpace(os.Getenv("COPSEC_API_KEY"))
	if apiKey == "" {
		candidates := []string{
			"/etc/copsec/api_key",
			"/var/lib/copsec/api_key",
			"/opt/copsec/etc/api_key",
			"./controller/data/api_key",
			"./data/api_key",
			"../controller/data/api_key",
		}
		for _, p := range candidates {
			if data, err := os.ReadFile(p); err == nil {
				trimmed := strings.TrimSpace(string(data))
				if trimmed != "" {
					apiKey = trimmed
					break
				}
			}
		}
	}
	if apiKey == "" {
		// Also inspect copsec.env
		if data, err := os.ReadFile("/etc/copsec/copsec.env"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "COPSEC_API_KEY=") {
					apiKey = strings.Trim(strings.TrimPrefix(line, "COPSEC_API_KEY="), " \"'\r\n")
					break
				}
			}
		}
	}

	return Config{
		BaseURL: baseURL,
		APIKey:  apiKey,
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printHelp()
		return
	}

	cfg := resolveConfig()

	// Parse global flags if provided at the start
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
			printHelp()
			return
		}
		if args[0] == "-v" || args[0] == "--version" || args[0] == "version" {
			printVersion()
			return
		}
		if strings.HasPrefix(args[0], "--url=") {
			cfg.BaseURL = strings.TrimRight(strings.TrimPrefix(args[0], "--url="), "/")
			args = args[1:]
			continue
		}
		if args[0] == "-u" || args[0] == "--url" {
			if len(args) > 1 {
				cfg.BaseURL = strings.TrimRight(args[1], "/")
				args = args[2:]
				continue
			}
		}
		if strings.HasPrefix(args[0], "--key=") {
			cfg.APIKey = strings.TrimPrefix(args[0], "--key=")
			args = args[1:]
			continue
		}
		if args[0] == "-k" || args[0] == "--key" {
			if len(args) > 1 {
				cfg.APIKey = args[1]
				args = args[2:]
				continue
			}
		}
		break
	}

	if len(args) == 0 {
		printHelp()
		return
	}

	cmd := strings.ToLower(args[0])
	cmdArgs := args[1:]

	switch cmd {
	case "help", "-h", "--help":
		printHelp()
	case "version", "-v", "--version":
		printVersion()
	case "status", "st":
		handleStatus(cfg)
	case "apikey", "key", "token":
		handleAPIKey(cfg, cmdArgs)
	case "web", "dashboard", "ui":
		handleWeb(cfg)
	case "ban":
		handleBan(cfg, cmdArgs)
	case "unban":
		handleUnban(cfg, cmdArgs)
	case "bans", "list-bans", "quarantine":
		handleListBans(cfg)
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

	fmt.Printf("%sCORE COMMANDS:%s\n", cBold+cWhite, cReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %sstatus%s (st)\tCheck health, services, XDP status, EPS & active bans\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sapikey%s (key)\tShow Master API key and one-click Web SOC login URL\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sapikey set <key>%s\tUpdate Master API key and restart daemon\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sapikey generate%s\tGenerate fresh 32-byte key, save and restart daemon\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sweb%s (ui)\tPrint Web SOC Cockpit URL and token login link\n", cGreen, cReset)
	w.Flush()

	fmt.Printf("\n%sDEFENSE & QUARANTINE (eBPF/XDP):%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %sban <ip> [ttl] [reason]%s\tInstantly quarantine IP in kernel XDP (e.g. copsec ban 1.2.3.4 1h)\n", cYellow, cReset)
	fmt.Fprintf(w, "  %sunban <ip>%s\tEvict IP from kernel quarantine list\n", cYellow, cReset)
	fmt.Fprintf(w, "  %sbans%s (quarantine)\tList all active kernel quarantine bans & TTLs\n", cYellow, cReset)
	w.Flush()

	fmt.Printf("\n%sTELEMETRY & INTELLIGENCE:%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %salerts [limit]%s\tDisplay latest security alerts & mitigation status\n", cCyan, cReset)
	fmt.Fprintf(w, "  %sfleet%s (nodes)\tList enrolled autonomous edge sensor nodes & status\n", cCyan, cReset)
	fmt.Fprintf(w, "  %srules%s (sigma)\tList active Sigma & eBPF detection rules\n", cCyan, cReset)
	fmt.Fprintf(w, "  %scanary%s\tInspect canary deception breadcrumbs and honeytokens\n", cCyan, cReset)
	w.Flush()

	fmt.Printf("\n%sSYSTEM & DAEMON MANAGEMENT:%s\n", cBold+cWhite, cReset)
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  %slogs [svc] [-f] [n]%s\tView service logs (controller, collector, cockpit)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %srestart [svc]%s\tRestart CoPSeC service(s) (all, controller, collector)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %sstart [svc]%s\tStart CoPSeC service(s)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %sstop [svc]%s\tStop CoPSeC service(s)\n", cWhite, cReset)
	fmt.Fprintf(w, "  %supdate%s (upgrade)\tPull latest updates, recompile & gracefully reload\n", cGreen, cReset)
	fmt.Fprintf(w, "  %sversion%s (-v)\tDisplay platform version and build metadata\n", cWhite, cReset)
	w.Flush()

	fmt.Printf("\n%sOPTIONS:%s\n", cBold+cWhite, cReset)
	fmt.Printf("  %s-u, --url <url>%s       Controller base address (Default: http://127.0.0.1:8080)\n", cGray, cReset)
	fmt.Printf("  %s-k, --key <key>%s       Explicit API Key override\n", cGray, cReset)
	fmt.Printf("\n%sEXAMPLES:%s\n", cBold+cWhite, cReset)
	fmt.Printf("  copsec status\n")
	fmt.Printf("  copsec apikey\n")
	fmt.Printf("  copsec ban 198.51.100.4 2h \"brute-force attempt\"\n")
	fmt.Printf("  copsec unban 198.51.100.4\n")
	fmt.Printf("  copsec bans\n")
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

	if cfg.APIKey != "" {
		req.Header.Set("X-API-Key", cfg.APIKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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

	// 1. Host Services
	fmt.Printf("%s[HOST SERVICES]%s\n", cBold+cWhite, cReset)
	fmt.Printf("  • copsec-controller : %s\n", checkServiceActive("copsec-controller"))
	fmt.Printf("  • copsec-collector  : %s\n", checkServiceActive("copsec-collector"))
	fmt.Printf("  • copsec-cockpit    : %s\n", checkServiceActive("copsec-cockpit"))

	// 2. Credentials
	fmt.Printf("\n%s[AUTHENTICATION & ACCESS]%s\n", cBold+cWhite, cReset)
	ip := getServerIP()
	if os.Geteuid() == 0 {
		if cfg.APIKey != "" {
			masked := cfg.APIKey
			if len(masked) > 8 {
				masked = masked[:4] + strings.Repeat("*", len(masked)-8) + masked[len(masked)-4:]
			}
			fmt.Printf("  • Master API Key    : %s%s%s (configured)\n", cGreen, masked, cReset)
			fmt.Printf("  • Credential File   : %s/etc/copsec/api_key%s\n", cWhite, cReset)
		} else {
			fmt.Printf("  • Master API Key    : %s[NOT CONFIGURED - Set via 'copsec apikey set <key>']%s\n", cRed, cReset)
		}
		fmt.Printf("  • Web SOC Cockpit   : %shttp://%s:8080%s\n", cCyan, ip, cReset)
		if cfg.APIKey != "" {
			fmt.Printf("  • Direct Login URL  : %shttp://%s:8080/?token=%s%s\n", cCyan, ip, cfg.APIKey, cReset)
		}
	} else {
		fmt.Printf("  • Master API Key    : %s[PROTECTED - View via 'sudo copsec apikey']%s\n", cYellow, cReset)
		fmt.Printf("  • Credential File   : %s/etc/copsec/api_key%s (mode 0600 root)\n", cWhite, cReset)
		fmt.Printf("  • Web SOC Cockpit   : %shttp://%s:8080%s\n", cCyan, ip, cReset)
		fmt.Printf("  • Direct Login URL  : %s[PROTECTED - View via 'sudo copsec apikey']%s\n", cYellow, cReset)
	}

	// 3. Query Controller Health & Stats
	fmt.Printf("\n%s[REAL-TIME TELEMETRY]%s\n", cBold+cWhite, cReset)
	resp, body, err := apiRequest(cfg, "GET", "/api/stats", nil)
	if err != nil {
		fmt.Printf("  %s[!] Could not connect to controller API (%s): %v%s\n", cYellow, cfg.BaseURL, err, cReset)
		fmt.Printf("  Hint: Ensure 'copsec-controller' service is running ('copsec start controller').\n")
		return
	}
	if resp.StatusCode == 401 {
		fmt.Printf("  %s[!] API Authentication Failed (401 Unauthorized)%s\n", cRed, cReset)
		fmt.Printf("  Hint: Active API key does not match controller. Update using 'copsec apikey set <key>'.\n")
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("  %s[!] Controller returned HTTP %d: %s%s\n", cRed, resp.StatusCode, string(body), cReset)
		return
	}

	var stats struct {
		EPS            uint64 `json:"eps"`
		TotalEvents    uint64 `json:"total_events"`
		NodesCount     int    `json:"nodes_count"`
		ActiveBans     int    `json:"active_bans"`
		ActiveAlerts   int    `json:"active_alerts"`
		ArchiveAlerts  int    `json:"archive_alerts"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		fmt.Printf("  [!] Failed to parse telemetry stats: %v\n", err)
		return
	}

	fmt.Printf("  • Current Throughput: %s%d EPS%s (Events Per Second)\n", cBold+cGreen, stats.EPS, cReset)
	fmt.Printf("  • Total Ingested    : %s%d events%s\n", cWhite, stats.TotalEvents, cReset)
	fmt.Printf("  • Active Bans (XDP) : %s%d quarantined%s\n", cYellow, stats.ActiveBans, cReset)
	fmt.Printf("  • Active Alerts     : %s%d unmitigated%s\n", cRed, stats.ActiveAlerts, cReset)
	fmt.Printf("  • Fleet Nodes       : %s%d sensors connected%s\n", cCyan, stats.NodesCount, cReset)
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

	fmt.Printf("%s[🔒] Root/Sudo authentication required to %s...%s\n", cBold+cYellow, reason, cReset)

	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}

	var cmd *exec.Cmd
	if strings.HasSuffix(sudoPath, "sudo") {
		// -k invalidates cached credentials, forcing sudo to prompt for the password
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

func handleAPIKey(cfg Config, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}

	switch sub {
	case "set":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Printf("%s[!] Error:%s Please provide an API key. Usage: %scopsec apikey set <new-key>%s\n", cRed, cReset, cCyan, cReset)
			os.Exit(1)
		}
		ensureSudo("change Master API Key")
		newKey := strings.TrimSpace(args[1])
		applyNewAPIKey(newKey)

	case "generate", "gen", "reset":
		ensureSudo("generate and save new Master API Key")
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			fmt.Printf("%s[!] Error generating crypto random bytes: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		newKey := hex.EncodeToString(buf)
		fmt.Printf("%s[+] Generated new 32-byte Master API Key: %s%s%s\n", cGreen, cBold+cYellow, newKey, cReset)
		applyNewAPIKey(newKey)

	default: // get or show
		// Enforce sudo authentication to view active Master API key and token
		ensureSudo("view Master API Key and direct login URL")

		if cfg.APIKey == "" {
			cfg = resolveConfig()
		}

		if cfg.APIKey == "" {
			fmt.Printf("%s[!] No Master API Key currently configured.%s\n", cYellow, cReset)
			fmt.Printf("To set a key, run: %scopsec apikey set <your_key>%s\n", cCyan, cReset)
			fmt.Printf("To generate one, run: %scopsec apikey generate%s\n", cCyan, cReset)
			return
		}

		ip := getServerIP()
		fmt.Printf("%s=== CoPSeC Master API Key Configuration ===%s\n\n", cBold+cCyan, cReset)
		fmt.Printf("  • Active API Key    : %s%s%s\n", cBold+cYellow, cfg.APIKey, cReset)
		fmt.Printf("  • Stored In         : %s/etc/copsec/api_key%s and %s/etc/copsec/copsec.env%s\n", cWhite, cReset, cWhite, cReset)
		fmt.Printf("  • Single-Click URL  : %shttp://%s:8080/?token=%s%s\n\n", cCyan, ip, cfg.APIKey, cReset)
		fmt.Printf("%sTip:%s You can copy and paste the Single-Click URL directly into your browser to log in without prompting!\n\n", cGray, cReset)
	}
}

func applyNewAPIKey(newKey string) {
	if os.Geteuid() != 0 {
		fmt.Printf("%s[!] Note:%s Writing to /etc/copsec requires root/sudo privileges.\n", cYellow, cReset)
	}

	_ = os.MkdirAll("/etc/copsec", 0755)

	if err := os.WriteFile("/etc/copsec/api_key", []byte(newKey+"\n"), 0600); err != nil {
		fmt.Printf("%s[!] Failed to write /etc/copsec/api_key: %v (try with sudo)%s\n", cRed, err, cReset)
		os.Exit(1)
	}

	envContent := fmt.Sprintf("COPSEC_API_KEY=%s\n", newKey)
	if err := os.WriteFile("/etc/copsec/copsec.env", []byte(envContent), 0600); err != nil {
		fmt.Printf("%s[!] Warning: Failed to write /etc/copsec/copsec.env: %v%s\n", cYellow, err, cReset)
	}

	fmt.Printf("%s[✓] Master API Key persisted to /etc/copsec/api_key and copsec.env (mode 0600).%s\n", cGreen, cReset)

	// Restart service
	fmt.Printf("[*] Reloading copsec-controller service...\n")
	restarted := false
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := exec.Command("systemctl", "restart", "copsec-controller").Run(); err == nil {
			fmt.Printf("%s[✓] Successfully restarted copsec-controller via systemd.%s\n", cGreen, cReset)
			restarted = true
		}
	}
	if !restarted {
		if _, err := exec.LookPath("rc-service"); err == nil {
			if err := exec.Command("rc-service", "copsec-controller", "restart").Run(); err == nil {
				fmt.Printf("%s[✓] Successfully restarted copsec-controller via OpenRC.%s\n", cGreen, cReset)
				restarted = true
			}
		}
	}
	if !restarted {
		fmt.Printf("%s[!] Please restart copsec-controller manually to load the new key:%s\n", cYellow, cReset)
		fmt.Printf("    sudo systemctl restart copsec-controller  OR  sudo rc-service copsec-controller restart\n")
	}

	ip := getServerIP()
	fmt.Printf("\n%sNew Direct Login URL:%s %shttp://%s:8080/?token=%s%s\n\n", cBold+cWhite, cReset, cCyan, ip, newKey, cReset)
}

func handleWeb(cfg Config) {
	ensureSudo("view Web SOC login credentials and direct token")
	if cfg.APIKey == "" {
		cfg = resolveConfig()
	}

	ip := getServerIP()
	fmt.Printf("%s=== CoPSeC Web SOC Cockpit ===%s\n\n", cBold+cCyan, cReset)
	fmt.Printf("  • Localhost URL     : %shttp://127.0.0.1:8080%s\n", cCyan, cReset)
	fmt.Printf("  • Network IP URL    : %shttp://%s:8080%s\n", cCyan, ip, cReset)
	if cfg.APIKey != "" {
		fmt.Printf("  • One-Click Token   : %shttp://%s:8080/?token=%s%s\n\n", cGreen, ip, cfg.APIKey, cReset)
	} else {
		fmt.Printf("  • API Key           : %s[Not configured - run 'copsec apikey generate']%s\n\n", cYellow, cReset)
	}
}

func parseDurationSeconds(durStr string) int64 {
	durStr = strings.TrimSpace(strings.ToLower(durStr))
	if durStr == "" {
		return 3600 // default 1 hour
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
		os.Exit(1)
	}

	ip := strings.TrimSpace(args[0])
	if net.ParseIP(ip) == nil {
		fmt.Printf("%s[!] Error:%s Invalid IP format: '%s'\n", cRed, cReset, ip)
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
		"ip":               ip,
		"reason":           reason,
		"duration_seconds": durationSec,
	}

	resp, respBody, err := apiRequest(cfg, "POST", "/api/quarantine/ban", payload)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Ban failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
		os.Exit(1)
	}

	fmt.Printf("%s[✓] IP %s successfully quarantined in kernel eBPF/XDP map!%s\n", cGreen, ip, cReset)
	fmt.Printf("    Duration : %d seconds (~%s)\n", durationSec, time.Duration(durationSec)*time.Second)
	fmt.Printf("    Reason   : %s\n", reason)
}

func handleUnban(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[!] Error:%s Missing target IP. Usage: %scopsec unban <ip>%s\n", cRed, cReset, cCyan, cReset)
		os.Exit(1)
	}

	ip := strings.TrimSpace(args[0])
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
	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Unban failed (HTTP %d):%s %s\n", cRed, resp.StatusCode, cReset, string(respBody))
		os.Exit(1)
	}

	fmt.Printf("%s[✓] IP %s successfully unbanned and evicted from kernel XDP quarantine.%s\n", cGreen, ip, cReset)
}

func handleListBans(cfg Config) {
	resp, body, err := apiRequest(cfg, "GET", "/api/quarantine", nil)
	if err != nil {
		fmt.Printf("%s[!] Connection error:%s %v\n", cRed, cReset, err)
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
			fmt.Printf("%s[✓] %s %s completed successfully.%s\n", cGreen, svc, action, cReset)
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
		fmt.Printf("\n%s[✓] Update check complete.%s To apply this update, run: %scopsec update%s\n\n", cGreen, cReset, cCyan, cReset)
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
			fmt.Printf("%s[✓] Repository updated successfully.%s\n", cGreen, cReset)
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

	fmt.Printf("%s[✓] All binaries compiled successfully.%s\n", cGreen, cReset)

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

	fmt.Printf("%s[✓] Binary deployment complete.%s\n", cGreen, cReset)

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
	fmt.Printf("%s CoPSeC Pro Upgrade Succeeded! Active Version: %s%s\n", cBold+cGreen, Version, cReset)
	if len(remoteCommit) >= 8 {
		fmt.Printf("  • Commit Hash       : %s%s%s\n", cYellow, remoteCommit[:8], cReset)
	}
	fmt.Printf("  • Preserved Ledger  : %s/var/lib/copsec/vault.db%s\n", cWhite, cReset)
	fmt.Printf("  • Preserved API Key : %s/etc/copsec/api_key%s\n", cWhite, cReset)
	fmt.Printf("  • Verify Health     : %scopsec status%s\n", cCyan, cReset)
	fmt.Printf("%s================================================================================%s\n\n", cBold+cGreen, cReset)
}

