package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/copsec/pkg/rules"
)

const (
	DefaultListenAddr = ":8080"
)

// ServerConfig specifies the HTTP server configuration
type ServerConfig struct {
	ListenAddr string
	StaticDir  string
}

// WebServer encapsulates the standalone HTTP management dashboard and REST control APIs
type WebServer struct {
	cfg        *ServerConfig
	rm         *rules.RuleManager
	httpServer *http.Server
	mux        *http.ServeMux
	startTime  time.Time

	// Real-time telemetry counters
	activeBans uint64
	epsCount   uint64
}

// NewWebServer constructs a new standalone, fully-enabled HTTP management server
func NewWebServer(cfg *ServerConfig, rm *rules.RuleManager) *WebServer {
	if cfg == nil {
		cfg = &ServerConfig{ListenAddr: DefaultListenAddr}
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}

	ws := &WebServer{
		cfg:       cfg,
		rm:        rm,
		mux:       http.NewServeMux(),
		startTime: time.Now(),
	}

	ws.setupRoutes()

	ws.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      ws.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return ws
}

// UpdateMetrics updates live telemetry metrics
func (ws *WebServer) UpdateMetrics(activeBans uint64, eps uint64) {
	atomic.StoreUint64(&ws.activeBans, activeBans)
	atomic.StoreUint64(&ws.epsCount, eps)
}

// setupRoutes registers all standalone REST and UI endpoints
func (ws *WebServer) setupRoutes() {
	// Health check
	ws.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Core administrative endpoints
	ws.mux.HandleFunc("/api/v1/status", ws.handleStatus)
	ws.mux.HandleFunc("/api/v1/blocks", ws.handleBlocks)
	ws.mux.HandleFunc("/api/v1/rules", ws.handleRules)
	ws.mux.HandleFunc("/api/v1/metrics", ws.handleMetrics)

	// Web Dashboard
	ws.mux.HandleFunc("/", ws.handleDashboard)
}

// handleStatus returns live system operational metrics
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(ws.startTime).Round(time.Second)

	var blockCount int
	var isEmulated bool
	if ws.rm != nil {
		blockCount = len(ws.rm.ListBlocks())
		isEmulated = ws.rm.IsEmulated()
	}

	status := map[string]interface{}{
		"status":        "operational",
		"mode":          "standalone-open-source",
		"version":       "v1.6.0-community",
		"uptime":        uptime.String(),
		"uptime_sec":    int64(uptime.Seconds()),
		"active_bans":   atomic.LoadUint64(&ws.activeBans),
		"lpm_blocks":    blockCount,
		"ebpf_emulated": isEmulated,
		"eps":           atomic.LoadUint64(&ws.epsCount),
		"system": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"num_cpu":    runtime.NumCPU(),
			"alloc_mb":   memStats.Alloc / (1024 * 1024),
			"sys_mb":     memStats.Sys / (1024 * 1024),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

// handleBlocks manages adding, listing, and removing CIDR prefix rules
func (ws *WebServer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ws.rm == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "RuleManager not initialized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		blocks := ws.rm.ListBlocks()
		_ = json.NewEncoder(w).Encode(blocks)

	case http.MethodPost:
		var req struct {
			CIDR        string `json:"cidr"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		if err := ws.rm.BlockCIDR(req.CIDR, req.Description); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Blocked prefix %s in kernel LPM trie", req.CIDR),
		})

	case http.MethodDelete:
		cidr := r.URL.Query().Get("cidr")
		if cidr == "" {
			var req struct {
				CIDR string `json:"cidr"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			cidr = req.CIDR
		}

		if strings.TrimSpace(cidr) == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'cidr' parameter"})
			return
		}

		if err := ws.rm.UnblockCIDR(cidr); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Evicted prefix %s from kernel LPM trie", cidr),
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method Not Allowed"})
	}
}

// handleRules returns all configured firewall rules
func (ws *WebServer) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.rm == nil {
		_ = json.NewEncoder(w).Encode([]rules.FirewallRule{})
		return
	}
	_ = json.NewEncoder(w).Encode(ws.rm.ListRules())
}

// handleMetrics returns Prometheus-compatible plain-text metrics
func (ws *WebServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	var blockCount int
	if ws.rm != nil {
		blockCount = len(ws.rm.ListBlocks())
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP copsec_active_bans Current number of active eBPF bans\n")
	fmt.Fprintf(w, "# TYPE copsec_active_bans gauge\n")
	fmt.Fprintf(w, "copsec_active_bans %d\n", atomic.LoadUint64(&ws.activeBans))

	fmt.Fprintf(w, "# HELP copsec_lpm_blocks Current number of blocked CIDRs in LPM trie\n")
	fmt.Fprintf(w, "# TYPE copsec_lpm_blocks gauge\n")
	fmt.Fprintf(w, "copsec_lpm_blocks %d\n", blockCount)

	fmt.Fprintf(w, "# HELP copsec_events_per_second Current processing rate\n")
	fmt.Fprintf(w, "# TYPE copsec_events_per_second gauge\n")
	fmt.Fprintf(w, "copsec_events_per_second %d\n", atomic.LoadUint64(&ws.epsCount))

	fmt.Fprintf(w, "# HELP copsec_goroutines Active goroutines\n")
	fmt.Fprintf(w, "# TYPE copsec_goroutines gauge\n")
	fmt.Fprintf(w, "copsec_goroutines %d\n", runtime.NumGoroutine())
}

// handleDashboard renders the admin console unconditionally
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	var blocks []rules.BlockEntry
	var ruleList []rules.FirewallRule
	if ws.rm != nil {
		blocks = ws.rm.ListBlocks()
		ruleList = ws.rm.ListRules()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	data := struct {
		ActiveBans uint64
		EPS        uint64
		Uptime     string
		Blocks     []rules.BlockEntry
		Rules      []rules.FirewallRule
	}{
		ActiveBans: atomic.LoadUint64(&ws.activeBans),
		EPS:        atomic.LoadUint64(&ws.epsCount),
		Uptime:     time.Since(ws.startTime).Round(time.Second).String(),
		Blocks:     blocks,
		Rules:      ruleList,
	}

	_ = standaloneDashboardTemplate.Execute(w, data)
}

// Start begins listening on the configured HTTP port in background
func (ws *WebServer) Start() error {
	log.Printf("[SERVER] [READY] Standalone Web Management Dashboard listening on http://127.0.0.1%s", ws.cfg.ListenAddr)
	go func() {
		if err := ws.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[SERVER] [FATAL] HTTP server failed: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully closes the HTTP server with context timeout
func (ws *WebServer) Shutdown(ctx context.Context) error {
	log.Printf("[SERVER] [STOPPING] Shutting down Web Management Dashboard on %s...", ws.cfg.ListenAddr)
	return ws.httpServer.Shutdown(ctx)
}

// Embedded standalone management dashboard template
var standaloneDashboardTemplate = template.Must(template.New("standaloneDashboard").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CoPSeC - Open-Core Security Platform</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --green: #00ff66;
      --cyan: #58a6ff;
      --amber: #f0883e;
      --red: #f85149;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Courier New', Courier, monospace;
      padding: 30px 15px;
    }
    .container { max-width: 960px; margin: 0 auto; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    h1 { color: var(--cyan); font-size: 18px; margin-bottom: 12px; }
    h2 { color: var(--text); font-size: 14px; margin-bottom: 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }
    .stat-box {
      background: #0d1117;
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 4px;
    }
    .stat-val { font-size: 20px; font-weight: bold; color: var(--green); }
    .stat-label { font-size: 11px; color: #8b949e; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--cyan); }
    .tag { background: #238636; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; }
    .tag-drop { background: var(--red); color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>[ CoPSeC Open-Core Security Cockpit ]</h1>
      <div class="stat-grid">
        <div class="stat-box"><div class="stat-val">{{.ActiveBans}}</div><div class="stat-label">ACTIVE BANS (XDP)</div></div>
        <div class="stat-box"><div class="stat-val">{{len .Blocks}}</div><div class="stat-label">LPM TRIE BLOCKS</div></div>
        <div class="stat-box"><div class="stat-val">{{.EPS}}</div><div class="stat-label">TELEMETRY EPS</div></div>
        <div class="stat-box"><div class="stat-val">{{.Uptime}}</div><div class="stat-label">UPTIME</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Active Kernel LPM Trie CIDR Blocklist</h2>
      {{if .Blocks}}
      <table>
        <thead><tr><th>CIDR PREFIX</th><th>ACTION</th><th>DESCRIPTION</th><th>ADDED</th></tr></thead>
        <tbody>
          {{range .Blocks}}
          <tr>
            <td><code>{{.CIDR}}</code></td>
            <td><span class="tag-drop">DROP</span></td>
            <td>{{.Description}}</td>
            <td>{{.AddedAt.Format "2006-01-02 15:04:05"}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <p style="color: #8b949e; font-size: 12px; padding: 8px 0;">No active CIDR blocks in kernel LPM trie. Use <code>copsec block &lt;CIDR&gt;</code> to add entries.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Configured Firewall Rules</h2>
      {{if .Rules}}
      <table>
        <thead><tr><th>RULE ID</th><th>PROTOCOL</th><th>PORT</th><th>ACTION</th><th>DESCRIPTION</th></tr></thead>
        <tbody>
          {{range .Rules}}
          <tr>
            <td><code>{{.ID}}</code></td>
            <td>{{.Protocol}}</td>
            <td>{{.Port}}</td>
            <td><span class="tag">{{.Action}}</span></td>
            <td>{{.Description}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <p style="color: #8b949e; font-size: 12px; padding: 8px 0;">No firewall rules loaded. Configure via <code>/etc/copsec/rules.yaml</code>.</p>
      {{end}}
    </div>
  </div>
</body>
</html>
`))
