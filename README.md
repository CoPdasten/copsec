# ⚡ CoPSeC — Enterprise Cyber-Defense Cockpit v2.5
### Distributed Edge Threat Sensing, MITRE ATT&CK Matrix & Real-Time SOAR Engine

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Architecture-gRPC%20Streaming-blueviolet?style=for-the-badge&logo=grpc" alt="gRPC" />
  <img src="https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v14-orange?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/SOAR-Automated%20%26%20Interactive-critical?style=for-the-badge" alt="SOAR" />
  <img src="https://img.shields.io/badge/TUI-Bubbletea%20%2F%20Lipgloss-green?style=for-the-badge" alt="TUI" />
</p>

---

## 🛡 System Overview

**CoPSeC** is a high-throughput, dual-layer SIEM/EDR & SOAR platform written entirely in Go. Designed for Blue/Purple Team operators, it bridges the gap between low-level kernel/network events and actionable threat intelligence. 

Unlike heavy, resource-hungry web-based SIEMs, CoPSeC leverages:
* **Microsecond-latency Inotify Log Streaming:** Real-time ingestion from Nginx, Auth (SSH), and Syslog sources.
* **Shannon Entropy Analytics:** Instant heuristic detection of obfuscated payloads, base64 blobs, and raw binary shellcodes.
* **Dynamic Cyber Kill Chain Alignment:** Real-time mapping against MITRE ATT&CK techniques.
* **Dual-Action SOAR Defense:** Automated firewall policy enforcement paired with Telegram-based remote command & telemetry execution.

---

## 🏛 Technical Architecture

```text
                              [ ATTACK VECTOR ]
                   (SQLi / RCE / Brute-Force / LFI Probes)
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EDGE NODE COLLECTOR (VDS)                           │
│  ├─ Multi-Source Inotify Tailers (/var/log/{nginx,auth,syslog})             │
│  ├─ Pre-Routing CIDR / IP Whitelist In-Memory Fast Path                     │
│  ├─ Self-Healing SQLite Buffer (Zero-Loss Offline Resilience)               │
│  └─ SOAR Execution Core (Active iptables DROP Enforcement)                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ [TLS 1.3 / gRPC Protobuf Stream]
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CENTRAL SOC CONTROLLER                               │
│  ├─ Signature Matching, Regex Filters & Shannon Entropy Engine              │
│  ├─ MITRE ATT&CK Correlator & Cyber Kill Chain Stage Tracker                │
│  ├─ SQLite Forensic Storage & Full-Text Search Engine                       │
│  └─ 6-Panel Cyberpunk SOC Cockpit (Bubbletea / Lipgloss)                    │
└──────────────────────┬───────────────────────────────┬──────────────────────┘
                       │                               │
                       ▼                               ▼
┌─────────────────────────────────────┐ ┌─────────────────────────────────────┐
│     INTERACTIVE TELEGRAM BOT        │ │        CYBER DEFENSE COCKPIT        │
│  - Instant High-Threat Alerts       │ │  - Deep Forensic Inspection [Enter] │
│  - Inline [BAN] / [WHITELIST] Cards │ │  - Live Attack Sparklines & EPS     │
│  - Interactive Remote Commands      │ │  - Active Jail & Top Hot Targets    │
└─────────────────────────────────────┘ └─────────────────────────────────────┘
```

---

## 🎛 TUI Cockpit Structure

The terminal UI is divided into 6 distinct analytical panes:

1. **Fleet Matrix & Telemetry:** Monitors edge agent health, CPU/RAM consumption, round-trip ping latency, and open exposed ports.
2. **SOAR Jail & Mitigations:** Live ledger of blocked IP addresses, rule tags, and time-to-live expiration metrics.
3. **Live Ingestion Stream:** High-velocity raw log feed with real-time Shannon Entropy metrics and velocity sparklines.
4. **Critical Incidents Panel:** High-priority threat inbox (`ThreatScore >= 50`) with color-coded severity tiers.
5. **Enterprise MITRE Intel:** Dynamic ATT&CK heatmap visualizer and Cyber Kill Chain progression indicator.
6. **Geographic Threat Radar & Actors:** Enriched threat intelligence detailing attacker ASNs, GeoIP tags, and detected scanner signatures.

---

## ⌨️ Operator Shortcuts

| Key Binding | Functionality |
| :--- | :--- |
| `[/]` or `[F]` | Open full-text forensic search modal (e.g. `mitre:T1190`, `src:nginx`) |
| `[Tab]` | Toggle active focus between Ingestion and Incident panels |
| `[Enter]` | Open **Forensic Inspection Card** for the selected event |
| `[B]` / `[U]` | Instantly execute **SOAR Ban / Unban** on the highlighted attacker IP |
| `[Space]` | Freeze / Resume live telemetry stream |
| `[↑ / ↓]` / `[PgUp / PgDn]` | Scroll history using the dynamic cyberpunk neon scrollbar |
| `[Q]` | Gracefully terminate controller session |

---

## 🚀 Installation & Execution

### 1. Build & Run Central Controller
```bash
cd controller
go build -ldflags="-s -w" -o copsec-controller .

./copsec-controller \
  -grpc-addr "0.0.0.0:8443" \
  -rules "../config/rules.json" \
  -db "./data/copsec.db" \
  -telegram-token "<YOUR_BOT_TOKEN>" \
  -telegram-chat "<YOUR_CHAT_ID>"
```

### 2. Build & Deploy Edge Collector (VDS / Target Node)
```bash
cd collector
go build -ldflags="-s -w" -o copsec-collector .

sudo ./copsec-collector \
  -controller "<CONTROLLER_IP>:8443" \
  -nginx-log "/var/log/nginx/access.log" \
  -auth-log "/var/log/auth.log" \
  -syslog "/var/log/syslog" \
  -whitelist "/etc/copsec/whitelist.json"
```

---

## 🤖 Remote Telegram SOC Operations

Operate the entire defense grid remotely via verified Telegram chat commands:

* `/ban <IP>` — Broadcasts an instant `iptables -I INPUT -s <IP> -j DROP` command to all nodes.
* `/unban <IP>` — Removes active firewall restriction.
* `/whitelist <IP>` — Appends IP to `/etc/copsec/whitelist.json` and evades detection.
* `/status` — Fetches connected node telemetries, incident rates, and active jail count.
* `/help` — Lists operational documentation.

---

## 📄 License
Released under the [MIT License](LICENSE).
