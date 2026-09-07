# CoPSeC — Enterprise Autonomous XDR & Kernel-Level Threat Prevention Platform

> Autonomous, kernel-native intrusion detection, deception honey-tokens, pre-attack PCAP forensics, cryptographic audit chaining, eBPF EDR, and real-time multi-node SOC triage ecosystem built with Go, eBPF/XDP, C++, and SQLite.

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Kernel-eBPF%20%2F%20XDP-orange?style=for-the-badge&logo=linux&logoColor=white" alt="eBPF/XDP" />
  <img src="https://img.shields.io/badge/Deception-Honey--Tokens%20%26%20Tarpit-blue?style=for-the-badge" alt="Honey Tokens & Tarpit" />
  <img src="https://img.shields.io/badge/Forensics-Pre--Attack%20PCAP%20Buffer-purple?style=for-the-badge" alt="PCAP Forensics" />
  <img src="https://img.shields.io/badge/Crypt-SHA--256%20Merkle%20Chaining-red?style=for-the-badge" alt="SHA-256 Hash Chain" />
  <img src="https://img.shields.io/badge/Fleet-gRPC%20Multi--Node%20Mesh-green?style=for-the-badge" alt="gRPC Fleet Mesh" />
  <img src="https://img.shields.io/badge/Cockpit-High--Contrast%20Monochrome-black?style=for-the-badge" alt="SOC Cockpit" />
</p>

---

## 🏛️ Architecture Overview

CoPSeC partitions responsibilities between high-speed kernel edge sensors (**Collectors**) and a centralized intelligence & policy orchestrator (**Controller**), interconnected over secure bidirectional gRPC/mTLS channels and visualized via a high-contrast zero-latency analyst cockpit.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                     ATTACK TRAFFIC                                      │
│               (DDoS / Exploit Probes / Port Scans / Obfuscated RCE / DNS Exfil)          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              COLLECTOR (EDGE / FLEET NODES)                             │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  Kernel Space: eBPF / XDP Ingress Engine (Driver Fast-Path)                         │ │
│ │  ├─ BPF Hash Maps (Active Blocklists & Quarantine Table)                            │ │
│ │  ├─ XDP_DROP Action (<10µs Line-Rate Sub-Millisecond Drop)                          │ │
│ │  ├─ eBPF EDR: Process Injection Guard (ptrace, process_vm_writev, memfd_create)      │ │
│ │  └─ XDP_PASS / Kernel Network Stack Delivery                                        │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
│                                           ▼                                             │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  User Space Defense & Telemetry Daemon                                              │ │
│ │  ├─ TCP Zero-Window Tarpit Engine (Connection Stalling / Resource Depletion)        │ │
│ │  ├─ Pre-Attack PCAP Ring Buffer (Circular In-Memory Network Frame Capture)          │ │
│ │  ├─ Deception Honey-Token Engine (Canary AWS Keys, DB Strings, API Tokens)          │ │
│ │  ├─ Multi-Source Tailers: Suricata EVE JSON, Snort 3, Nginx, Linux Auth, Auditd     │ │
│ │  ├─ Offline Buffer Queue (SQLite Local Resiliency upon Controller Disconnect)       │ │
│ │  └─ Autonomous Fallback SOAR Sensor (Self-Preservation & Local Mitigations)         │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
└───────────────────────────────────────────┼─────────────────────────────────────────────┘
                                            │ Bidirectional gRPC Fleet Stream (<=50ms Sync)
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               CONTROLLER (CENTRAL BRAIN)                                │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  Threat Intelligence & SOAR Correlation Core                                        │ │
│ │  ├─ Snort & Suricata Signature Engine + MITRE ATT&CK CTI Mapping                     │ │
│ │  ├─ Shannon Entropy Engine (Payloads, Base64 Shellcode, DNS Tunneling Analysis)     │ │
│ │  ├─ IPinfo & GeoIP Autonomous ASN Risk Multiplier                                   │ │
│ │  ├─ CIDR Dynamic Whitelist Engine with Radix Tree & Self-Lockout Guard              │ │
│ │  ├─ Zero Trust Contextual Scoring Engine (Session Isolation Trigger)                │ │
│ │  └─ 60-Second Sliding Window Multi-Signal Fusion (Scan + Auth + Entropy + Canary)   │ │
│ ├─────────────────────────────────────────────────────────────────────────────────────┤ │
│ │  Immutable Storage & Cryptographic Verification                                     │ │
│ │  ├─ SQLite Forensic State & Incident History Store                                  │ │
│ │  ├─ SHA-256 Sequential Hash-Chaining (`prev_hash` -> `entry_hash` Non-Repudiation)  │ │
│ │  └─ Integrity Audit Verification Engine (`/api/audit/verify-integrity`)             │ │
│ ├─────────────────────────────────────────────────────────────────────────────────────┤ │
│ │  Global Fleet Manager Hub                                                           │ │
│ │  ├─ Real-Time Node Health, Resource Telemetry & Lifecycle Tracking                  │ │
│ │  └─ Concurrent Ban Broadcast & Rollout across entire Edge Fleet Mesh                │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
└───────────────────────────────────────────┼─────────────────────────────────────────────┘
                                            │ Secure WebSocket Stream / REST API
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              ANALYST COCKPIT (SOC UI)                                   │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  High-Contrast Monochrome Triage Interface                                          │ │
│ │  ├─ Real-Time Telemetry Stream with Pause/Freeze Control ([Space])                   │ │
│ │  ├─ Zero-Wait Auto-Advance Drawer Triage Workflow                                    │ │
│ │  ├─ Honey-Token Canary Management & Pre-Attack PCAP Download                        │ │
│ │  ├─ Hotkey Operational Actions: [B] Global Ban / [X] Dismiss / [U] Unban             │ │
│ │  └─ Single-Click DFIR Markdown / Forensic Report Export                             │ │
│ └─────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Technical Features

### 1. Kernel-Level Prevention & eBPF EDR
* **Sub-Millisecond `XDP_DROP`:** Offloads packet filtering directly to the network interface card (NIC) driver hook via eBPF/XDP before packets enter the Linux network stack or allocate `sk_buff` structures.
* **eBPF EDR & Process Injection Kill:** Hooks system calls (`ptrace`, `process_vm_writev`, `memfd_create`, `execve`) to detect code injection, reflective DLL loading, memory patching, and fileless binary execution, automatically terminating compromised PIDs via `SIGKILL`.
* **TCP Zero-Window Tarpit:** Traps aggressive scanning bots and brute-forcers in zero-window TCP sessions, exhausting attacker connection pools while consuming negligible host memory.

### 2. Deception & Canary Honey-Tokens
* **Zero-False-Positive Honey-Tokens:** Dynamically generates high-enticing decoy credentials (AWS Access Keys `AKIA...`, PostgreSQL/MySQL connection strings, bearer tokens) placed in code repositories, config files, and honeypots.
* **Instant Incident Trigger:** Any read or usage of a honey-token triggers immediate 100/100 critical scoring, pre-attack PCAP preservation, and fleet-wide attacker isolation.

### 3. Pre-Attack Forensics & PCAP Ring Buffer
* **Circular In-Memory Frame Capture:** Continuously records full raw Ethernet/IP packets in an in-memory ring buffer (up to 100,000 packets per node).
* **Automated Incident Snapshot:** When a critical alert or SOAR quarantine triggers, the engine instantly dumps the preceding 10–30 seconds of raw network traffic into a forensic `.pcap` file ready for Wireshark and DFIR analysis.

### 4. Shannon Entropy Engine & DNS Tunneling Detection
* **Payload Entropy Calculation:** Mathematical entropy calculations applied to raw HTTP payloads, authentication headers, and request buffers to detect high-entropy payloads (e.g., XOR-encoded shellcode, packed malware, Base64 obfuscated scripts, and Cobalt Strike stagers):
  $$\mathcal{H}(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* **DNS Tunneling & DGA Defense:** Analyzes subdomains and query names for high entropy ($\mathcal{H} \ge 3.8$), excessive query length, base32/base64 encoding, and rapid NXDOMAIN bursts to detect DNS data exfiltration and C2 beaconing.

### 5. Multi-Node gRPC Fleet Mesh & Offline Resiliency
* **Bidirectional gRPC Streaming:** High-performance protobuf streaming between edge collector nodes and the central controller hub.
* **<=50ms Cluster-Wide Ban Propagation:** When a ban directive is issued, it is simultaneously broadcasted to all connected fleet nodes in parallel.
* **Offline SQLite Buffer:** If an edge node loses network connectivity to the controller, telemetry events and quarantine logs are safely queued in a local SQLite buffer and automatically drained upon reconnection.

### 6. Cryptographic Log Chaining (Non-Repudiation)
* **Sequential SHA-256 Merkle-Chain:** Every audit record and telemetry event is cryptographically linked to the preceding entry:
  $$\text{EntryHash}_k = \text{SHA256}(\text{EntryHash}_{k-1} \,\|\, \text{Timestamp} \,\|\, \text{EventData})$$
* **Tamper-Proof Audit Trails:** Any modification, truncation, or insertion breaks the chain integrity, providing non-repudiation for incident investigations.
* **Verification Endpoint:** Instant verification of the entire log chain via `/api/audit/verify-integrity`.

### 7. Standalone "PC Mode" & Cross-Platform Quarantine
* **Standalone Workstation Mode (`--mode=standalone` / `--standalone`):** Run full CoPSeC capabilities on a single workstation, laptop, or test VM without distributed collectors or complex network setups. Automatically launches built-in local log watchers, eBPF probes, and threat mitigations in one self-contained process.
* **Cross-Platform Quarantine Drivers:** Seamless driver abstraction supporting Linux (`iptables`, `conntrack`, `XDP`, `ss`, `nginx`) and Windows (`netsh advfirewall`).

---

## 🚀 Quick Start & Deployment

### Prerequisites
- Linux Kernel >= 5.8 (Debian, Ubuntu, Pardus, CentOS, AlmaLinux, Rocky Linux, RHEL, Fedora, Arch)
- Go 1.22+
- `sqlite3`, `curl`, `jq`, `libpcap-dev`, `openssl`, `iptables`, `conntrack`

---

### Automated Deployment Options

#### Option A: Central Controller Setup
Deploys the central controller with Web SOC Cockpit, gRPC Fleet Mesh, SQLite state engine, and Deception Honey-Token API:
```bash
sudo ./install.sh --port 8080 --api-key "YOUR_MASTER_API_KEY"
```

#### Option B: Edge Collector Setup (Pardus / Debian / Ubuntu / RHEL)
Installs the edge collector sensor and connects it to the central controller:
```bash
sudo bash scripts/install-agent.sh \
  --controller 192.168.1.10:8443 \
  --api-key "YOUR_MASTER_API_KEY" \
  --group "PARDUS_EDGE"
```

#### Option C: Standalone PC Mode (Single Machine / Laptop / Lab)
Runs both controller and edge monitoring in a single standalone binary:
```bash
cd controller
go build -ldflags="-s -w" -o copsec-standalone .
sudo ./copsec-standalone --mode=standalone --auth-key="YOUR_MASTER_API_KEY"
```

---

## 🛡️ REST API Reference

The CoPSeC Controller exposes REST endpoints for automated SOAR orchestration, telemetry ingestion, and SOC integration.

All endpoints require the `X-API-Key: <YOUR_API_KEY>` header.

### 1. Fleet Nodes Telemetry & Health
* **Endpoint:** `GET /api/nodes`
* **Description:** Lists all registered edge collectors, CPU/RAM usage, active BPF bans, and real-time connection status.
* **Sample Response:**
  ```json
  [
    {
      "node_id": "node-pardus-edge",
      "hostname": "pardus-edge",
      "group_name": "PARDUS_EDGE",
      "remote_addr": "192.168.1.11:46126",
      "last_seen_ms": 1788780068573,
      "cpu_usage": 0.0,
      "memory_usage": 870.23,
      "active_bans_count": 40,
      "uptime_seconds": 870,
      "status": "ACTIVE"
    }
  ]
  ```

---

### 2. Deception Honey-Tokens Management
* **List Active Tokens:** `GET /api/canary/tokens`
* **Generate New Canary Token:** `POST /api/canary/tokens`
* **Request Payload:**
  ```json
  {
    "type": "AWS_KEY",
    "metadata": "production-database-backup-s3"
  }
  ```
* **Sample Response:**
  ```json
  {
    "success": true,
    "token": {
      "token_value": "AKIATQRVAH7HL73UDDIK",
      "token_type": "AWS_KEY",
      "created_at_ms": 1788779278833,
      "triggered_count": 0,
      "metadata": "production-database-backup-s3"
    }
  }
  ```

---

### 3. Pre-Attack Forensics & PCAP Ring Buffer
* **List Captured PCAP Snapshots:** `GET /api/forensics/pcaps`
* **Download PCAP Snapshot:** `GET /api/forensics/download?file=attack_142.251.13.102_1788779212956.pcap`
* **Sample Response (`/api/forensics/pcaps`):**
  ```json
  {
    "success": true,
    "count": 18,
    "pcaps": [
      {
        "filename": "attack_157.180.28.32_1788779076081.pcap",
        "file_path": "/var/log/copsec/forensics/attack_157.180.28.32_1788779076081.pcap",
        "target_ip": "157.180.28.32",
        "reason": "Autonomous SOAR Zero-Latency Mitigation",
        "timestamp_ms": 1788779076081,
        "packet_count": 420,
        "file_size": 32840,
        "created_at": "2026-09-07T11:04:36Z"
      }
    ]
  }
  ```

---

### 4. Cryptographic Hash-Chain Integrity Verification
* **Endpoint:** `GET /api/audit/verify-integrity`
* **Description:** Cryptographically traverses the sequential SHA-256 Merkle chain from root to head to prove tamper-resistance.
* **Sample Response:**
  ```json
  {
    "valid": true,
    "integrity_status": "VERIFIED_VALID",
    "records_verified": 262561,
    "last_verified_hash": "14ee7b3f20ee3722433a935b81af97648bd34112ec25b9330b46820079db248e",
    "timestamp": "2026-09-07T14:21:09+03:00"
  }
  ```

---

### 5. Manual & Automated Quarantine Ban
* **Endpoint:** `POST /api/quarantine/ban`
* **Request Payload:**
  ```json
  {
    "ip": "198.51.100.23",
    "duration_seconds": 86400,
    "reason": "Manual SOC investigation quarantine"
  }
  ```

---

## 🧪 Comprehensive Verification & Test Suite

All components are rigorously tested across C++ unit tests, Go package suites, and live multi-node laboratory environments.

```bash
# 1. Run C++ / Fast-Path Whitelist Tests
ctest --test-dir build --output-on-failure

# 2. Run Root Go Unit & Regression Tests
go test -v ./...

# 3. Run Collector Edge Sensor Tests
cd collector && go test -v ./...

# 4. Run Controller & SOAR Engine Tests
cd controller && go test -v ./...
```

### Verified Multi-Node Lab Results
* **Pardus Server 1 (`192.168.1.11`):** Edge Collector active, eBPF XDP hook verified, telemetry streaming.
* **Pardus Server 2 (`192.168.1.12`):** Edge Collector active, Zero-Trust ban propagation verified in <=15ms.
* **Central Controller (`192.168.1.10`):** Web SOC (port 8080), gRPC Fleet Mesh (port 8443), 260,000+ cryptographically verified records.

---

## 📄 License
Released under the [GNU General Public License v3.0 (GPLv3)](LICENSE).
