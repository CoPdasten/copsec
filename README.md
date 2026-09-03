# CoPSeC — Enterprise Autonomous XDR & Kernel-Level Threat Prevention Platform

> Autonomous, kernel-native intrusion detection, deception, cryptographic audit chaining, and real-time SOC triage ecosystem built with Go, eBPF/XDP, and SQLite.

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Kernel-eBPF%20%2F%20XDP-orange?style=for-the-badge&logo=linux&logoColor=white" alt="eBPF/XDP" />
  <img src="https://img.shields.io/badge/Deception-TCP%20Zero--Window%20Tarpit-blue?style=for-the-badge" alt="TCP Tarpit" />
  <img src="https://img.shields.io/badge/Crypt-SHA--256%20Merkle%20Chaining-red?style=for-the-badge" alt="SHA-256 Hash Chain" />
  <img src="https://img.shields.io/badge/SOAR-Autonomous%2060s%20Correlation-critical?style=for-the-badge" alt="SOAR" />
  <img src="https://img.shields.io/badge/Cockpit-High--Contrast%20Monochrome-black?style=for-the-badge" alt="SOC Cockpit" />
</p>

---

## 🏛️ Architecture Overview

CoPSeC partitions responsibilities between high-speed kernel edge sensors (**Collectors**) and a centralized intelligence & policy orchestrator (**Controller**), interconnected over secure mTLS/WebSocket channels and visualized via a high-contrast zero-latency analyst cockpit.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                     ATTACK TRAFFIC                                      │
│                      (DDoS / Exploit Probes / Port Scans / Obfuscated RCE)              │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              COLLECTOR (EDGE / FLEET NODES)                             │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  Kernel Space: eBPF / XDP Ingress Engine (Driver Fast-Path)                         │ │
│ │  ├─ BPF Hash Maps (Active Blocklists & Quarantine Table)                            │ │
│ │  ├─ XDP_DROP Action (<10µs Line-Rate Sub-Millisecond Drop)                          │ │
│ │  └─ XDP_PASS / Kernel Network Stack Delivery                                        │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
│                                           ▼                                             │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  User Space Defense & Telemetry Daemon                                              │ │
│ │  ├─ TCP Zero-Window Tarpit Engine (Connection Stalling / Resource Depletion)        │ │
│ │  ├─ Honeypot Deception Router (Decoy Traps & Attacker Profiling)                    │ │
│ │  ├─ Multi-Source Ingestion: Suricata EVE JSON, Nginx Access, Linux Auth (/var/log)  │ │
│ │  └─ Atomic Quarantine Dispatch Receiver (Local Kernel BPF Map Synchronizer)         │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
└───────────────────────────────────────────┼─────────────────────────────────────────────┘
                                            │ mTLS / Encrypted WebSocket Fleet Sync
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               CONTROLLER (CENTRAL BRAIN)                                │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  Threat Engine & Correlation Core                                                   │ │
│ │  ├─ Snort & Suricata Signature Engine + MITRE ATT&CK CTI Mapping                     │ │
│ │  ├─ Shannon Entropy Payload Analyzer (Obfuscated Base64, Shellcode, Packed Payloads)│ │
│ │  ├─ Threat Intel Radix/Trie IP Lookups & CIDR Fast-Matching                         │ │
│ │  └─ 60-Second Sliding Window SOAR Correlator (Multi-Vector Fusion: Scan+Auth+Entropy)│ │
│ ├─────────────────────────────────────────────────────────────────────────────────────┤ │
│ │  Immutable Storage & Cryptographic Verification                                     │ │
│ │  ├─ SQLite Forensic State & Incident History Store                                  │ │
│ │  ├─ SHA-256 Sequential Hash-Chaining (`prev_hash` -> `entry_hash` Non-Repudiation)  │ │
│ │  └─ Integrity Audit Verification Engine (`/api/audit/verify-integrity`)             │ │
│ ├─────────────────────────────────────────────────────────────────────────────────────┤ │
│ │  Global Fleet Sync Manager                                                          │ │
│ │  └─ Broadcast Atomic Fleet Quarantine across all connected edge nodes               │ │
│ └─────────────────────────────────────────┬───────────────────────────────────────────┘ │
└───────────────────────────────────────────┼─────────────────────────────────────────────┘
                                            │ Secure WebSocket Stream
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              ANALYST COCKPIT (SOC UI)                                   │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │  High-Contrast Monochrome Triage Interface                                          │ │
│ │  ├─ Real-Time Telemetry Stream with Pause/Freeze Control ([Space])                   │ │
│ │  ├─ Zero-Wait Auto-Advance Drawer Triage Workflow                                    │ │
│ │  ├─ Hotkey Operational Actions: [B] Global Ban / [X] Dismiss / [U] Unban             │ │
│ │  └─ Single-Click DFIR Markdown / Forensic Report Export                             │ │
│ └─────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Technical Features

### 1. Kernel-Level Prevention & Deception
* **Sub-Millisecond `XDP_DROP`:** Offloads packet filtering directly to the network interface card (NIC) driver hook via eBPF/XDP before packets enter the Linux network stack or allocate `sk_buff` structures.
* **TCP Zero-Window Tarpit:** Traps aggressive scanning bots and brute-forcers in zero-window TCP sessions, exhausting attacker connection pools while consuming negligible host memory.
* **Honeypot Deception Routing:** Transparently routes unauthorized service probes and lateral movements to decoy handlers for real-time attacker behavioral profiling.

### 2. Hybrid Detection & Shannon Entropy Engine
* **Signature Mapping:** Native integration with Suricata EVE JSON streams and Snort signature schemas for immediate, high-fidelity CVE and exploit pattern recognition.
* **Shannon Entropy Analysis:** Mathematical entropy calculations applied to raw HTTP payloads, authentication headers, and request buffers to detect high-entropy payloads (e.g., XOR-encoded shellcode, packed malware, Base64 obfuscated scripts, and Cobalt Strike stagers):
  $$\mathcal{H}(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

### 3. Autonomous SOAR & Threat Correlation
* **60-Second Sliding Window Aggregation:** Continuously aggregates discrete security signals (such as port scan bursts, failed credential attempts, honeypot touches, and high-entropy payloads) per source IP and CIDR.
* **Automated Mitigation Trigger:** Computes a real-time composite Threat Score ($0 - 100$). Any source achieving $\text{ThreatScore} \ge 90$ immediately triggers automated kernel-level mitigation and fleet-wide broadcast.

### 4. Cryptographic Log Chaining (Non-Repudiation)
* **Sequential SHA-256 Merkle-Chain:** Every audit record and telemetry event is cryptographically linked to the preceding entry:
  $$\text{EntryHash}_k = \text{SHA256}(\text{EntryHash}_{k-1} \,\|\, \text{Timestamp} \,\|\, \text{EventData})$$
* **Tamper-Proof Audit Trails:** Any modification, truncation, or insertion breaks the chain integrity, providing non-repudiation for incident investigations.
* **Verification Endpoint:** Instant verification of the entire log chain via `/api/audit/verify-integrity`.

### 5. Global Fleet Synchronization & Standalone Local/PC Mode
* **Atomic Quarantine Dispatch:** When a threat is neutralized or banned on one node or by the central SOAR engine, an atomic quarantine directive is pushed over mTLS/WebSocket to every registered edge collector.
* **Kernel Map Synchronization:** Edge collectors immediately update local in-kernel BPF hash maps without daemon restart or socket drops.
* **Standalone "PC Mode" (`--mode=standalone` / `--standalone`):** Run full CoPSeC capabilities on a single workstation, laptop, or test VM without distributed collectors or complex network setups. Automatically launches built-in local log watchers, eBPF probes, and threat mitigations in one self-contained process.

### 6. Built-in SigmaHQ Sync, DNS Sinkhole & YARA In-Memory Inspection
* **SigmaHQ Rules Engine:** Automated live streaming and parsing of official SigmaHQ detection rules with tarball stream decompressors and directory filtering.
* **DNS Sinkhole & DGA Defense:** Intercepts rogue domain lookups, fast-flux DNS exfiltration, and C2 beacons with automated threat scoring and containment.
* **YARA In-Memory Process Scanner:** Live memory buffer inspection against Cobalt Strike stagers, web shell injectors, and raw shellcode execution.

### 7. SOC Cockpit & Hardened Application Security
* **Direct Database File Download Protection:** Router-level rejection of direct SQLite and database dump exposures (`.db`, `.db-wal`, `.db-shm`, `.sqlite`, `.sql`).
* **Timing-Safe Authentication:** API key token validation powered by constant-time comparisons (`crypto/subtle.ConstantTimeCompare`).
* **Instant Incident Chaining on Quarantine:** SOAR manual or autonomous ban/unban triggers automatically persist, cryptographically chain, and broadcast high-severity alerts to the SOC Cockpit.
* **High-Contrast Monochrome Aesthetic:** Designed for high visual clarity and reduced fatigue during extended incident response rotations.
* **Keyboard Hotkey Control:** Full operational coverage via keyboard shortcuts:
  * `[Space]` — Freeze / Resume live telemetry stream.
  * `[B]` — Enforce global kernel ban on selected entity.
  * `[X]` — Dismiss alert / False positive.
  * `[E]` — Single-click DFIR Markdown / Forensic Report export.

---

## 🚀 Quick Start & Deployment

### Prerequisites
- Linux Kernel >= 5.8 (eBPF/XDP support)
- Go 1.22+
- `suricata`, `sqlite3`, `libpcap`

---

### Standalone PC Mode (Single Machine / Workstation)

Run Controller and local edge telemetry monitoring in a single process:

```bash
cd controller
go build -ldflags="-s -w" -o copsec-standalone .
sudo ./copsec-standalone --mode=standalone --auth-key="YOUR_STRONG_API_KEY"
```

---

### Distributed Architecture: Build & Run Controller

```bash
cd controller
go build -ldflags="-s -w" -o copsec-controller .
sudo ./copsec-controller --port=8080 --auth-key="YOUR_STRONG_API_KEY"
```

---

### Distributed Architecture: Build & Run Collector

```bash
cd collector
go build -ldflags="-s -w" -o copsec-collector .
sudo ./copsec-collector --controller-url ws://localhost:8080/ws/collector --api-key="YOUR_STRONG_API_KEY"
```

---

## 🔒 Cryptographic Integrity Audit

Verify the non-repudiation and SHA-256 hash-chain integrity of all telemetry records and audit logs stored in the platform:

```bash
curl -s http://localhost:8080/api/audit/verify-integrity | jq .
```

```json
{
  "status": "VERIFIED",
  "verified_records": 14208,
  "head_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "tamper_detected": false,
  "timestamp": "2026-08-30T22:30:00Z"
}
```

---

## 🛡️ Telemetry & REST API Reference

The CoPSeC Controller exposes a REST API for automated SOAR orchestration, telemetry ingestion, and SOC integration.

### 1. Active Threat Alerts
Retrieve live threat alerts filtered by status, threat score, or kill-chain stage.

* **Endpoint:** `GET /api/alerts?status=ACTIVE`
* **Response:**
  ```json
  [
    {
      "id": "alt_01H9X8V9",
      "src_ip": "198.51.100.23",
      "status": "ACTIVE",
      "threat_score": 94,
      "shannon_entropy": 7.82,
      "rule": "SURICATA_ET_EXPLOIT_RCE_GENERIC",
      "mitre_technique": "T1059.004",
      "vectors": ["PORT_SCAN", "HIGH_ENTROPY_PAYLOAD", "AUTH_BRUTE_FORCE"],
      "first_seen": "2026-08-30T22:28:10Z",
      "last_seen": "2026-08-30T22:29:05Z"
    }
  ]
  ```

---

### 2. Manual & Automated Quarantine Ban
Issue an atomic global ban command. Automatically broadcasts to all connected collector nodes to update local in-kernel BPF hash maps via `XDP_DROP`.

* **Endpoint:** `POST /api/quarantine/ban`
* **Headers:** `Content-Type: application/json`
* **Request Payload:**
  ```json
  {
    "ip": "198.51.100.23",
    "duration_seconds": 3600,
    "reason": "Autonomous SOAR threshold exceeded (ThreatScore=94)",
    "scope": "GLOBAL_FLEET"
  }
  ```
* **Response:**
  ```json
  {
    "status": "ENFORCED",
    "target_ip": "198.51.100.23",
    "nodes_synchronized": 12,
    "xdp_rule_id": "bpf_map_entry_904",
    "expires_at": "2026-08-30T23:29:05Z"
  }
  ```

---

### 3. Audit Trail Integrity Verification
Cryptographically traverse the sequential SHA-256 Merkle chain from root to head to guarantee tamper-resistance.

* **Endpoint:** `GET /api/audit/verify-integrity`
* **Response:**
  ```json
  {
    "status": "VERIFIED",
    "total_records": 14208,
    "tamper_detected": false,
    "root_hash": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    "head_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "verification_time_ms": 1.42
  }
  ```

---

### 4. Fleet Nodes Telemetry & Health
Enumerate all registered edge collectors, connection health, kernel XDP status, and packet drop metrics.

* **Endpoint:** `GET /api/fleet/nodes`
* **Response:**
  ```json
  [
    {
      "node_id": "edge-sensor-prod-us-east-1",
      "ip": "10.0.4.12",
      "kernel_version": "6.5.0-35-generic",
      "xdp_mode": "DRV_FAST_PATH",
      "status": "HEALTHY",
      "active_bpf_bans": 142,
      "packets_dropped_xdp": 1205943,
      "tarpit_sessions_active": 18,
      "last_heartbeat": "2026-08-30T22:30:40Z"
    }
  ]
  ```

---

## 📄 License
Released under the [MIT License](LICENSE).

