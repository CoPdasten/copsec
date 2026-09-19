# CoPSeC High-Performance eBPF/XDP Active Defense Engine & Architecture Reference

## Architecture Overview

This document describes the CoPSeC Agent ecosystem, featuring:
- **Suricata NIDS/NIPS Ingestion** for real-time signature-based threat detection
- **eBPF/XDP Kernel-Level Packet Dropping** for high-performance traffic filtering
- **Hardened Management Plane (`:50052`)** with loopback default, Bearer auth, and TLS 1.3/mTLS
- **Automated Forensic PCAP Capture** for incident response analysis
- **Wazuh SIEM Integration** with custom decoders and rules
- **Systemd Hardening Profile** for production-grade security isolation
- **Zero-Copy POSIX Shared Memory & eBPF RingBuf IPC** for real-time telemetry
- **Offline-First SQLite Cache & Ring Buffer** for edge node resilience
- **Fail2ban Escalation Engine** with automatic CIDR `/24` aggregation
- **MITRE ATT&CK Threat Intelligence** with offline STIX 2.1 parsing

---

## 1. Suricata NIDS/NIPS Ingestion (`include/suricata_parser.hpp`)

### Features
- **Real-Time EVE JSON Streaming**: Monitors `/var/log/suricata/eve.json` continuously
- **Alert Filtering**: Captures only `event_type == \"alert\"` events
- **Alert Extraction**: Parses `src_ip`, `signature`, `signature_id`, `severity`, `proto`
- **Dynamic Escalation**: Feeds alerts into Fail2banEngine for time-based escalation
- **Auto-Aggregation**: Triggers `/24` CIDR blocking after 3+ hits in 10 minutes

### Data Flow
```
Suricata EVE Stream
    ↓
SuricataWatcher (callback)
    ↓
Fail2banEngine (escalation)
    ↓
XdpBouncer + Bouncer (nftables fallback)
    ↓
ShmServer (telemetry)
    ↓
copsec-cli shm (live view)
```

### CLI Usage
```bash
copsec-cli suricata status     # Show EVE stream status
```

---

## 2. eBPF/XDP Kernel-Level Packet Dropping (`include/xdp_bouncer.hpp`)

### Features
- **XDP-Capable NICs**: Drops malicious packets at driver level (pre-TCP/IP stack)
- **BPF_MAP_TYPE_HASH**: In-kernel IP blocklist with atomic updates
- **Fallback to nftables**: Automatic graceful degradation on unsupported NICs
- **Packet Statistics**: Track dropped/processed counts without copying

### Integration Points
- **Suricata Alerts** → Auto-block high-severity source IPs
- **Fail2ban Events** → Rate-limit escalated bans
- **Dynamic Updates** → No restart required

### CLI Usage
```bash
copsec-cli xdp status          # Show eBPF/XDP stats
```

---

## 3. Automated Forensic PCAP Capture (`include/pcap_capture.hpp`)

### Features
- **Ring-Buffer Capture**: Maintains circular packet buffer in background
- **Incident Triggers**: Records 10s before + 10s after ban decision
- **File Organization**: Stores to `/var/log/copsec/pcap/incident_{IP}_{TIMESTAMP}.pcap`
- **IR-Ready Format**: Standard libpcap format for Wireshark/tcpdump analysis

### Capture Triggers
- Suricata alerts (severity >= 2)
- Fail2ban escalations
- Manual CLI ban commands

### CLI Usage
```bash
copsec-cli pcap list           # List forensic PCAP files
```

---

## 4. Wazuh SIEM Integration

### Decoder (`config/copsec_decoders.xml`)
- JSON decoder for CoPSeC structured logs
- Parent mapping for threat event classification
- MITRE ATT&CK technique extraction

### Rule Set (`config/copsec_rules.xml`)
- **Rule 200101** (L5): IP Ban Detection
- **Rule 200102** (L7): High-Severity Threat
- **Rule 200103** (L8): Suricata NIDS Alert
- **Rule 200104** (L6): MITRE Technique Detection
- **Rule 200105** (L9): Critical Escalation
- **Rule 200106** (L10): Subnet-Wide Attack

### Integration Steps
```bash
sudo cp config/copsec_decoders.xml /var/ossec/etc/decoders/
sudo cp config/copsec_rules.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-control restart
```

---

## 5. Systemd Hardening Profile (`config/copsec.service`)

### Security Features
- **ProtectSystem=strict**: Read-only root filesystem
- **ProtectHome=read-only**: Home directory isolation
- **MemoryDenyWriteExecute=true**: Prevent code injection
- **PrivateTmp=true**: Isolated /tmp namespace
- **CapabilityBoundingSet**: Minimal required capabilities

### Installation
```bash
sudo cp config/copsec.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable copsec
sudo systemctl start copsec
```

---

## 6. Enterprise CLI Commands

```bash
# Show agent status + nftables bans
copsec-cli status

# Manual ban / unban
copsec-cli ban <IP> <seconds>
copsec-cli unban <IP>
copsec-cli flush

# Threat Intelligence
copsec-cli lookup <IP>              # Shodan enrichment
copsec-cli mitre <TECH> [--offline] # MITRE ATT&CK lookup

# Real-Time Telemetry
copsec-cli shm                      # Shared memory metrics
copsec-cli fail2ban status          # Ban escalation state

# Enterprise Features
copsec-cli suricata status          # NIDS alert stream
copsec-cli xdp status               # eBPF/XDP packet stats
copsec-cli pcap list                # Forensic PCAP files
```

---

## 7. Shared Memory IPC Telemetry (`include/shm_ipc.hpp`)

### Metrics
- **active_bans**: Current IP bans in kernel
- **total_processed_lines**: Log lines analyzed
- **total_threats**: Threat detections recorded
- **total_bans**: Historical ban count
- **ring_buffer**: Last 50 events (IP, rule, duration, timestamp)

### Zero-Copy Access
- POSIX `/dev/shm` backed (`/copsec_shm`)
- Lock-free reads from CLI
- Spinlock-protected writes from daemon
- No IPC overhead

---

## 8. Build & Deploy

### Build
```bash
cd /home/copdasten/Documents/CoPSeC/copsec
cmake -B build -S .
cmake --build build -j$(nproc)
```

### Dependencies
- **libnftables**: Kernel packet filtering
- **libcurl**: HTTP API clients (Shodan, Suricata)
- **libpcap** (optional): Forensic capture
- **libmaxminddb** (optional): GeoIP lookups
- **nlohmann_json**: JSON parsing
- **pthreads**: Multi-threading

### Installation
```bash
sudo cp build/copsec /usr/local/bin/
sudo cp build/copsec-cli /usr/local/bin/
sudo mkdir -p /var/log/copsec /var/run/copsec /var/log/copsec/pcap
sudo chmod 750 /var/log/copsec /var/run/copsec
```

---

## 9. Operational Flow

### Daemon Startup Sequence
1. Initialize shared memory IPC
2. Load whitelist & MITRE mappings
3. Initialize nftables ban table
4. Initialize XDP bouncer (fallback to nftables)
5. Initialize PCAP forensics
6. Start Suricata EVE watcher
7. Start log parser/monitor
8. Start sync thread (global blocklists)
9. Start telemetry thread (SHM updates)

### Detection & Response Pipeline
```
Log Source
    ↓
Parser (rules + regex)
    ↓
Honeypot Engine (trap detection)
    ↓
Rate Limiter (check_rate_limit)
    ↓
Fail2ban Escalation (multiplier + aggregation)
    ↓
CIDR Auto-Aggregation (/24)
    ↓
Shodan Enrichment (async)
    ↓
Bouncer (XDP → nftables)
    ↓
ShmServer.push_event() (telemetry)
    ↓
PCAP.record_incident() (forensics)
    ↓
Wazuh (syslog → SIEM)
```

---

## 10. Performance Characteristics

| Component | Latency | Throughput | Memory |
|-----------|---------|-----------|--------|
| Parser | <1ms | 10K lines/s | ~5MB |
| Fail2ban | <100µs | 1M ops/s | ~2MB |
| XDP (kernel) | <10µs | Line-rate | Variable |
| PCAP (ring) | N/A | Real-time | ~100MB |
| SHM IPC | <100ns | 100M ops/s | 5.6KB |
| Suricata feed | <5ms | Alert-driven | ~1MB |

---

## 11. File Structure

```
copsec/
├── include/
│   ├── suricata_parser.hpp       # NIDS alert ingestion
│   ├── xdp_bouncer.hpp           # eBPF/XDP packet filter
│   ├── pcap_capture.hpp          # Forensic capture engine
│   ├── fail2ban_engine.hpp       # Ban escalation + aggregation
│   ├── shm_ipc.hpp               # Zero-copy telemetry
│   ├── shodan.hpp                # Host intelligence
│   ├── mitre_fetcher.hpp         # CTI lookup
│   ├── stix_parser.hpp           # Offline MITRE STIX 2.1
│   ├── honeypot.hpp              # Decoy trap detection
│   ├── geoip.hpp                 # MaxMindDB lookup
│   └── ...
├── src/
│   ├── main.cpp                  # Daemon + component init
│   ├── parser.cpp                # Log monitor + rule engine
│   ├── bouncer.cpp               # nftables enforcement
│   ├── copsec_cli.cpp            # CLI tool
│   ├── logger.cpp                # JSON event logging
│   ├── mitre.cpp                 # MITRE mapping
│   └── ...
├── config/
│   ├── copsec_decoders.xml       # Wazuh decoders
│   ├── copsec_rules.xml          # Wazuh rule set
│   ├── copsec.service            # Systemd hardening
│   ├── rules.json                # Detection rules
│   ├── whitelist.json            # Trusted CIDR list
│   ├── shodan.json               # API keys
│   └── ...
├── build/
│   ├── copsec                    # Daemon binary
│   └── copsec-cli                # CLI binary
└── CMakeLists.txt                # Build configuration
```

---

## 12. Security Posture

### Defense Layers
1. **Detection**: Parser + Suricata + MITRE mapping
2. **Escalation**: Fail2ban with adaptive multiplier
3. **Enforcement**: eBPF/XDP + nftables fallback
4. **Isolation**: Systemd hardening + capability bounding
5. **Telemetry**: Zero-copy SHM + Wazuh SIEM
6. **Forensics**: Ring-buffer PCAP for IR

### Hardening
- Kernel-level packet drop (XDP)
- Read-only filesystem (systemd)
- Memory-safe construction (C++20)
- No privilege escalation required for network access
- Automatic cleanup on crash

---

## 13. Management Plane Security (`SensorManagementService` on `:50052`)

### Zero-Trust Access Control
1. **Loopback Default Binding**: The dynamic rule management listener binds exclusively to `127.0.0.1:50052` or UNIX domain socket `/var/run/copsec/mgmt.sock`. Wildcard (`0.0.0.0`) binding is rejected by default.
2. **Explicit Remote Management**: Remote interface binding strictly requires `--enable-remote-mgmt`.
3. **Authoritative Interceptors**: gRPC Unary and Stream Server Interceptors authenticate all calls using pre-shared Bearer tokens (`--mgmt-secret` or `COPSEC_MGMT_KEY`). Mismatched or missing credentials return `codes.Unauthenticated`.
4. **TLS 1.3 & mTLS Enforcement**: All non-loopback management connections mandate TLS 1.3 encryption (`--mgmt-tls-cert` and `--mgmt-tls-key`) with optional mutual TLS client certificate verification (`--mgmt-tls-ca`).

---

## 14. Telemetry Architecture & Scalable Storage Realism

### SQLite Boundaries
- **Edge Cache & Offline Spooling**: SQLite (WAL mode) functions as an ultra-lightweight, zero-dependency local buffer for edge nodes to survive network partitions without memory growth.
- **Concurrency Ceiling**: Single-writer database locking limits SQLite under sustained high-EPS workloads (>10k EPS).

### Enterprise High-EPS Pipelines
- **Kafka / Redpanda**: Partitioned message bus for decoupling high-volume edge event streams.
- **ClickHouse**: Columnar storage for petabyte-scale security telemetry and sub-second analytical queries.
- **PostgreSQL / TimescaleDB**: Relational case management, MITRE ATT&CK correlation, and incident lifecycle state.
- **Enterprise SIEM Streaming**: Non-blocking `RingChannelBuffer` streaming CEF and RFC 5424 Syslog over mTLS to Wazuh, Splunk, and Elastic.

---

## 15. Laboratory PoC Validation & Phase 2 Roadmap

### Verified Laboratory PoC Environment
- Benchmarks (111k PPS, sub-millisecond fast-path drops) were verified in an isolated 4-node virtualized lab environment (CachyOS, Pardus Linux, Kali Linux) using synthetic load generators (`hping3`, `scapy`) and RFC 5737 documentation test blocks (`198.51.100.0/24`).

### Phase 2 Evolution
- [ ] Multi-region bare-metal & cloud VPS deployments (AWS, Hetzner, Vultr with physical NIC SR-IOV/XDP).
- [ ] Live internet ingress testing and in-the-wild threat telemetry.
- [ ] Distributed WAN fuzzing and upstream BGP Anycast flapping resilience.
- [ ] Native ClickHouse and Kafka direct producer export plugins.
- [ ] eBPF CO-RE expansion across Linux kernels 5.15 through 6.12+.

---

**CoPSeC** | High-Performance eBPF/XDP Active Defense Engine | Validated in Multi-Node Lab PoC
