# CoPSeC Enterprise Threat Prevention Engine

[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Linux Kernel](https://img.shields.io/badge/Linux-kernel-2d2d2d?logo=linux&logoColor=white)](https://kernel.org/)
[![eBPF/XDP](https://img.shields.io/badge/eBPF%2FXDP-kernel%20offload-fcc624?logo=linux&logoColor=111111)](https://ebpf.io/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-CMake%20%7C%20GoogleTest-2ea44f)](CMakeLists.txt)

**CoPSeC Enterprise Threat Prevention Engine** is an open-source, Linux-native threat prevention daemon created by **CoPdasten**. It combines low-level C++20 packet enforcement, eBPF/XDP offload, `libnftables`, structured log inspection, threat-intelligence enrichment, and authenticated shared-memory telemetry in one operational engine.

> CoPSeC is designed for security-sensitive Linux deployments. Validate rules, capabilities, kernel support, and benchmark traffic in an isolated environment before production rollout.

## Architecture Overview

```text
                         KERNEL SPACE
+------------------------------------------------------------------+
|  XDP/eBPF programs          nftables/libnftables                 |
|  fast-path observation  ---> enforcement sets / timed bans       |
+-------------------+-------------------------------+--------------+
                    | events / packets              ^ commands
                    v                               |
+------------------------------------------------------------------+
|                 USER-SPACE COPSEC DAEMON                         |
|  Raw sockets / parser | Suricata EVE JSON | SOAR worker          |
|  anti-evasion         | rate limiter       | MITRE / TI engines  |
+----------------------+-------------------+-----------------------+
                       |
                       | authenticated lockless telemetry
                       v
+------------------------------------------------------------------+
| /dev/shm/copsec_shm: metrics, 50-entry atomic ring buffer, HMAC  |
+-------------------------------+----------------------------------+
                                ^
                                | read-only snapshots / management
+-------------------------------+----------------------------------+
|                         copsec-cli                               |
|  shm | ban/unban/flush | status | config-reload | intelligence   |
+------------------------------------------------------------------+
```

## Key Features

### Kernel and Performance

- C++20 daemon with strict compiler warnings and optimized release compilation.
- eBPF/XDP kernel network offloading through the programs in `bpf/` when `libbpf` and Clang are available.
- `libnftables` C-API bouncer integration for atomic enforcement sets and timed bans.
- L3/L4 raw-socket and packet-capture paths for low-latency network observation.
- Lock-protected, atomic shared-memory metrics and a bounded 50-event telemetry ring buffer.
- POSIX `SIGHUP` handling for configuration reload requests without stopping the daemon.

### Detection Capabilities

- Multi-layer threat detection across L3/L4 network traffic and L7 HTTP patterns.
- HTTP regex parsing and normalization for evasive encodings and malformed input.
- Sliding-window rate limiting and repeated-failure escalation.
- Suricata EVE JSON ingestion for deep-packet-inspection events.
- Whitelist-aware enforcement and forensic PCAP capture management.

### Threat Intelligence

- Automatic MITRE ATT&CK tactic and technique mapping, including examples such as `T1595.002`, `T1189`, and `T1059`.
- STIX 2.1 and TAXII-oriented parsing for offline and external intelligence workflows.
- Shodan and GeoIP enrichment when the corresponding services and databases are configured.
- Honeypot event ingestion and SOAR worker automation for response workflows.

### Management and Operations

- `copsec-cli` for service control, nftables ban management, intelligence lookups, and telemetry inspection.
- Shared-memory telemetry is protected by an HMAC key supplied through `COPSEC_SHM_HMAC_KEY`.
- Native GoogleTest target `test_bouncer` and a Python stress/performance harness.
- systemd service definition with resource limits, network capabilities, and journal logging.

## Repository Layout

```text
.
├── bpf/                    # XDP, kprobe, and ring-buffer eBPF programs
├── config/                 # Rules, whitelist, MITRE, service, and integration data
├── include/                # Public C++ headers and subsystem interfaces
├── src/                    # Daemon, CLI, bouncer, parsers, telemetry, and workers
├── tools/                  # Python benchmark and operational tooling
├── CMakeLists.txt          # CMake build and dependency definition
├── ENTERPRISE_ARCHITECTURE.md
├── LICENSE                 # GNU GPLv3
└── README.md
```

Generated build output belongs in `build/` and is intentionally not part of the source tree.

## Requirements

- Linux with a kernel supporting the required eBPF/XDP features for offload mode.
- CMake 3.16 or newer and a C++20 compiler.
- `pkg-config`, `libnftables`, `nlohmann_json`, pthreads, libcurl, OpenSSL, and SQLite3 development packages.
- Optional: Clang and `libbpf` for eBPF object compilation; libpcap and MaxMindDB for additional collectors and enrichment.
- Root or equivalent privileges for nftables, raw sockets, XDP attachment, `/dev/shm`, and system service installation.

On Debian-family systems, package names commonly include:

```bash
sudo apt install build-essential cmake pkg-config clang libbpf-dev \
  libnftables-dev nlohmann-json3-dev libcurl4-openssl-dev \
  libssl-dev libsqlite3-dev libpcap-dev libmaxminddb-dev \
  libgtest-dev
```

Package names vary by distribution. Install only the optional packages required by the deployment.

## Installation and Build

Clone the repository and configure an out-of-tree build:

```bash
git clone https://github.com/CoPSeC/copsec.git
cd copsec
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build --parallel
```

The main binaries are `build/copsec` and `build/copsec-cli`. If GoogleTest is not installed, CMake may fetch the pinned GoogleTest release during configuration; provide network access or install the distribution package first.

Install the daemon, CLI, and configuration files using your packaging policy. A minimal local installation is:

```bash
sudo install -Dm755 build/copsec /usr/local/bin/copsec
sudo install -Dm755 build/copsec-cli /usr/local/bin/copsec-cli
sudo install -d -m 0750 /etc/copsec /var/log/copsec /var/lib/copsec
sudo cp -a config/. /etc/copsec/
sudo install -Dm644 config/copsec.service /etc/systemd/system/copsec.service
sudo systemctl daemon-reload
sudo systemctl enable --now copsec.service
```

The service runs as root because packet enforcement and kernel attachment require elevated privileges. For a manually managed binary, capabilities can reduce the need for a fully privileged process, but the exact set must match the enabled collectors:

```bash
sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_nice+ep' /usr/local/bin/copsec
getcap /usr/local/bin/copsec
```

Review the systemd hardening settings and capability requirements before changing the service user.

## Configuration

The supplied service starts the daemon with `--config /etc/copsec/copsec.yaml`. In the current engine, a YAML path is treated as the deployment entry point for the rules directory `/etc/copsec/rules`; the repository's checked-in rule and integration data are JSON/XML files under `config/`. Keep the production configuration format aligned with the daemon version you deploy.

A deployment-level `/etc/copsec/copsec.yaml` should define, at minimum, these parameter groups:

| Group | Parameters | Purpose |
| --- | --- | --- |
| `paths` | `rules`, `whitelist`, `log`, `pcap`, `database` | Select rules, trusted CIDRs, JSON logs, captures, and SQLite storage locations. |
| `nftables` | `table`, `chain`, `set`, `ban_seconds` | Select the enforcement objects and default timed-ban policy. |
| `ebpf` | `enabled`, `interface`, `pin_path` | Enable XDP/eBPF, choose an interface, and select bpffs pinning. |
| `suricata` | `eve_path`, `enabled` | Enable and locate the Suricata EVE JSON stream. |
| `rate_limit` | `window_seconds`, `max_events`, `cooldown_seconds` | Configure sliding-window detection and escalation. |
| `threat_intel` | `shodan_api_key`, `maxmind_db`, `taxii_url` | Configure optional enrichment providers. Store secrets outside world-readable files. |
| `soar` | `enabled`, `webhook`, `timeout_seconds` | Configure automated response actions and timeouts. |
| `telemetry` | `shm_name`, `ring_capacity`, `hmac_key_env` | Configure `/dev/shm` naming and integrity-key sourcing. |

The daemon refuses to start unless `COPSEC_SHM_HMAC_KEY` is set. Use a protected systemd environment file or a secret manager; do not commit the key:

```bash
sudo install -d -m 0750 /etc/copsec
sudo sh -c 'printf "%s\n" "COPSEC_SHM_HMAC_KEY=<long-random-secret>" > /etc/copsec/copsec.env'
sudo chmod 0640 /etc/copsec/copsec.env
```

Add `EnvironmentFile=/etc/copsec/copsec.env` to the service's `[Service]` section, then run `sudo systemctl daemon-reload && sudo systemctl restart copsec`.

## CLI and Telemetry

Run the CLI as root, or grant only the narrowly required operational permissions through your service policy:

```bash
copsec-cli status
copsec-cli shm
copsec-cli config-reload
```

`shm` reads authenticated metrics and recent events from `/dev/shm/copsec_shm`. `config-reload` sends `SIGHUP` to the running daemon; verify the reload in the journal:

```bash
sudo journalctl -u copsec -f
```

Ban management uses nftables-backed timed sets:

```bash
sudo copsec-cli ban 203.0.113.10 3600
sudo copsec-cli ban list
sudo copsec-cli unban 203.0.113.10
sudo copsec-cli flush
```

Additional operational commands include `start`, `stop`, `restart`, `whitelist add/remove/list`, `lookup <ip>`, `mitre <technique>`, `xdp status`, `suricata status`, `fail2ban status`, `pcap list`, `purge-pcaps`, and `db-vacuum`. Run `copsec-cli help` for the installed binary's complete command list.

## Testing and Benchmarking

Build the test target and run the registered GoogleTest suite:

```bash
cmake --build build --target test_bouncer --parallel
ctest --test-dir build --output-on-failure
```

Run a bounded benchmark against a test deployment:

```bash
sudo tools/copsec_bench.py --mode all --duration 10 --eps 5000 --pid "$(pidof copsec)"
```

Useful modes are `a` for web logs, `b` for SSH logs, and `c` for packets. The default packet target is loopback. Raw SYN mode requires the explicit `--allow-network-flood` flag and must only be used against an isolated lab host:

```bash
sudo tools/copsec_bench.py --mode c --packet-kind udp \
  --target 127.0.0.1 --port 9999 --duration 5
```

Benchmark output is generated as `copsec_bench_report.json` and `copsec_bench_report.md`; these are local artifacts and should not be committed unless they are intentionally used as release evidence.

## Security and Operational Notes

- Treat detection rules and nftables changes as production security policy. Review them before deployment.
- Protect `COPSEC_SHM_HMAC_KEY`, Shodan credentials, TAXII credentials, and any SOAR webhook secret.
- Test XDP driver compatibility and fallback behavior on every target NIC and kernel combination.
- Use a dedicated lab network for packet-generation benchmarks.
- Inspect `journalctl -u copsec`, `/var/log/copsec/agent.log`, and `/var/lib/copsec/copsec.db` according to your retention policy.

## License and Author

CoPSeC Enterprise Threat Prevention Engine is Copyright (C) 2026 CoPdasten and is distributed under the **GNU General Public License version 3.0**. See [LICENSE](LICENSE) for the complete license text.
