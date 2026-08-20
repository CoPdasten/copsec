#!/usr/bin/env python3
"""CoPSeC threat-engine stress benchmark.

Examples:
  sudo tools/copsec_bench.py --mode all --duration 10 --eps 5000 --pid <copsec-pid>
  sudo tools/copsec_bench.py --mode a --duration 5 --eps 10000 --log-file /var/log/nginx/access.log
  sudo tools/copsec_bench.py --mode c --packet-kind udp --target 127.0.0.1 --port 9999 --duration 5

Raw SYN mode is intentionally gated by --allow-network-flood and should only target
an isolated lab host. The default packet mode sends UDP to loopback.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import json
import os
import pathlib
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

DEFAULT_AGENT_LOG = "/var/log/copsec/agent.log"
DEFAULT_PCAP_DIR = "/var/log/copsec/pcap"
DEFAULT_CLI = "./build/copsec-cli"
IP_POOL = [f"198.51.100.{value}" for value in range(10, 42)]


@dataclass
class LatencyStats:
    samples_us: List[float] = field(default_factory=list)
    observed: int = 0

    def summary(self) -> dict:
        if not self.samples_us:
            return {"samples": 0, "average_us": None, "p50_us": None, "p95_us": None, "max_us": None}
        values = sorted(self.samples_us)
        percentile = lambda ratio: values[min(len(values) - 1, int(len(values) * ratio))]
        return {
            "samples": len(values),
            "average_us": round(sum(values) / len(values), 2),
            "p50_us": round(percentile(0.50), 2),
            "p95_us": round(percentile(0.95), 2),
            "max_us": round(values[-1], 2),
        }


@dataclass
class Metrics:
    started_wall: float
    attempted_events: int = 0
    accepted_events: int = 0
    observed_events: int = 0
    observed_bans: int = 0
    max_rss_kib: int = 0
    max_cpu_percent: float = 0.0
    shm_samples_us: List[float] = field(default_factory=list)
    latency: LatencyStats = field(default_factory=LatencyStats)
    writes_by_ip: Dict[str, Deque[float]] = field(default_factory=lambda: collections.defaultdict(collections.deque))
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_write(self, ip: str, wall_time: float) -> None:
        with self.lock:
            self.attempted_events += 1
            self.writes_by_ip[ip].append(wall_time)

    def add_observation(self, ip: str, event_time: float, is_ban: bool) -> None:
        with self.lock:
            writes = self.writes_by_ip.get(ip)
            if writes:
                written = writes.popleft()
                self.latency.samples_us.append(max(0.0, (event_time - written) * 1_000_000))
            self.observed_events += 1
            self.latency.observed = self.observed_events
            if is_ban:
                self.observed_bans += 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CoPSeC synthetic attack and performance benchmark")
    parser.add_argument("--mode", choices=("a", "b", "c", "all"), default="a", help="a=web logs, b=SSH logs, c=packets")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--eps", type=int, default=5000, help="Target events per second for log modes")
    parser.add_argument("--log-file", default="", help="Override the log file for the selected log mode")
    parser.add_argument("--web-log", default="/var/log/nginx/access.log")
    parser.add_argument("--ssh-log", default="/var/log/auth.log")
    parser.add_argument("--agent-log", default=DEFAULT_AGENT_LOG)
    parser.add_argument("--pid", type=int, default=0, help="copsec PID; auto-discovered when omitted")
    parser.add_argument("--cli", default=DEFAULT_CLI)
    parser.add_argument("--shm-workers", type=int, default=4)
    parser.add_argument("--packet-kind", choices=("udp", "syn"), default="udp")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--packet-eps", type=int, default=10000)
    parser.add_argument("--allow-network-flood", action="store_true", help="Required for raw SYN mode")
    parser.add_argument("--output-prefix", default="copsec_bench_report")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def find_pid(explicit: int) -> Optional[int]:
    if explicit:
        return explicit
    for entry in pathlib.Path("/proc").glob("[0-9]*"):
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")
            if pathlib.Path(command.split()[0]).name == "copsec":
                return int(entry.name)
        except (OSError, ValueError, IndexError):
            continue
    return None


def read_proc_stats(pid: Optional[int]) -> tuple[int, int]:
    if not pid:
        return 0, 0
    try:
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        rss_match = re.search(r"^VmRSS:\s+(\d+)", status, re.MULTILINE)
        rss = int(rss_match.group(1)) if rss_match else 0
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        ticks = int(fields[13]) + int(fields[14])
        return rss, ticks
    except (OSError, ValueError, IndexError):
        return 0, 0


def sample_process(metrics: Metrics, pid: Optional[int], stop: threading.Event) -> None:
    previous_ticks = 0
    previous_time = time.monotonic()
    cpu_count = os.cpu_count() or 1
    while not stop.wait(0.25):
        rss, ticks = read_proc_stats(pid)
        now = time.monotonic()
        if rss:
            metrics.max_rss_kib = max(metrics.max_rss_kib, rss)
        if previous_ticks:
            clk = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            cpu = ((ticks - previous_ticks) / clk) / max(now - previous_time, 0.001) * 100.0 / cpu_count
            metrics.max_cpu_percent = max(metrics.max_cpu_percent, cpu)
        previous_ticks, previous_time = ticks, now


def observe_agent_log(metrics: Metrics, path: str, stop: threading.Event) -> None:
    log_path = pathlib.Path(path)
    try:
        position = log_path.stat().st_size
    except OSError:
        position = 0
    while not stop.wait(0.02):
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(position)
                for line in stream:
                    position = stream.tell()
                    if '"event"' not in line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event_type = event.get("event", {}).get("type", "")
                    ip = event.get("source", {}).get("ip", "")
                    if event_type not in {"AUTH_FAILURE_ATTEMPT", "IP_BANNED", "RULE_TRIGGER", "BAN_EVENT"} or not ip:
                        continue
                    timestamp = event.get("timestamp", "")
                    try:
                        event_time = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
                    except (ValueError, TypeError):
                        event_time = time.time()
                    metrics.add_observation(ip, event_time, event_type in {"IP_BANNED", "BAN_EVENT"})
        except OSError:
            pass


def shm_contention(metrics: Metrics, cli: str, workers: int, stop: threading.Event) -> None:
    def worker() -> None:
        while not stop.is_set():
            start = time.perf_counter_ns()
            try:
                subprocess.run([cli, "shm"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
                elapsed = (time.perf_counter_ns() - start) / 1000.0
                with metrics.lock:
                    metrics.shm_samples_us.append(elapsed)
            except (OSError, subprocess.TimeoutExpired):
                pass

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(0, workers))]
    for thread in threads:
        thread.start()
    while not stop.wait(0.25):
        pass
    for thread in threads:
        thread.join(timeout=1)


def web_line(index: int) -> str:
    ip = IP_POOL[index % len(IP_POOL)]
    attack = ("/.env", "/login?id=1%20UNION%20SELECT%201", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")[index % 3]
    return f'{ip} - - [18/Aug/2026:23:30:{index % 60:02d} +0000] "GET {attack} HTTP/1.1" 404 512 "-" "copsec-bench/1.0"\n', ip


def ssh_line(index: int) -> tuple[str, str]:
    ip = IP_POOL[index % len(IP_POOL)]
    return f"Aug 18 23:30:{index % 60:02d} parrot sshd[12345]: Failed password for invalid user bench{index % 1000} from {ip} port {40000 + index % 20000} ssh2\n", ip


def flood_log(metrics: Metrics, path: str, duration: float, eps: int, generator) -> None:
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + duration
    interval = 1.0 / max(eps, 1)
    next_emit = time.perf_counter()
    index = 0
    with open(path, "ab", buffering=0) as output:
        while time.monotonic() < deadline:
            line, ip = generator(index)
            wall = time.time()
            output.write(line.encode())
            metrics.add_write(ip, wall)
            metrics.accepted_events += 1
            index += 1
            next_emit += interval
            delay = next_emit - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
    metrics.attempted_events = max(metrics.attempted_events, index)


def checksum(data: bytes) -> int:
    result = 0
    for index in range(0, len(data), 2):
        word = data[index] << 8
        if index + 1 < len(data):
            word |= data[index + 1]
        result += word
        result = (result & 0xffff) + (result >> 16)
    return (~result) & 0xffff


def flood_packets(metrics: Metrics, target: str, port: int, duration: float, eps: int, kind: str, allow: bool) -> None:
    if kind == "syn" and not allow:
        raise RuntimeError("raw SYN mode requires --allow-network-flood")
    deadline = time.monotonic() + duration
    interval = 1.0 / max(eps, 1)
    next_emit = time.perf_counter()
    index = 0
    if kind == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"copsec-bench-udp"
        while time.monotonic() < deadline:
            sock.sendto(payload, (target, port))
            index += 1
            next_emit += interval
            delay = next_emit - time.perf_counter()
            if delay > 0: time.sleep(delay)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        source = socket.inet_aton("198.51.100.250")
        destination = socket.inet_aton(target)
        while time.monotonic() < deadline:
            source_port = 40000 + index % 20000
            tcp = struct.pack("!HHLLBBHHH", source_port, port, index, 0, 5 << 4, 2, 65535, 0, 0)
            pseudo = source + destination + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp)) + tcp
            tcp = tcp[:16] + struct.pack("!H", checksum(pseudo)) + tcp[18:]
            total = 20 + len(tcp)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, index & 0xffff, 0, 64, socket.IPPROTO_TCP, 0, source, destination)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            sock.sendto(ip + tcp, (target, port))
            index += 1
            next_emit += interval
            delay = next_emit - time.perf_counter()
            if delay > 0: time.sleep(delay)
        sock.close()
    metrics.attempted_events += index
    metrics.accepted_events += index


def percentile(values: List[float], ratio: float) -> Optional[float]:
    if not values: return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(len(ordered) * ratio))], 2)


def report(metrics: Metrics, duration: float, args: argparse.Namespace, pid: Optional[int]) -> dict:
    with metrics.lock:
        shm = list(metrics.shm_samples_us)
        attempted = metrics.attempted_events
        accepted = metrics.accepted_events
        observed = metrics.observed_events
        bans = metrics.observed_bans
    return {
        "benchmark": {"mode": args.mode, "duration_seconds": duration, "pid": pid, "target_eps": args.eps, "packet_eps": args.packet_eps},
        "throughput": {"attempted_events": attempted, "accepted_events": accepted, "accepted_eps": round(accepted / max(duration, 0.001), 2), "observed_events": observed, "inferred_unobserved_events": max(0, accepted - observed)},
        "latency_us": metrics.latency.summary(),
        "process": {"max_rss_kib": metrics.max_rss_kib, "max_cpu_percent": round(metrics.max_cpu_percent, 2)},
        "shm_cli_contention_us": {"samples": len(shm), "average": round(sum(shm) / len(shm), 2) if shm else None, "p95": percentile(shm, .95), "max": max(shm) if shm else None},
        "enforcement": {"observed_bans": bans, "loss_note": "Log loss is inferred from agent-log observations; kernel packet loss requires external NIC counters."},
    }


def write_reports(summary: dict, prefix: str) -> None:
    json_path = pathlib.Path(prefix + ".json")
    md_path = pathlib.Path(prefix + ".md")
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    throughput = summary["throughput"]
    latency = summary["latency_us"]
    process = summary["process"]
    contention = summary["shm_cli_contention_us"]
    markdown = f"""# CoPSeC Benchmark Report

- Mode: `{summary['benchmark']['mode']}`
- Duration: `{summary['benchmark']['duration_seconds']:.2f}s`
- PID: `{summary['benchmark']['pid'] or 'not found'}`

## Throughput

| Metric | Value |
|---|---:|
| Accepted events | {throughput['accepted_events']} |
| Accepted EPS | {throughput['accepted_eps']} |
| Observed engine events | {throughput['observed_events']} |
| Inferred unobserved events | {throughput['inferred_unobserved_events']} |
| Observed bans | {summary['enforcement']['observed_bans']} |

## Performance

| Metric | Value |
|---|---:|
| Average processing latency | {latency['average_us']} us |
| P50 latency | {latency['p50_us']} us |
| P95 latency | {latency['p95_us']} us |
| Maximum RSS | {process['max_rss_kib']} KiB |
| Maximum CPU utilization | {process['max_cpu_percent']}% |
| SHM CLI p95 latency | {contention['p95']} us |

> Latency is measured from the benchmark write timestamp to the timestamped JSON event observed in `agent.log`. Packet loss requires external interface/NIC counters.
"""
    md_path.write_text(markdown, encoding="utf-8")
    print(f"Wrote {json_path} and {md_path}")


def main() -> int:
    args = parse_args()
    if args.duration <= 0 or args.eps <= 0:
        raise SystemExit("duration and eps must be positive")
    if args.dry_run:
        print(json.dumps({"mode": args.mode, "duration": args.duration, "eps": args.eps, "packet_kind": args.packet_kind, "target": args.target}, indent=2))
        return 0
    if args.mode == "c" and args.packet_kind == "syn" and not args.allow_network_flood:
        raise SystemExit("Refusing raw SYN mode without --allow-network-flood")

    pid = find_pid(args.pid)
    metrics = Metrics(time.time())
    stop = threading.Event()
    observers = [threading.Thread(target=sample_process, args=(metrics, pid, stop), daemon=True), threading.Thread(target=observe_agent_log, args=(metrics, args.agent_log, stop), daemon=True)]
    for observer in observers: observer.start()
    contention = threading.Thread(target=shm_contention, args=(metrics, args.cli, args.shm_workers, stop), daemon=True)
    contention.start()
    workers = []
    try:
        if args.mode in {"a", "all"}:
            workers.append(threading.Thread(target=flood_log, args=(metrics, args.log_file or args.web_log, args.duration, args.eps, web_line)))
        if args.mode in {"b", "all"}:
            workers.append(threading.Thread(target=flood_log, args=(metrics, args.log_file or args.ssh_log, args.duration, args.eps, ssh_line)))
        if args.mode == "c":
            workers.append(threading.Thread(target=flood_packets, args=(metrics, args.target, args.port, args.duration, args.packet_eps, args.packet_kind, args.allow_network_flood)))
        for worker in workers: worker.start()
        for worker in workers: worker.join()
    finally:
        stop.set()
        contention.join(timeout=2)
        for observer in observers: observer.join(timeout=1)
    elapsed = max(0.001, time.time() - metrics.started_wall)
    summary = report(metrics, elapsed, args, pid)
    write_reports(summary, args.output_prefix)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except RuntimeError as error:
        raise SystemExit(str(error))
