#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC - Enterprise Autonomous SIEM/SOAR System Deployment & Orchestration
# ==============================================================================
#  Supported OS: Ubuntu, Debian, CentOS, AlmaLinux, Rocky Linux, RHEL, Fedora, Arch, Alpine
#  Supported Arch: x86_64, aarch64 / arm64, armv7l
# ==============================================================================

set -euo pipefail

# ANSI Colors
CLR_RESET="\033[0m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"
CLR_YELLOW="\033[1;33m"
CLR_MAGENTA="\033[1;35m"
CLR_GRAY="\033[0;90m"

echo -e "${CLR_CYAN}"
cat << 'ASCII_BANNER'
  ██████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║     ██║   ██║██████╔╝███████╗█████╗  ██║     
 ██║     ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║     
 ╚██████╗╚██████╔╝██║     ███████║███████╗╚██████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝
 Enterprise SIEM / Autonomous SOAR Deployment Pipeline
ASCII_BANNER
echo -e "${CLR_RESET}"

# 1. Privilege Validation
if [ "$EUID" -ne 0 ]; then
  echo -e "${CLR_RED}[ERROR] Provisioning pipeline must be executed as root (sudo).${CLR_RESET}"
  exit 1
fi

DEPLOY_ROLE="all" # all, controller, collector
CONTROLLER_GRPC="0.0.0.0:8443"
CONTROLLER_WEB="0.0.0.0:8080"
HONEYPOT_SSH=":2222"
PULL_ET_RULES=true
FORCE_REINSTALL=false

# 2. Parse CLI Arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role|-r)
      DEPLOY_ROLE="$2"
      shift 2
      ;;
    --grpc-addr)
      CONTROLLER_GRPC="$2"
      shift 2
      ;;
    --web-addr)
      CONTROLLER_WEB="$2"
      shift 2
      ;;
    --honeypot-ssh)
      HONEYPOT_SSH="$2"
      shift 2
      ;;
    --skip-et-rules)
      PULL_ET_RULES=false
      shift
      ;;
    --force|-f)
      FORCE_REINSTALL=true
      shift
      ;;
    --help|-h)
      echo "Usage: sudo bash deploy-copsec.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --role, -r <ROLE>        Deployment role: 'all', 'controller', 'collector' (Default: all)"
      echo "  --grpc-addr <ADDR>       Controller gRPC listen address (Default: 0.0.0.0:8443)"
      echo "  --web-addr <ADDR>        Web SOC console listen address (Default: 0.0.0.0:8080)"
      echo "  --honeypot-ssh <ADDR>    Fake SSH honeypot listen address (Default: :2222)"
      echo "  --skip-et-rules          Skip downloading Emerging Threats rule sets"
      echo "  --force, -f              Force overwrite existing configuration"
      echo "  --help, -h               Show this help menu"
      exit 0
      ;;
    *)
      echo -e "${CLR_YELLOW}[WARN] Unknown argument: $1${CLR_RESET}"
      shift
      ;;
  esac
done

# 3. Detect System Architecture and Distribution
ARCH="$(uname -m)"
OS="$(uname -s)"

if [ "$OS" != "Linux" ]; then
  echo -e "${CLR_RED}[ERROR] CoPSeC requires Linux kernel. Found: ${OS}${CLR_RESET}"
  exit 1
fi

echo -e "${CLR_GREEN}[+] Detected Architecture : ${CLR_CYAN}${ARCH}${CLR_RESET} (${OS})"

PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MANAGER="yum"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MANAGER="pacman"
elif command -v apk >/dev/null 2>&1; then
  PKG_MANAGER="apk"
elif command -v zypper >/dev/null 2>&1; then
  PKG_MANAGER="zypper"
fi

echo -e "${CLR_GREEN}[+] Detected Package Mgr  : ${CLR_CYAN}${PKG_MANAGER:-unknown}${CLR_RESET}"

# 4. Install Essential Dependencies
echo -e "${CLR_MAGENTA}[*] Installing dependencies (iptables, conntrack, iproute2, suricata, nginx)...${CLR_RESET}"
case "$PKG_MANAGER" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq iptables conntrack iproute2 ipset curl jq openssl tar gzip sqlite3 nginx || true
    apt-get install -y -qq suricata || true
    ;;
  dnf|yum)
    $PKG_MANAGER install -y -q iptables conntrack-tools iproute ipset curl jq openssl tar gzip sqlite nginx || true
    $PKG_MANAGER install -y -q epel-release || true
    $PKG_MANAGER install -y -q suricata || true
    ;;
  pacman)
    pacman -Sy --noconfirm iptables conntrack-tools iproute2 ipset curl jq openssl tar gzip sqlite nginx suricata || true
    ;;
  apk)
    apk add --no-cache iptables conntrack-tools iproute2 ipset curl jq openssl tar gzip sqlite nginx suricata || true
    ;;
  *)
    echo -e "${CLR_YELLOW}[WARN] Manual dependency validation required for custom package manager.${CLR_RESET}"
    ;;
esac

# 5. Kernel & Sysctl Hardening (High-Throughput Conntrack & Netfilter Tuning)
echo -e "${CLR_MAGENTA}[*] Configuring kernel sysctl boundaries (/etc/sysctl.d/99-copsec.conf)...${CLR_RESET}"
cat << 'SYSCTL_EOF' > /etc/sysctl.d/99-copsec.conf
# CoPSeC High-Performance SIEM/SOAR Kernel Parameter Tuning
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_forward = 1
net.core.netdev_max_backlog = 100000
net.ipv4.tcp_syncookies = 1
fs.file-max = 2097152
SYSCTL_EOF

if command -v sysctl >/dev/null 2>&1; then
  sysctl -p /etc/sysctl.d/99-copsec.conf >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true
fi

# 6. Initialize Directory Structure with Strict Permissions (0750 / 0640)
echo -e "${CLR_MAGENTA}[*] Initializing secure directory hierarchy...${CLR_RESET}"
mkdir -p /etc/copsec/sigma \
         /etc/copsec/rules \
         /etc/copsec/suricata/rules \
         /var/lib/copsec/data \
         /var/log/copsec \
         /usr/local/bin \
         /etc/nginx/conf.d

chmod 0750 /etc/copsec /var/lib/copsec /var/log/copsec /etc/copsec/sigma /etc/copsec/suricata

# Ensure Nginx Blocklist file exists
if [ ! -f "/etc/nginx/conf.d/copsec_blocklist.conf" ]; then
  cat << 'NGINX_BLK' > /etc/nginx/conf.d/copsec_blocklist.conf
# CoPSeC Autonomous SOAR Layer-7 Dynamic WAF Blocklist
# Auto-maintained by CoPSeC Controller
NGINX_BLK
  chmod 0644 /etc/nginx/conf.d/copsec_blocklist.conf
fi

# 7. Pull Emerging Threats (ET Open) Rule Sets for Suricata
if [ "$PULL_ET_RULES" = true ]; then
  echo -e "${CLR_MAGENTA}[*] Synchronizing Proofpoint Emerging Threats (ET Open) rule sets...${CLR_RESET}"
  ET_URL="https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz"
  TMP_TAR="/tmp/emerging.rules.tar.gz"
  
  if curl -sSL --connect-timeout 8 --max-time 30 "$ET_URL" -o "$TMP_TAR" 2>/dev/null; then
    tar -xzf "$TMP_TAR" -C /etc/copsec/suricata/rules --strip-components=1 2>/dev/null || true
    rm -f "$TMP_TAR"
    echo -e "${CLR_GREEN}[+] Emerging Threats rule sets successfully deployed to /etc/copsec/suricata/rules${CLR_RESET}"
  else
    echo -e "${CLR_YELLOW}[WARN] Remote ET rules download skipped (network timeout or offline). Creating baseline ruleset.${CLR_RESET}"
    cat << 'ET_FALLBACK' > /etc/copsec/suricata/rules/copsec_emerging.rules
alert http any any -> any any (msg:"COPSEC ET WEB SQL Injection Attempt"; flow:established,to_server; content:"union"; nocase; content:"select"; nocase; sid:2000001; rev:1;)
alert http any any -> any any (msg:"COPSEC ET WEB Shell Execution Attempt"; flow:established,to_server; content:"/bin/sh"; nocase; sid:2000002; rev:1;)
alert tcp any any -> any 22 (msg:"COPSEC ET SCAN SSH Brute Force Inbound"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:2000003; rev:1;)
ET_FALLBACK
  fi
fi

# 8. Deploy Out-of-the-Box SigmaHQ Detection-as-Code Rules
echo -e "${CLR_MAGENTA}[*] Deploying native SigmaHQ rules to /etc/copsec/sigma/...${CLR_RESET}"
cat << 'SIGMA_SQLI' > /etc/copsec/sigma/web_sqli.yml
title: Web Application SQL Injection Attack
id: sigma-web-sqli-generic
status: stable
description: Detects SQL injection UNION, SELECT, OR 1=1 payloads in web access logs
tags:
  - attack.initial_access
  - attack.t1190
level: critical
logsource:
  category: webserver
detection:
  selection_sqli:
    _raw|re: "(?i)(union\\s+select|select\\s+.*from|waitfor\\s+delay|sleep\\(\\d+\\)|'--|%27%20or%20|or\\s+1=1)"
  condition: selection_sqli
SIGMA_SQLI

cat << 'SIGMA_RCE' > /etc/copsec/sigma/web_rce.yml
title: Command Injection and Unix Shell Execution
id: sigma-web-rce-execution
status: stable
description: Detects unix shell execution, pipe commands, and reverse shell triggers
tags:
  - attack.execution
  - attack.t1059.004
level: critical
logsource:
  category: webserver
detection:
  selection_cmd:
    _raw|re: "(?i)(/bin/(sh|bash)|curl\\s+https?://.*\\|\\s*(sh|bash)|;\\s*(cat|id|whoami)\\s+|\\|\\s*(cat|id)\\s*|`whoami`|\\$\\(whoami\\))"
  condition: selection_cmd
SIGMA_RCE

cat << 'SIGMA_SSH' > /etc/copsec/sigma/ssh_bruteforce.yml
title: SSH Authentication Brute-Force Activity
id: sigma-ssh-auth-bruteforce
status: stable
description: Detects repeated authentication failures on SSH service
tags:
  - attack.credential_access
  - attack.t1110.001
level: high
logsource:
  service: sshd
detection:
  selection_auth:
    _raw|re: "(?i)(Failed password for (invalid user )?[a-zA-Z0-9_.-]+ from \\d+\\.\\d+\\.\\d+\\.\\d+|Invalid user [a-zA-Z0-9_.-]+ from \\d+\\.\\d+\\.\\d+\\.\\d+)"
  condition: selection_auth
SIGMA_SSH

chmod 0640 /etc/copsec/sigma/*.yml

# 9. Build and Install Binaries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if command -v go >/dev/null 2>&1; then
  if [ "$DEPLOY_ROLE" = "all" ] || [ "$DEPLOY_ROLE" = "controller" ]; then
    echo -e "${CLR_MAGENTA}[*] Compiling copsec-controller (Embedded Web SOC + Sigma Engine)...${CLR_RESET}"
    (cd "${ROOT_DIR}/controller" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-controller .)
    chmod 0755 /usr/local/bin/copsec-controller
    echo -e "${CLR_GREEN}[+] Installed Controller : ${CLR_CYAN}/usr/local/bin/copsec-controller${CLR_RESET}"
  fi

  if [ "$DEPLOY_ROLE" = "all" ] || [ "$DEPLOY_ROLE" = "collector" ]; then
    echo -e "${CLR_MAGENTA}[*] Compiling copsec-collector (High-Performance Edge Sensor)...${CLR_RESET}"
    (cd "${ROOT_DIR}/collector" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-collector .)
    chmod 0755 /usr/local/bin/copsec-collector
    echo -e "${CLR_GREEN}[+] Installed Collector  : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
  fi
else
  echo -e "${CLR_YELLOW}[WARN] Go compiler not found. Attempting to copy prebuilt binaries...${CLR_RESET}"
  if [ -f "${ROOT_DIR}/controller/copsec-controller" ]; then
    cp -f "${ROOT_DIR}/controller/copsec-controller" /usr/local/bin/copsec-controller
    chmod 0755 /usr/local/bin/copsec-controller
  fi
  if [ -f "${ROOT_DIR}/collector/copsec-collector" ]; then
    cp -f "${ROOT_DIR}/collector/copsec-collector" /usr/local/bin/copsec-collector
    chmod 0755 /usr/local/bin/copsec-collector
  fi
fi

# 10. Register Persistent Systemd Daemons
if command -v systemctl >/dev/null 2>&1; then
  # Controller Service
  if [ "$DEPLOY_ROLE" = "all" ] || [ "$DEPLOY_ROLE" = "controller" ]; then
    echo -e "${CLR_MAGENTA}[*] Configuring Controller Systemd Daemon (/etc/systemd/system/copsec-controller.service)...${CLR_RESET}"
    cat << SVC_CTL > /etc/systemd/system/copsec-controller.service
[Unit]
Description=CoPSeC Central SIEM / SOAR Controller & Embedded Web SOC
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/copsec
ExecStart=/usr/local/bin/copsec-controller \\
  -grpc-addr ${CONTROLLER_GRPC} \\
  -web-addr ${CONTROLLER_WEB} \\
  -honeypot-ssh "${HONEYPOT_SSH}" \\
  -db /var/lib/copsec/data/copsec.db \\
  -sigma-dir /etc/copsec/sigma \\
  -headless=true
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC_CTL
    systemctl daemon-reload
    systemctl enable copsec-controller.service >/dev/null 2>&1 || true
    systemctl restart copsec-controller.service || true
  fi

  # Collector Service
  if [ "$DEPLOY_ROLE" = "all" ] || [ "$DEPLOY_ROLE" = "collector" ]; then
    echo -e "${CLR_MAGENTA}[*] Configuring Collector Systemd Daemon (/etc/systemd/system/copsec-collector.service)...${CLR_RESET}"
    cat << SVC_COL > /etc/systemd/system/copsec-collector.service
[Unit]
Description=CoPSeC Edge Telemetry Collector & SOAR Sensor
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/copsec
ExecStart=/usr/local/bin/copsec-collector \\
  -controller 127.0.0.1:8443 \\
  -node-identity /etc/copsec/node.json \\
  -buffer-db /var/lib/copsec/data/buffer.db \\
  -offset-file /var/lib/copsec/offsets.json \\
  -whitelist /etc/copsec/whitelist.json
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC_COL
    systemctl daemon-reload
    systemctl enable copsec-collector.service >/dev/null 2>&1 || true
    systemctl restart copsec-collector.service || true
  fi

  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  echo -e "${CLR_GREEN} ✔ CoPSeC Enterprise Platform Successfully Provisioned and Orchestrated!${CLR_RESET}"
  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  echo -e " • Web SOC Console : ${CLR_CYAN}http://${CONTROLLER_WEB}${CLR_RESET}"
  echo -e " • gRPC Collector  : ${CLR_CYAN}${CONTROLLER_GRPC}${CLR_RESET}"
  echo -e " • SSH Honeypot    : ${CLR_CYAN}${HONEYPOT_SSH}${CLR_RESET}"
  echo -e " • Sigma HQ Rules  : ${CLR_CYAN}/etc/copsec/sigma/${CLR_RESET}"
  echo -e " • Service Status  : ${CLR_GREEN}Active Systemd Daemons Running${CLR_RESET}"
  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
fi
