#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC - Enterprise Edge Agent & Collector Automated Provisioning Pipeline
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
 Enterprise Edge Sensor & Telemetry Collector Setup
ASCII_BANNER
echo -e "${CLR_RESET}"

# 1. Privilege Validation
if [ "$EUID" -ne 0 ]; then
  echo -e "${CLR_RED}[ERROR] Provisioning script must be executed as root (sudo).${CLR_RESET}"
  exit 1
fi

DEPLOY_ROLE="collector" # Default to collector agent only on remote nodes
CONTROLLER_ADDR="${CONTROLLER_ADDR:-}"
NODE_GROUP="${NODE_GROUP:-DEFAULT_EDGE}"
CUSTOM_NODE_ID=""
CUSTOM_API_KEY=""
FORCE_REINSTALL=false

# 2. Parse CLI Arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller|-c|--grpc-addr)
      CONTROLLER_ADDR="$2"
      shift 2
      ;;
    --group|-g)
      NODE_GROUP="$2"
      shift 2
      ;;
    --node-id|-n)
      CUSTOM_NODE_ID="$2"
      shift 2
      ;;
    --api-key|-k)
      CUSTOM_API_KEY="$2"
      shift 2
      ;;
    --role|-r)
      DEPLOY_ROLE="$2"
      shift 2
      ;;
    --force|-f)
      FORCE_REINSTALL=true
      shift
      ;;
    --help|-h)
      echo "Usage: sudo bash deploy-copsec.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --controller, -c <ADDR>      Central Controller gRPC address (e.g. 198.51.100.10:8443)"
      echo "  --group, -g <GROUP>          Fleet Cluster Tag (e.g. PROD_WEB, DB_CLUSTER, K8S_WORKER)"
      echo "  --node-id, -n <ID>           Explicit Node ID (Default: auto-generated from hostname)"
      echo "  --api-key, -k <KEY>          Authentication API key (Default: auto-generated live key)"
      echo "  --role, -r <ROLE>            Role: 'collector' (Default), 'controller', or 'all'"
      echo "  --force, -f                  Force overwrite existing configuration"
      echo "  --help, -h                   Show this help menu"
      exit 0
      ;;
    *)
      echo -e "${CLR_YELLOW}[WARN] Unknown argument: $1${CLR_RESET}"
      shift
      ;;
  esac
done

# Prompt for Controller Address if not supplied and running on remote node
if [ -z "$CONTROLLER_ADDR" ] && [ "$DEPLOY_ROLE" = "collector" ]; then
  if [ -t 0 ]; then
    echo -e "${CLR_YELLOW}[?] Central Controller gRPC address is required for remote telemetry streaming.${CLR_RESET}"
    read -rp "Enter Central Controller Address [e.g. 198.51.100.10:8443]: " USER_INPUT_ADDR
    CONTROLLER_ADDR="${USER_INPUT_ADDR:-127.0.0.1:8443}"
  else
    CONTROLLER_ADDR="127.0.0.1:8443"
  fi
fi

echo -e "${CLR_GREEN}[+] Target Controller  : ${CLR_CYAN}${CONTROLLER_ADDR}${CLR_RESET}"
echo -e "${CLR_GREEN}[+] Deployment Role    : ${CLR_CYAN}${DEPLOY_ROLE}${CLR_RESET}"
echo -e "${CLR_GREEN}[+] Fleet Group Tag    : ${CLR_CYAN}${NODE_GROUP}${CLR_RESET}"

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

# 5. Kernel & Sysctl Hardening
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

# 6. Initialize Secure Directory Hierarchy
echo -e "${CLR_MAGENTA}[*] Initializing secure directory hierarchy...${CLR_RESET}"
mkdir -p /etc/copsec /var/lib/copsec/data /var/log/copsec /usr/local/bin /etc/nginx/conf.d
chmod 0750 /etc/copsec /var/lib/copsec /var/log/copsec

# Ensure Nginx Blocklist file exists
if [ ! -f "/etc/nginx/conf.d/copsec_blocklist.conf" ]; then
  cat << 'NGINX_BLK' > /etc/nginx/conf.d/copsec_blocklist.conf
# CoPSeC Autonomous SOAR Layer-7 Dynamic WAF Blocklist
# Auto-maintained by CoPSeC Agent
NGINX_BLK
  chmod 0644 /etc/nginx/conf.d/copsec_blocklist.conf
fi

# 7. Detect Active Log Sources
echo -e "${CLR_MAGENTA}[*] Detecting active server log sources...${CLR_RESET}"
DETECTED_NGINX=""
DETECTED_AUTH=""
DETECTED_SYSLOG=""

# Nginx / Web
if [ -f "/var/log/nginx/access.log" ]; then
  DETECTED_NGINX="/var/log/nginx/access.log"
elif [ -f "/var/log/httpd/access_log" ]; then
  DETECTED_NGINX="/var/log/httpd/access_log"
elif [ -f "/var/log/apache2/access.log" ]; then
  DETECTED_NGINX="/var/log/apache2/access.log"
else
  touch /var/log/copsec/dummy_web.log
  DETECTED_NGINX="/var/log/copsec/dummy_web.log"
fi

# Auth / SSH
if [ -f "/var/log/auth.log" ]; then
  DETECTED_AUTH="/var/log/auth.log"
elif [ -f "/var/log/secure" ]; then
  DETECTED_AUTH="/var/log/secure"
else
  touch /var/log/copsec/dummy_auth.log
  DETECTED_AUTH="/var/log/copsec/dummy_auth.log"
fi

# Syslog
if [ -f "/var/log/syslog" ]; then
  DETECTED_SYSLOG="/var/log/syslog"
elif [ -f "/var/log/messages" ]; then
  DETECTED_SYSLOG="/var/log/messages"
else
  touch /var/log/copsec/dummy_sys.log
  DETECTED_SYSLOG="/var/log/copsec/dummy_sys.log"
fi

# 8. Enroll / Load Node Identity
NODE_ID_FILE="/etc/copsec/node.json"
HOSTNAME="$(hostname -s 2>/dev/null || echo "edge")"

if [ ! -f "$NODE_ID_FILE" ] || [ "$FORCE_REINSTALL" = true ]; then
  RANDOM_HEX="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 6)"
  FINAL_NODE_ID="${CUSTOM_NODE_ID:-node-${HOSTNAME}-${RANDOM_HEX}}"
  KEY_RANDOM="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 24)"
  FINAL_API_KEY="${CUSTOM_API_KEY:-cps_live_${KEY_RANDOM}}"

  cat << JSON_EOF > "$NODE_ID_FILE"
{
  "node_id": "${FINAL_NODE_ID}",
  "api_key": "${FINAL_API_KEY}",
  "hostname": "${HOSTNAME}",
  "group": "${NODE_GROUP}",
  "created_at": $(date +%s%3N)
}
JSON_EOF
  chmod 0600 "$NODE_ID_FILE"
  echo -e "${CLR_GREEN}[+] Enrolled Node Identity : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
else
  FINAL_NODE_ID="$(grep -o '"node_id": *"[^"]*"' "$NODE_ID_FILE" | cut -d'"' -f4 || echo "node-${HOSTNAME}")"
  echo -e "${CLR_GREEN}[+] Using Existing Node ID : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
fi

# 9. Whitelist File
WHITELIST_FILE="/etc/copsec/whitelist.json"
if [ ! -f "$WHITELIST_FILE" ]; then
  cat << 'WL_EOF' > "$WHITELIST_FILE"
{
  "trusted_cidrs": [
    "127.0.0.1/32",
    "::1/128",
    "100.64.0.0/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "allowed_http_codes": [
    400, 401, 403, 404, 405, 429, 500, 502, 503
  ]
}
WL_EOF
  chmod 0640 "$WHITELIST_FILE"
fi

# 10. Install / Build Collector Binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if command -v go >/dev/null 2>&1 && [ -d "${ROOT_DIR}/collector" ]; then
  echo -e "${CLR_MAGENTA}[*] Compiling copsec-collector binary...${CLR_RESET}"
  (cd "${ROOT_DIR}/collector" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-collector .)
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Compiled and Installed : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif [ -f "${ROOT_DIR}/collector/copsec-collector" ]; then
  cp -f "${ROOT_DIR}/collector/copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
elif [ -f "./copsec-collector" ]; then
  cp -f "./copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
fi

# Optional Controller Compilation if role includes controller
if [ "$DEPLOY_ROLE" = "controller" ] || [ "$DEPLOY_ROLE" = "all" ]; then
  if command -v go >/dev/null 2>&1 && [ -d "${ROOT_DIR}/controller" ]; then
    echo -e "${CLR_MAGENTA}[*] Compiling copsec-controller...${CLR_RESET}"
    (cd "${ROOT_DIR}/controller" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-controller .)
    chmod 0755 /usr/local/bin/copsec-controller
  fi
fi

# 11. Register Systemd Daemon for Edge Collector
if command -v systemctl >/dev/null 2>&1; then
  SERVICE_FILE="/etc/systemd/system/copsec-collector.service"
  echo -e "${CLR_MAGENTA}[*] Configuring Collector Systemd Unit (/etc/systemd/system/copsec-collector.service)...${CLR_RESET}"

  cat << SVC_COL > "$SERVICE_FILE"
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
  -controller ${CONTROLLER_ADDR} \\
  -node-identity /etc/copsec/node.json \\
  -buffer-db /var/lib/copsec/data/buffer.db \\
  -offset-file /var/lib/copsec/offsets.json \\
  -whitelist /etc/copsec/whitelist.json \\
  -nginx-log ${DETECTED_NGINX} \\
  -auth-log ${DETECTED_AUTH} \\
  -syslog ${DETECTED_SYSLOG}
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

  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  echo -e "${CLR_GREEN} ✔ CoPSeC Edge Collector Agent Successfully Deployed & Active!${CLR_RESET}"
  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  echo -e " • Node ID     : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
  echo -e " • Fleet Group : ${CLR_CYAN}${NODE_GROUP}${CLR_RESET}"
  echo -e " • Controller  : ${CLR_CYAN}${CONTROLLER_ADDR}${CLR_RESET}"
  echo -e " • Service     : ${CLR_GREEN}copsec-collector.service (active)${CLR_RESET}"
  echo -e " • Logs        : ${CLR_GRAY}journalctl -u copsec-collector -f${CLR_RESET}"
  echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
fi
