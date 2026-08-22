#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC - Enterprise Edge Agent Automated Provisioning & Dynamic Onboarding
# ==============================================================================
#  Supported OS: Ubuntu, Debian, CentOS, AlmaLinux, Rocky Linux, RHEL, Fedora
#  Supported Arch: x86_64, aarch64 / arm64
# ==============================================================================

set -euo pipefail

# ANSI Cyberpunk Colors
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
 CoPSeC Distributed Micro-SIEM / Edge Collector Setup
ASCII_BANNER
echo -e "${CLR_RESET}"

# 1. Root Privileges Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${CLR_RED}[ERROR] This provisioning script must be run as root (sudo).${CLR_RESET}"
  exit 1
fi

# Default Variables
CONTROLLER_ADDR="127.0.0.1:8443"
NODE_GROUP="DEFAULT_EDGE"
CUSTOM_NODE_ID=""
CUSTOM_API_KEY=""
FALLBACK_TG_TOKEN=""
FALLBACK_TG_CHAT=""
FORCE_REINSTALL=false

# 2. Parse CLI Arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller|-c)
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
    --fallback-token)
      FALLBACK_TG_TOKEN="$2"
      shift 2
      ;;
    --fallback-chat)
      FALLBACK_TG_CHAT="$2"
      shift 2
      ;;
    --force|-f)
      FORCE_REINSTALL=true
      shift
      ;;
    --help|-h)
      echo "Usage: sudo bash install-agent.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --controller, -c <ADDR>      Central Controller gRPC address (e.g. 100.72.101.79:8443)"
      echo "  --group, -g <GROUP>          Cluster/Fleet Group (e.g. PROD_WEB, DB_CLUSTER, K8S_WORKER)"
      echo "  --node-id, -n <ID>           Explicit Node ID (Default: auto-generated from hostname)"
      echo "  --api-key, -k <KEY>          Authentication API key (Default: auto-generated live key)"
      echo "  --fallback-token <TOKEN>     Optional Telegram Bot Token for offline emergency fallback"
      echo "  --fallback-chat <CHAT_ID>    Optional Telegram Chat ID for offline emergency fallback"
      echo "  --force, -f                  Force overwrite existing configuration & service"
      echo "  --help, -h                   Show this help menu"
      exit 0
      ;;
    *)
      echo -e "${CLR_YELLOW}[WARN] Unknown option: $1 (ignoring)${CLR_RESET}"
      shift
      ;;
  esac
done

echo -e "${CLR_GREEN}[+] Target Controller : ${CLR_CYAN}${CONTROLLER_ADDR}${CLR_RESET}"
echo -e "${CLR_GREEN}[+] Fleet Group Tag   : ${CLR_CYAN}${NODE_GROUP}${CLR_RESET}"

# 3. Detect Architecture and OS
ARCH="$(uname -m)"
OS="$(uname -s)"

if [ "$OS" != "Linux" ]; then
  echo -e "${CLR_RED}[ERROR] CoPSeC Agent requires Linux kernel. Found: ${OS}${CLR_RESET}"
  exit 1
fi

echo -e "${CLR_GREEN}[+] Architecture      : ${CLR_CYAN}${ARCH}${CLR_RESET} (${OS})"

# 4. Prepare Directories with strict permissions (0750)
mkdir -p /etc/copsec /var/lib/copsec /var/log/copsec /usr/local/bin
chmod 0750 /etc/copsec /var/lib/copsec /var/log/copsec

# 5. Detect Active Log Sources Automatically
echo -e "${CLR_MAGENTA}[*] Scanning system for active server log tailers...${CLR_RESET}"

DETECTED_NGINX=""
DETECTED_AUTH=""
DETECTED_SYSLOG=""

# Nginx / Web Server
if [ -f "/var/log/nginx/access.log" ]; then
  DETECTED_NGINX="/var/log/nginx/access.log"
  echo -e "  ${CLR_GREEN}✔ Nginx Access Log:${CLR_RESET} ${DETECTED_NGINX}"
elif [ -f "/var/log/httpd/access_log" ]; then
  DETECTED_NGINX="/var/log/httpd/access_log"
  echo -e "  ${CLR_GREEN}✔ Apache Access Log:${CLR_RESET} ${DETECTED_NGINX}"
elif [ -f "/var/log/apache2/access.log" ]; then
  DETECTED_NGINX="/var/log/apache2/access.log"
  echo -e "  ${CLR_GREEN}✔ Apache2 Access Log:${CLR_RESET} ${DETECTED_NGINX}"
else
  touch /var/log/copsec/dummy_web.log
  DETECTED_NGINX="/var/log/copsec/dummy_web.log"
  echo -e "  ${CLR_YELLOW}⚠ Web Access Log not found (created fallback buffer)${CLR_RESET}"
fi

# SSH / Auth Logs
if [ -f "/var/log/auth.log" ]; then
  DETECTED_AUTH="/var/log/auth.log"
  echo -e "  ${CLR_GREEN}✔ SSH/Auth Log (Debian/Ubuntu):${CLR_RESET} ${DETECTED_AUTH}"
elif [ -f "/var/log/secure" ]; then
  DETECTED_AUTH="/var/log/secure"
  echo -e "  ${CLR_GREEN}✔ SSH/Secure Log (RHEL/CentOS):${CLR_RESET} ${DETECTED_AUTH}"
else
  touch /var/log/copsec/dummy_auth.log
  DETECTED_AUTH="/var/log/copsec/dummy_auth.log"
  echo -e "  ${CLR_YELLOW}⚠ Auth Log not found (created fallback buffer)${CLR_RESET}"
fi

# Syslog
if [ -f "/var/log/syslog" ]; then
  DETECTED_SYSLOG="/var/log/syslog"
  echo -e "  ${CLR_GREEN}✔ Syslog (Debian/Ubuntu):${CLR_RESET} ${DETECTED_SYSLOG}"
elif [ -f "/var/log/messages" ]; then
  DETECTED_SYSLOG="/var/log/messages"
  echo -e "  ${CLR_GREEN}✔ Messages Log (RHEL/CentOS):${CLR_RESET} ${DETECTED_SYSLOG}"
else
  touch /var/log/copsec/dummy_sys.log
  DETECTED_SYSLOG="/var/log/copsec/dummy_sys.log"
  echo -e "  ${CLR_YELLOW}⚠ Syslog not found (created fallback buffer)${CLR_RESET}"
fi

# 6. Generate or Load Node Identity
NODE_ID_FILE="/etc/copsec/node.json"
if [ ! -f "$NODE_ID_FILE" ] || [ "$FORCE_REINSTALL" = true ]; then
  HOSTNAME="$(hostname -s 2>/dev/null || echo "edge")"
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
  echo -e "${CLR_GREEN}[+] Enrolled Node Identity : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET} (Mode 0600)"
else
  FINAL_NODE_ID="$(grep -o '"node_id": *"[^"]*"' "$NODE_ID_FILE" | cut -d'"' -f4 || echo "node-vps-active")"
  echo -e "${CLR_GREEN}[+] Using Existing Node ID : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
fi

# 7. Generate Dynamic Whitelist File if missing
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

# 8. Deploy Binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "${PARENT_DIR}/collector/copsec-collector" ]; then
  cp -f "${PARENT_DIR}/collector/copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Installed Collector Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif [ -f "./copsec-collector" ]; then
  cp -f "./copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Installed Collector Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif command -v go >/dev/null 2>&1 && [ -d "${PARENT_DIR}/collector" ]; then
  echo -e "${CLR_MAGENTA}[*] Compiling copsec-collector from source...${CLR_RESET}"
  (cd "${PARENT_DIR}/collector" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-collector .)
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Built and Installed Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
else
  if [ ! -f "/usr/local/bin/copsec-collector" ]; then
    echo -e "${CLR_RED}[ERROR] copsec-collector binary not found. Please compile or download it first.${CLR_RESET}"
    exit 1
  fi
fi

# 9. Configure Systemd Service
SERVICE_FILE="/etc/systemd/system/copsec-collector.service"
echo -e "${CLR_MAGENTA}[*] Configuring Systemd Unit : ${CLR_CYAN}${SERVICE_FILE}${CLR_RESET}"

cat << SVC_EOF > "$SERVICE_FILE"
[Unit]
Description=CoPSeC Edge Telemetry Collector & Fallback SOAR Sensor
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
  -buffer-db /var/lib/copsec/buffer.db \\
  -offset-file /var/lib/copsec/offsets.json \\
  -whitelist /etc/copsec/whitelist.json \\
  -nginx-log ${DETECTED_NGINX} \\
  -auth-log ${DETECTED_AUTH} \\
  -syslog ${DETECTED_SYSLOG} \\
  -fallback-telegram-token "${FALLBACK_TG_TOKEN}" \\
  -fallback-telegram-chat "${FALLBACK_TG_CHAT}"
Restart=always
RestartSec=3s
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC_EOF

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable copsec-collector.service >/dev/null 2>&1 || true
  systemctl restart copsec-collector.service || true

  sleep 1.5
  if systemctl is-active --quiet copsec-collector.service; then
    echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
    echo -e "${CLR_GREEN} ✔ CoPSeC Edge Collector successfully provisioned and running!${CLR_RESET}"
    echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
    echo -e " • Node ID     : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
    echo -e " • Fleet Group : ${CLR_CYAN}${NODE_GROUP}${CLR_RESET}"
    echo -e " • Controller  : ${CLR_CYAN}${CONTROLLER_ADDR}${CLR_RESET}"
    echo -e " • Service     : ${CLR_GREEN}active (running)${CLR_RESET}"
    echo -e " • Logs        : ${CLR_GRAY}journalctl -u copsec-collector -f${CLR_RESET}"
    echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  else
    echo -e "${CLR_YELLOW}[WARN] Service created. Start manually with: sudo systemctl start copsec-collector${CLR_RESET}"
  fi
else
  echo -e "${CLR_YELLOW}[WARN] systemd not found. Start collector with: /usr/local/bin/copsec-collector -controller ${CONTROLLER_ADDR}${CLR_RESET}"
fi
