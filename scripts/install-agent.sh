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
INSTALL_SURICATA=true
INSTALL_SNORT=true
BINARY_URL=""

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
    --binary-url|-u)
      BINARY_URL="$2"
      shift 2
      ;;
    --no-suricata)
      INSTALL_SURICATA=false
      shift
      ;;
    --no-snort)
      INSTALL_SNORT=false
      shift
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
      echo "  --controller, -c <ADDR>      Central Controller gRPC address (e.g. 192.168.1.10:8443)"
      echo "  --group, -g <GROUP>          Cluster/Fleet Group (e.g. PROD_WEB, DB_CLUSTER, PARDUS_EDGE)"
      echo "  --node-id, -n <ID>           Explicit Node ID (Default: auto-generated from hostname)"
      echo "  --api-key, -k <KEY>          Authentication API key (Default: auto-generated live key)"
      echo "  --binary-url, -u <URL>       Direct HTTP/HTTPS URL to download copsec-collector binary"
      echo "  --no-suricata                Skip Suricata NIDS auto-installation"
      echo "  --no-snort                   Skip Snort-ML / Snort auto-installation"
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

# Detect Package Manager
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

# 4. Auto-Install Dependencies (Suricata, Snort / Snort-ML, Network Tools)
echo -e "${CLR_MAGENTA}[*] Verifying security modules and prerequisites...${CLR_RESET}"

case "$PKG_MANAGER" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    PKGS_TO_INSTALL=()
    command -v curl >/dev/null 2>&1 || PKGS_TO_INSTALL+=(curl)
    command -v iptables >/dev/null 2>&1 || PKGS_TO_INSTALL+=(iptables)
    command -v conntrack >/dev/null 2>&1 || PKGS_TO_INSTALL+=(conntrack)
    command -v jq >/dev/null 2>&1 || PKGS_TO_INSTALL+=(jq)
    command -v sqlite3 >/dev/null 2>&1 || PKGS_TO_INSTALL+=(sqlite3)
    command -v rsyslogd >/dev/null 2>&1 || PKGS_TO_INSTALL+=(rsyslog)

    if [ ${#PKGS_TO_INSTALL[@]} -gt 0 ]; then
      echo -e "${CLR_CYAN}[+] Installing system tools: ${PKGS_TO_INSTALL[*]}${CLR_RESET}"
      apt-get update -qq && apt-get install -y -qq "${PKGS_TO_INSTALL[@]}" || true
      command -v rsyslogd >/dev/null 2>&1 && systemctl enable --now rsyslog >/dev/null 2>&1 || true
    fi

    # 4a. Suricata NIDS Auto-Install
    if [ "$INSTALL_SURICATA" = true ]; then
      if ! command -v suricata >/dev/null 2>&1; then
        echo -e "${CLR_CYAN}[+] Auto-installing Suricata NIDS engine...${CLR_RESET}"
        apt-get install -y -qq suricata suricata-update || echo -e "${CLR_YELLOW}⚠ Suricata install skipped or unavailable.${CLR_RESET}"
      else
        echo -e "  ${CLR_GREEN}✔ Suricata already installed:${CLR_RESET} $(which suricata)"
      fi
      if command -v suricata >/dev/null 2>&1; then
        # Detect primary interface
        PRIMARY_IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')"
        if [ -n "$PRIMARY_IFACE" ] && [ "$PRIMARY_IFACE" != "eth0" ]; then
          [ -f "/etc/suricata/suricata.yaml" ] && sed -i "s/- interface: eth0/- interface: ${PRIMARY_IFACE}/g" /etc/suricata/suricata.yaml
          [ -f "/etc/default/suricata" ] && sed -i "s/IFACE=eth0/IFACE=${PRIMARY_IFACE}/g" /etc/default/suricata
        fi
        mkdir -p /var/lib/suricata/rules
        if [ ! -f "/var/lib/suricata/rules/suricata.rules" ]; then
          echo -e "${CLR_CYAN}[+] Initializing Suricata threat rules (suricata-update)...${CLR_RESET}"
          suricata-update || touch /var/lib/suricata/rules/suricata.rules
        fi
        systemctl enable --now suricata >/dev/null 2>&1 || true
      fi
    fi

    # 4b. Snort / Snort-ML Auto-Install
    if [ "$INSTALL_SNORT" = true ]; then
      if ! command -v snort >/dev/null 2>&1; then
        echo -e "${CLR_CYAN}[+] Auto-installing Snort IDS/IPS engine...${CLR_RESET}"
        apt-get install -y -qq snort snort-rules-default || apt-get install -y -qq snort3 || echo -e "${CLR_YELLOW}⚠ Snort package not in default apt repos (standby log tailing active).${CLR_RESET}"
      else
        echo -e "  ${CLR_GREEN}✔ Snort already installed:${CLR_RESET} $(which snort)"
      fi
    fi
    ;;

  dnf|yum)
    $PKG_MANAGER install -y -q iptables conntrack-tools curl jq sqlite || true
    if [ "$INSTALL_SURICATA" = true ] && ! command -v suricata >/dev/null 2>&1; then
      echo -e "${CLR_CYAN}[+] Auto-installing Suricata on RPM...${CLR_RESET}"
      $PKG_MANAGER install -y -q epel-release || true
      $PKG_MANAGER install -y -q suricata || true
      systemctl enable --now suricata >/dev/null 2>&1 || true
    fi
    if [ "$INSTALL_SNORT" = true ] && ! command -v snort >/dev/null 2>&1; then
      echo -e "${CLR_CYAN}[+] Auto-installing Snort on RPM...${CLR_RESET}"
      $PKG_MANAGER install -y -q snort || true
    fi
    ;;

  pacman)
    pacman -Sy --noconfirm iptables conntrack-tools curl jq sqlite || true
    if [ "$INSTALL_SURICATA" = true ] && ! command -v suricata >/dev/null 2>&1; then
      pacman -Sy --noconfirm suricata || true
      systemctl enable --now suricata >/dev/null 2>&1 || true
    fi
    if [ "$INSTALL_SNORT" = true ] && ! command -v snort >/dev/null 2>&1; then
      pacman -Sy --noconfirm snort || true
    fi
    ;;

  *)
    echo -e "${CLR_YELLOW}[WARN] Package manager not recognized. Ensure Suricata/Snort are installed if desired.${CLR_RESET}"
    ;;
esac

# 5. Prepare Directories with strict permissions (0750)
mkdir -p /etc/copsec /var/lib/copsec /var/log/copsec /usr/local/bin /var/log/suricata /var/log/snort /var/run/snort
chmod 0750 /etc/copsec /var/lib/copsec /var/log/copsec

# 6. Detect Active Log Sources Automatically
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

# Suricata EVE JSON
if [ -f "/var/log/suricata/eve.json" ]; then
  DETECTED_SURICATA="/var/log/suricata/eve.json"
  echo -e "  ${CLR_GREEN}✔ Suricata EVE Stream:${CLR_RESET} ${DETECTED_SURICATA}"
else
  touch /var/log/copsec/dummy_suricata.json
  DETECTED_SURICATA="/var/log/copsec/dummy_suricata.json"
  echo -e "  ${CLR_YELLOW}⚠ Suricata EVE log not found (initialized standby stream)${CLR_RESET}"
fi

# Snort Alert JSON / Snort-ML Stream
if [ -f "/var/log/snort/alert_json.txt" ]; then
  DETECTED_SNORT="/var/log/snort/alert_json.txt"
  echo -e "  ${CLR_GREEN}✔ Snort-ML Alert Stream:${CLR_RESET} ${DETECTED_SNORT}"
elif [ -f "/var/log/snort/snort.alert" ]; then
  DETECTED_SNORT="/var/log/snort/snort.alert"
  echo -e "  ${CLR_GREEN}✔ Snort Alert Log:${CLR_RESET} ${DETECTED_SNORT}"
else
  touch /var/log/copsec/dummy_snort.txt
  DETECTED_SNORT="/var/log/copsec/dummy_snort.txt"
  echo -e "  ${CLR_YELLOW}⚠ Snort Alert stream not found (initialized standby stream)${CLR_RESET}"
fi

# 7. Generate or Load Node Identity
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
  FINAL_NODE_ID="$(grep -o '"node_id": *"[^"]*"' "$NODE_ID_FILE" | cut -d'"' -f4 || echo "node-edge")"
  echo -e "${CLR_GREEN}[+] Using Existing Node ID : ${CLR_CYAN}${FINAL_NODE_ID}${CLR_RESET}"
fi

# 8. Generate Dynamic Whitelist File if missing
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

# 9. Deploy Binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -n "$BINARY_URL" ]; then
  echo -e "${CLR_CYAN}[+] Downloading copsec-collector from: ${BINARY_URL}${CLR_RESET}"
  curl -fsSL "$BINARY_URL" -o /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Downloaded and Installed : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif [ -f "${PARENT_DIR}/collector/copsec-collector" ]; then
  cp -f "${PARENT_DIR}/collector/copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Installed Collector Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif [ -f "./copsec-collector" ]; then
  cp -f "./copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Installed Collector Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif [ -f "/tmp/copsec-collector" ]; then
  cp -f "/tmp/copsec-collector" /usr/local/bin/copsec-collector
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Installed Collector Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
elif command -v go >/dev/null 2>&1 && [ -d "${PARENT_DIR}/collector" ]; then
  echo -e "${CLR_MAGENTA}[*] Compiling copsec-collector from source...${CLR_RESET}"
  (cd "${PARENT_DIR}/collector" && go build -ldflags="-s -w" -o /usr/local/bin/copsec-collector .)
  chmod 0755 /usr/local/bin/copsec-collector
  echo -e "${CLR_GREEN}[+] Built and Installed Binary : ${CLR_CYAN}/usr/local/bin/copsec-collector${CLR_RESET}"
else
  # Check if controller HTTP has binary ready or fallback
  CTRL_HOST="$(echo "${CONTROLLER_ADDR}" | cut -d':' -f1)"
  CTRL_PORT="$(echo "${CONTROLLER_ADDR}" | cut -d':' -f2)"
  HTTP_PORT="8080"
  if [ "$CTRL_PORT" = "8443" ]; then
    HTTP_PORT="8080"
  fi
  REMOTE_BIN_URL="http://${CTRL_HOST}:${HTTP_PORT}/static/copsec-collector"

  echo -e "${CLR_YELLOW}[*] Attempting to fetch binary from Controller (${REMOTE_BIN_URL})...${CLR_RESET}"
  if curl -fsSL --connect-timeout 5 "$REMOTE_BIN_URL" -o /usr/local/bin/copsec-collector 2>/dev/null; then
    chmod 0755 /usr/local/bin/copsec-collector
    echo -e "${CLR_GREEN}[+] Successfully fetched and installed binary from controller!${CLR_RESET}"
  elif [ -f "/usr/local/bin/copsec-collector" ]; then
    echo -e "${CLR_GREEN}[+] Found existing binary at /usr/local/bin/copsec-collector${CLR_RESET}"
  else
    echo -e "${CLR_RED}[ERROR] copsec-collector binary not found.${CLR_RESET}"
    echo -e "Provide binary URL via: --binary-url http://host:8080/copsec-collector or copy to /usr/local/bin/copsec-collector"
    exit 1
  fi
fi

# 10. Configure Systemd Service
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
  -suricata-log ${DETECTED_SURICATA} \\
  -snort-log ${DETECTED_SNORT}
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
    echo -e " • Suricata    : $(command -v suricata >/dev/null 2>&1 && echo "${CLR_GREEN}active (${DETECTED_SURICATA})${CLR_RESET}" || echo "${CLR_YELLOW}not installed${CLR_RESET}")"
    echo -e " • Snort-ML    : $(command -v snort >/dev/null 2>&1 && echo "${CLR_GREEN}active (${DETECTED_SNORT})${CLR_RESET}" || echo "${CLR_YELLOW}standby (${DETECTED_SNORT})${CLR_RESET}")"
    echo -e " • Service     : ${CLR_GREEN}active (running)${CLR_RESET}"
    echo -e " • Logs        : ${CLR_GRAY}journalctl -u copsec-collector -f${CLR_RESET}"
    echo -e "${CLR_GREEN}==============================================================================${CLR_RESET}"
  else
    echo -e "${CLR_YELLOW}[WARN] Service created. Start manually with: sudo systemctl start copsec-collector${CLR_RESET}"
  fi
else
  echo -e "${CLR_YELLOW}[WARN] systemd not found. Start collector with: /usr/local/bin/copsec-collector -controller ${CONTROLLER_ADDR}${CLR_RESET}"
fi
