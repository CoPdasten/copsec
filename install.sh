#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC - Enterprise Autonomous XDR & Linux Security Platform Installer
# ==============================================================================
#  Supported OS: Ubuntu, Debian, Fedora, Arch Linux, CentOS, RHEL, AlmaLinux, Rocky Linux
#  Supported Init: systemd
# ==============================================================================

set -euo pipefail

# ANSI Cyberpunk Terminal Styling
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"
CLR_YELLOW="\033[1;33m"
CLR_MAGENTA="\033[1;35m"
CLR_BLUE="\033[1;34m"
CLR_GRAY="\033[0;90m"

# Print Brand Banner
print_banner() {
  echo -e "${CLR_CYAN}"
  cat << 'ASCII_BANNER'
  ██████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║     ██║   ██║██████╔╝███████╗█████╗  ██║     
 ██║     ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║     
 ╚██████╗╚██████╔╝██║     ███████║███████╗╚██████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝
 Enterprise Autonomous XDR & SOC Platform Installer
ASCII_BANNER
  echo -e "${CLR_RESET}"
}

# ------------------------------------------------------------------------------
# 1. Configuration & Default Parameters (CLI Flags & Env Overrides)
# ------------------------------------------------------------------------------
COPSEC_USER="${COPSEC_USER:-copsec}"
COPSEC_INSTALL_DIR="${COPSEC_INSTALL_DIR:-/opt/copsec}"
COPSEC_DATA_DIR="${COPSEC_DATA_DIR:-/var/lib/copsec}"
COPSEC_LOG_DIR="${COPSEC_LOG_DIR:-/var/log/copsec}"
COPSEC_CONF_DIR="${COPSEC_CONF_DIR:-/etc/copsec}"
COPSEC_PORT="${COPSEC_PORT:-8080}"
COPSEC_API_KEY="${COPSEC_API_KEY:-}"
ENABLE_SERVICE=true
FORCE_REINSTALL=false
CLI_PASSED_API_KEY=""

show_help() {
  echo "Usage: sudo bash install.sh [OPTIONS]"
  echo ""
  echo "Modular, unattended-capable production installer for the CoPSeC platform."
  echo ""
  echo "Options:"
  echo "  --user <name>            Dedicated system user (Default: copsec | \$COPSEC_USER)"
  echo "  --install-dir <path>     Installation directory for binaries (Default: /opt/copsec | \$COPSEC_INSTALL_DIR)"
  echo "  --data-dir <path>        Directory for persistent databases & state (Default: /var/lib/copsec | \$COPSEC_DATA_DIR)"
  echo "  --log-dir <path>         Directory for service & audit logs (Default: /var/log/copsec | \$COPSEC_LOG_DIR)"
  echo "  --conf-dir <path>        Configuration directory (Default: /etc/copsec | \$COPSEC_CONF_DIR)"
  echo "  --port <port>            Web Cockpit HTTP listen port (Default: 8080 | \$COPSEC_PORT)"
  echo "  --api-key <key>          Master API Key (Default: auto-generated 32-byte hex token | \$COPSEC_API_KEY)"
  echo "  --no-service             Install binaries & configs without registering/enabling systemd unit"
  echo "  --force, -f              Force overwrite existing configs and binary links"
  echo "  --help, -h               Display this help and exit"
  echo ""
  echo "Environment Overrides:"
  echo "  COPSEC_USER, COPSEC_INSTALL_DIR, COPSEC_DATA_DIR, COPSEC_LOG_DIR, COPSEC_CONF_DIR,"
  echo "  COPSEC_PORT, COPSEC_API_KEY"
  echo ""
  echo "Examples:"
  echo "  sudo bash install.sh"
  echo "  sudo bash install.sh --port 9090 --api-key my-secure-token-12345"
  echo "  COPSEC_PORT=8443 sudo bash install.sh --no-service"
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      COPSEC_USER="$2"
      shift 2
      ;;
    --install-dir)
      COPSEC_INSTALL_DIR="$2"
      shift 2
      ;;
    --data-dir)
      COPSEC_DATA_DIR="$2"
      shift 2
      ;;
    --log-dir)
      COPSEC_LOG_DIR="$2"
      shift 2
      ;;
    --conf-dir)
      COPSEC_CONF_DIR="$2"
      shift 2
      ;;
    --port)
      COPSEC_PORT="$2"
      shift 2
      ;;
    --api-key)
      COPSEC_API_KEY="$2"
      CLI_PASSED_API_KEY="$2"
      shift 2
      ;;
    --no-service)
      ENABLE_SERVICE=false
      shift
      ;;
    --force|-f)
      FORCE_REINSTALL=true
      shift
      ;;
    --help|-h)
      print_banner
      show_help
      exit 0
      ;;
    *)
      echo -e "${CLR_YELLOW}[WARN] Unknown option: $1${CLR_RESET}"
      shift
      ;;
  esac
done

# Ensure valid port number
if ! [[ "$COPSEC_PORT" =~ ^[0-9]+$ ]] || [ "$COPSEC_PORT" -lt 1 ] || [ "$COPSEC_PORT" -gt 65535 ]; then
  echo -e "${CLR_RED}[FATAL] Invalid port number: ${COPSEC_PORT}. Must be between 1 and 65535.${CLR_RESET}"
  exit 1
fi

# Auto-generate cryptographically secure 32-byte (64 hex characters) API Key if none provided
if [ -z "$COPSEC_API_KEY" ]; then
  if command -v openssl >/dev/null 2>&1; then
    COPSEC_API_KEY="$(openssl rand -hex 32)"
  else
    COPSEC_API_KEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
fi

# ------------------------------------------------------------------------------
# 2. System Pre-Flight Checks & Dependency Validation
# ------------------------------------------------------------------------------
validate_preflight() {
  echo -e "${CLR_MAGENTA}[*] Running system pre-flight checks...${CLR_RESET}"

  # Check root privileges
  if [ "$EUID" -ne 0 ]; then
    echo -e "${CLR_RED}[FATAL] Root or sudo privileges required (EUID must be 0). Run as root or with sudo.${CLR_RESET}"
    exit 1
  fi
  echo -e "  ${CLR_GREEN}✔ Root privileges verified (EUID=0)${CLR_RESET}"

  # Validate OS Kernel (Linux only)
  local os_type
  os_type="$(uname -s)"
  if [ "$os_type" != "Linux" ]; then
    echo -e "${CLR_RED}[FATAL] CoPSeC requires a Linux environment. Detected: ${os_type}${CLR_RESET}"
    exit 1
  fi

  # Check Linux Kernel version for eBPF / XDP compatibility (>= 5.8 recommended)
  local kernel_release
  kernel_release="$(uname -r)"
  local major_ver
  local minor_ver
  major_ver="$(echo "$kernel_release" | cut -d'.' -f1 | tr -dc '0-9')"
  minor_ver="$(echo "$kernel_release" | cut -d'.' -f2 | tr -dc '0-9')"
  major_ver="${major_ver:-0}"
  minor_ver="${minor_ver:-0}"

  if [ "$major_ver" -gt 5 ] || { [ "$major_ver" -eq 5 ] && [ "$minor_ver" -ge 8 ]; }; then
    echo -e "  ${CLR_GREEN}✔ Linux kernel version ${kernel_release} (>= 5.8) - eBPF/XDP full support confirmed${CLR_RESET}"
  else
    echo -e "  ${CLR_YELLOW}⚠ WARNING: Linux kernel version ${kernel_release} is older than 5.8.${CLR_RESET}"
    echo -e "  ${CLR_YELLOW}           eBPF ring buffers, XDP fast-path, and bpf_link may have limited functionality.${CLR_RESET}"
  fi

  # Check init system (systemd)
  if [ "$ENABLE_SERVICE" = true ]; then
    if [ ! -d "/run/systemd/system" ] && ! command -v systemctl >/dev/null 2>&1; then
      echo -e "  ${CLR_YELLOW}⚠ systemd environment not detected. Disabling automatic systemd unit installation.${CLR_RESET}"
      ENABLE_SERVICE=false
    else
      echo -e "  ${CLR_GREEN}✔ systemd init system detected${CLR_RESET}"
    fi
  fi
}

install_dependencies() {
  echo -e "${CLR_MAGENTA}[*] Detecting package manager and validating runtimes...${CLR_RESET}"

  local pkg_manager=""
  if command -v apt-get >/dev/null 2>&1; then
    pkg_manager="apt"
  elif command -v dnf >/dev/null 2>&1; then
    pkg_manager="dnf"
  elif command -v yum >/dev/null 2>&1; then
    pkg_manager="yum"
  elif command -v pacman >/dev/null 2>&1; then
    pkg_manager="pacman"
  elif command -v zypper >/dev/null 2>&1; then
    pkg_manager="zypper"
  elif command -v apk >/dev/null 2>&1; then
    pkg_manager="apk"
  fi

  echo -e "  ${CLR_BLUE}• Package Manager Detected:${CLR_RESET} ${pkg_manager:-unknown}"

  case "$pkg_manager" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq || true
      apt-get install -y -qq sqlite3 curl jq libpcap-dev libpcap0.8 openssl ca-certificates >/dev/null 2>&1 || \
        apt-get install -y sqlite3 curl jq libpcap-dev openssl ca-certificates || true
      ;;
    dnf)
      dnf install -y -q sqlite curl jq libpcap libpcap-devel openssl ca-certificates >/dev/null 2>&1 || \
        dnf install -y sqlite curl jq libpcap openssl ca-certificates || true
      ;;
    yum)
      yum install -y -q sqlite curl jq libpcap libpcap-devel openssl ca-certificates >/dev/null 2>&1 || \
        yum install -y sqlite curl jq libpcap openssl ca-certificates || true
      ;;
    pacman)
      pacman -Sy --noconfirm --needed sqlite curl jq libpcap openssl ca-certificates >/dev/null 2>&1 || true
      ;;
    zypper)
      zypper --non-interactive install -y sqlite3 curl jq libpcap1 libpcap-devel openssl ca-certificates >/dev/null 2>&1 || true
      ;;
    apk)
      apk add --no-cache sqlite curl jq libpcap libpcap-dev openssl ca-certificates >/dev/null 2>&1 || true
      ;;
    *)
      echo -e "  ${CLR_YELLOW}⚠ Unrecognized package manager. Ensuring required binaries are available on PATH...${CLR_RESET}"
      ;;
  esac

  # Verify core utility availability
  local missing_tools=()
  for tool in curl jq sqlite3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done

  if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "${CLR_YELLOW}[WARN] Missing non-critical utilities: ${missing_tools[*]}. CoPSeC will function, but some CLI audit helpers require them.${CLR_RESET}"
  else
    echo -e "  ${CLR_GREEN}✔ Core dependencies verified (sqlite3, curl, jq, openssl, libpcap)${CLR_RESET}"
  fi
}

# ------------------------------------------------------------------------------
# 3. Dedicated System Account & Directory Permissions
# ------------------------------------------------------------------------------
setup_user_and_directories() {
  echo -e "${CLR_MAGENTA}[*] Provisioning isolated system user and directory structure...${CLR_RESET}"

  # Create dedicated system group if not exists
  if ! getent group "$COPSEC_USER" >/dev/null 2>&1; then
    groupadd --system "$COPSEC_USER" >/dev/null 2>&1 || groupadd "$COPSEC_USER" >/dev/null 2>&1 || true
    echo -e "  ${CLR_GREEN}✔ Created system group: ${COPSEC_USER}${CLR_RESET}"
  fi

  # Create dedicated system user if not exists
  if ! id -u "$COPSEC_USER" >/dev/null 2>&1; then
    useradd --system \
      --no-create-home \
      --gid "$COPSEC_USER" \
      --shell /usr/sbin/nologin \
      --comment "CoPSeC Autonomous Security Daemon" \
      "$COPSEC_USER" >/dev/null 2>&1 || \
    useradd -r -s /usr/sbin/nologin -g "$COPSEC_USER" "$COPSEC_USER" >/dev/null 2>&1 || true
    echo -e "  ${CLR_GREEN}✔ Created system user: ${COPSEC_USER} (nologin, non-interactive)${CLR_RESET}"
  else
    echo -e "  ${CLR_BLUE}• System user already exists: ${COPSEC_USER}${CLR_RESET}"
  fi

  # Directory Creation
  mkdir -p "${COPSEC_INSTALL_DIR}/bin"
  mkdir -p "${COPSEC_CONF_DIR}"
  mkdir -p "${COPSEC_DATA_DIR}"
  mkdir -p "${COPSEC_LOG_DIR}"

  # Permissions:
  # - Conf and Install directories: read/execute for service user, read-only for general users (chmod 750)
  chown -R root:"${COPSEC_USER}" "${COPSEC_INSTALL_DIR}"
  chmod 0750 "${COPSEC_INSTALL_DIR}"
  chmod 0750 "${COPSEC_INSTALL_DIR}/bin"

  chown -R root:"${COPSEC_USER}" "${COPSEC_CONF_DIR}"
  chmod 0750 "${COPSEC_CONF_DIR}"

  # - Data and Log directories: owned exclusively by COPSEC_USER with chmod 700 to prevent leaks
  chown -R "${COPSEC_USER}":"${COPSEC_USER}" "${COPSEC_DATA_DIR}"
  chmod 0700 "${COPSEC_DATA_DIR}"

  chown -R "${COPSEC_USER}":"${COPSEC_USER}" "${COPSEC_LOG_DIR}"
  chmod 0700 "${COPSEC_LOG_DIR}"

  echo -e "  ${CLR_GREEN}✔ Directory boundaries and permission masks established:${CLR_RESET}"
  echo -e "    • Install  : ${COPSEC_INSTALL_DIR} [0750 root:${COPSEC_USER}]"
  echo -e "    • Config   : ${COPSEC_CONF_DIR} [0750 root:${COPSEC_USER}]"
  echo -e "    • Data     : ${COPSEC_DATA_DIR} [0700 ${COPSEC_USER}:${COPSEC_USER}] (Database isolation)"
  echo -e "    • Logs     : ${COPSEC_LOG_DIR} [0700 ${COPSEC_USER}:${COPSEC_USER}]"
}

# ------------------------------------------------------------------------------
# 4. Binaries & Configuration Deployment
# ------------------------------------------------------------------------------
deploy_binaries_and_configs() {
  echo -e "${CLR_MAGENTA}[*] Compiling/Installing CoPSeC binaries and configurations...${CLR_RESET}"

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  # Locate or compile copsec-controller
  local controller_binary="${COPSEC_INSTALL_DIR}/bin/copsec-controller"

  if command -v go >/dev/null 2>&1 && [ -d "${script_dir}/controller" ]; then
    echo -e "  ${CLR_BLUE}• Building copsec-controller from source...${CLR_RESET}"
    (cd "${script_dir}/controller" && go build -ldflags="-s -w" -o "${controller_binary}" .)
  elif [ -f "${script_dir}/controller/copsec-controller" ]; then
    cp -f "${script_dir}/controller/copsec-controller" "${controller_binary}"
  elif [ -f "${script_dir}/copsec-controller" ]; then
    cp -f "${script_dir}/copsec-controller" "${controller_binary}"
  elif [ -f "/usr/local/bin/copsec-controller" ]; then
    cp -f "/usr/local/bin/copsec-controller" "${controller_binary}"
  else
    echo -e "${CLR_RED}[FATAL] Cannot find or build copsec-controller binary!${CLR_RESET}"
    echo -e "${CLR_RED}        Ensure Go 1.22+ is installed or provide a pre-compiled binary.${CLR_RESET}"
    exit 1
  fi

  # Locate or compile copsec-collector (optional companion)
  local collector_binary="${COPSEC_INSTALL_DIR}/bin/copsec-collector"
  if command -v go >/dev/null 2>&1 && [ -d "${script_dir}/collector" ]; then
    echo -e "  ${CLR_BLUE}• Building copsec-collector companion from source...${CLR_RESET}"
    (cd "${script_dir}/collector" && go build -ldflags="-s -w" -o "${collector_binary}" .) || true
  elif [ -f "${script_dir}/collector/copsec-collector" ]; then
    cp -f "${script_dir}/collector/copsec-collector" "${collector_binary}" || true
  fi

  # Set binary permissions (0750 root:copsec)
  chmod 0755 "${controller_binary}"
  chown root:"${COPSEC_USER}" "${controller_binary}"
  if [ -f "${collector_binary}" ]; then
    chmod 0755 "${collector_binary}"
    chown root:"${COPSEC_USER}" "${collector_binary}"
  fi

  # Symlink to /usr/local/bin for immediate CLI access
  ln -sf "${controller_binary}" /usr/local/bin/copsec-controller
  ln -sf "${controller_binary}" /usr/local/bin/copsec
  if [ -f "${collector_binary}" ]; then
    ln -sf "${collector_binary}" /usr/local/bin/copsec-collector
  fi
  echo -e "  ${CLR_GREEN}✔ Installed binaries linked to /usr/local/bin/copsec-controller${CLR_RESET}"

  # Deploy Default Config Files if missing or forced
  if [ ! -f "${COPSEC_CONF_DIR}/rules.json" ] || [ "$FORCE_REINSTALL" = true ]; then
    if [ -f "${script_dir}/config/rules.json" ]; then
      cp -f "${script_dir}/config/rules.json" "${COPSEC_CONF_DIR}/rules.json"
    else
      cat << 'RULES_JSON' > "${COPSEC_CONF_DIR}/rules.json"
{
  "rules": [
    {
      "id": "t1595-001-port-scan-probing",
      "category": "reconnaissance",
      "regex": "(?i)(Nmap\\s+Plugin|masscan|zmap|unicornscan|banner_grab)",
      "status_codes": [400, 403, 404, 500],
      "mitre_tactic": "Reconnaissance",
      "mitre_tactic_id": "TA0043",
      "mitre_technique_id": "T1595.001",
      "mitre_technique_name": "Port Scanning / Probing",
      "threat_score": 50
    }
  ]
}
RULES_JSON
    fi
    chown root:"${COPSEC_USER}" "${COPSEC_CONF_DIR}/rules.json"
    chmod 0640 "${COPSEC_CONF_DIR}/rules.json"
  fi

  if [ ! -f "${COPSEC_CONF_DIR}/whitelist.json" ] || [ "$FORCE_REINSTALL" = true ]; then
    if [ -f "${script_dir}/config/whitelist.json" ]; then
      cp -f "${script_dir}/config/whitelist.json" "${COPSEC_CONF_DIR}/whitelist.json"
    else
      cat << 'WL_JSON' > "${COPSEC_CONF_DIR}/whitelist.json"
{
  "trusted_cidrs": [
    "127.0.0.0/8",
    "::1/128",
    "100.64.0.0/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
}
WL_JSON
    fi
    chown root:"${COPSEC_USER}" "${COPSEC_CONF_DIR}/whitelist.json"
    chmod 0640 "${COPSEC_CONF_DIR}/whitelist.json"
  fi

  # Deploy SigmaHQ rule skeleton if present
  if [ -d "${script_dir}/config/sigma" ]; then
    mkdir -p "${COPSEC_CONF_DIR}/sigma"
    cp -rn "${script_dir}/config/sigma/"* "${COPSEC_CONF_DIR}/sigma/" 2>/dev/null || true
    chown -R root:"${COPSEC_USER}" "${COPSEC_CONF_DIR}/sigma"
    chmod -R 0750 "${COPSEC_CONF_DIR}/sigma"
  fi
}

# ------------------------------------------------------------------------------
# 5. Environment File Generation (/etc/copsec/copsec.env)
# ------------------------------------------------------------------------------
write_environment_file() {
  local env_file="${COPSEC_CONF_DIR}/copsec.env"
  echo -e "${CLR_MAGENTA}[*] Writing protected environment file (${env_file})...${CLR_RESET}"

  # Preserve existing API key if present and user didn't explicitly override it
  if [ -f "$env_file" ] && [ "$FORCE_REINSTALL" = false ]; then
    local existing_key
    existing_key="$(grep -E '^COPSEC_API_KEY=' "$env_file" | cut -d'=' -f2- | tr -d '"'\'' ' || true)"
    if [ -n "$existing_key" ] && [ -z "${CLI_PASSED_API_KEY:-}" ]; then
      COPSEC_API_KEY="$existing_key"
    fi
  fi

  cat << ENV_EOF > "$env_file"
# ==============================================================================
#  CoPSeC Runtime Environment Configuration
#  Managed by CoPSeC Installer - Permissions must remain 0600
# ==============================================================================
COPSEC_USER="${COPSEC_USER}"
COPSEC_API_KEY="${COPSEC_API_KEY}"
COPSEC_PORT="${COPSEC_PORT}"
COPSEC_INSTALL_DIR="${COPSEC_INSTALL_DIR}"
COPSEC_DATA_DIR="${COPSEC_DATA_DIR}"
COPSEC_LOG_DIR="${COPSEC_LOG_DIR}"
COPSEC_CONF_DIR="${COPSEC_CONF_DIR}"
COPSEC_RULES_FILE="${COPSEC_CONF_DIR}/rules.json"
COPSEC_DB_PATH="${COPSEC_DATA_DIR}/copsec.db"
ENV_EOF

  # Lock down environment file permissions to 0600 (owner read/write only)
  chown "${COPSEC_USER}":"${COPSEC_USER}" "$env_file"
  chmod 0600 "$env_file"
  echo -e "  ${CLR_GREEN}✔ Configured environment file with strict permissions (0600 ${COPSEC_USER}:${COPSEC_USER})${CLR_RESET}"
}

# ------------------------------------------------------------------------------
# 6. Systemd Unit Generation & Activation (/etc/systemd/system/copsec.service)
# ------------------------------------------------------------------------------
setup_systemd_service() {
  if [ "$ENABLE_SERVICE" != true ]; then
    echo -e "${CLR_YELLOW}[*] Skipping systemd service generation (--no-service was specified).${CLR_RESET}"
    return 0
  fi

  local service_file="/etc/systemd/system/copsec.service"
  echo -e "${CLR_MAGENTA}[*] Configuring hardened systemd unit (${service_file})...${CLR_RESET}"

  cat << SVC_EOF > "$service_file"
[Unit]
Description=CoPSeC Central Controller & Autonomous SOC Cockpit
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=simple
User=${COPSEC_USER}
Group=${COPSEC_USER}
WorkingDirectory=${COPSEC_DATA_DIR}
EnvironmentFile=${COPSEC_CONF_DIR}/copsec.env
ExecStart=${COPSEC_INSTALL_DIR}/bin/copsec-controller \\
  --web-port=\${COPSEC_PORT} \\
  --rules=\${COPSEC_RULES_FILE} \\
  --db=\${COPSEC_DB_PATH} \\
  --allow-external-bind=true

# Process & Crash Lifecycle
Restart=always
RestartSec=3s
LimitNOFILE=1048576

# Security Hardening & Linux Ambient Capabilities
# Grants eBPF, network filtering, and raw socket inspection without full root privileges
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_BPF CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_BPF CAP_SYS_ADMIN
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${COPSEC_DATA_DIR} ${COPSEC_LOG_DIR}
ReadOnlyPaths=${COPSEC_INSTALL_DIR} ${COPSEC_CONF_DIR}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=copsec

[Install]
WantedBy=multi-user.target
SVC_EOF

  chmod 0644 "$service_file"
  chown root:root "$service_file"

  echo -e "  ${CLR_BLUE}• Reloading systemd daemon...${CLR_RESET}"
  systemctl daemon-reload

  echo -e "  ${CLR_BLUE}• Enabling and starting copsec.service...${CLR_RESET}"
  systemctl enable copsec.service >/dev/null 2>&1 || true
  systemctl restart copsec.service || true

  # Brief verification delay
  sleep 1.5
}

# ------------------------------------------------------------------------------
# 7. Post-Installation Summary
# ------------------------------------------------------------------------------
print_summary() {
  local service_status="disabled / not installed"
  local status_color="${CLR_YELLOW}"

  if [ "$ENABLE_SERVICE" = true ]; then
    if systemctl is-active --quiet copsec.service; then
      service_status="active (running)"
      status_color="${CLR_GREEN}"
    else
      service_status="failed / activating"
      status_color="${CLR_RED}"
    fi
  fi

  echo ""
  echo -e "${CLR_CYAN}==============================================================================${CLR_RESET}"
  echo -e "${CLR_BOLD}${CLR_GREEN}   ✔ CoPSeC Platform Successfully Provisioned & Deployed!${CLR_RESET}"
  echo -e "${CLR_CYAN}==============================================================================${CLR_RESET}"
  echo -e "  ${CLR_BOLD}Platform User      :${CLR_RESET} ${COPSEC_USER}"
  echo -e "  ${CLR_BOLD}Install Directory  :${CLR_RESET} ${COPSEC_INSTALL_DIR}/bin/copsec-controller"
  echo -e "  ${CLR_BOLD}Data Directory     :${CLR_RESET} ${COPSEC_DATA_DIR}"
  echo -e "  ${CLR_BOLD}Log Directory      :${CLR_RESET} ${COPSEC_LOG_DIR}"
  echo -e "  ${CLR_BOLD}Service Status     :${CLR_RESET} ${status_color}${service_status}${CLR_RESET}"
  echo -e "  ${CLR_BOLD}Web Cockpit URL    :${CLR_RESET} ${CLR_CYAN}http://127.0.0.1:${COPSEC_PORT}${CLR_RESET}"
  echo -e "  ${CLR_BOLD}Web Cockpit (LAN)  :${CLR_RESET} ${CLR_CYAN}http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0"):${COPSEC_PORT}${CLR_RESET}"
  echo ""
  echo -e "  ${CLR_BOLD}${CLR_MAGENTA}Master API Key     :${CLR_RESET} ${CLR_YELLOW}${COPSEC_API_KEY}${CLR_RESET}"
  echo -e "  ${CLR_GRAY}(Store this token securely; it provides administrative access to SOC APIs)${CLR_RESET}"
  echo -e "${CLR_CYAN}==============================================================================${CLR_RESET}"
  echo -e "${CLR_BOLD}Operational Commands:${CLR_RESET}"
  echo -e "  • Check Live Logs   : ${CLR_CYAN}journalctl -u copsec -f${CLR_RESET}"
  echo -e "  • Check Service     : ${CLR_CYAN}systemctl status copsec${CLR_RESET}"
  echo -e "  • Restart Service   : ${CLR_CYAN}systemctl restart copsec${CLR_RESET}"
  echo -e "  • Verify Hash Chain : ${CLR_CYAN}curl -s -H \"X-API-Key: ${COPSEC_API_KEY}\" http://127.0.0.1:${COPSEC_PORT}/api/audit/verify-integrity | jq .${CLR_RESET}"
  echo -e "${CLR_CYAN}==============================================================================${CLR_RESET}"
  echo ""
}

# ------------------------------------------------------------------------------
# Main Execution Flow
# ------------------------------------------------------------------------------
main() {
  print_banner
  validate_preflight
  install_dependencies
  setup_user_and_directories
  deploy_binaries_and_configs
  write_environment_file
  setup_systemd_service
  print_summary
}

main "$@"
