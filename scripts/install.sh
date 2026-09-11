#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC Enterprise Autonomous Installer (Tier 1 Collector & Tier 2 Controller)
#  Usage:
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh | sudo bash -s -- --role=controller
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh | sudo bash -s -- --role=collector
# ==============================================================================
set -euo pipefail

CLR_RESET="\033[0m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"
CLR_YELLOW="\033[1;33m"
CLR_MAGENTA="\033[1;35m"
CLR_WHITE="\033[1;37m"

log_banner() {
  echo -e "${CLR_CYAN}"
  cat << 'EOF'
  ██████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║     ██║   ██║██████╔╝███████╗█████╗  ██║     
 ██║     ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║     
 ╚██████╗╚██████╔╝██║     ███████║███████╗╚██████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝
 Enterprise Autonomous Multi-Role Provisioner (eBPF/L7DPI/SIEM)
EOF
  echo -e "${CLR_RESET}"
}

log_info() { echo -e "${CLR_CYAN}[INFO]${CLR_RESET} $1"; }
log_step() { echo -e "\n${CLR_MAGENTA}[STEP]${CLR_RESET} ${CLR_WHITE}$1${CLR_RESET}"; }
log_success() { echo -e "${CLR_GREEN}[✓ SUCCESS]${CLR_RESET} $1"; }
log_warn() { echo -e "${CLR_YELLOW}[⚠️ WARNING]${CLR_RESET} $1"; }
log_error() { echo -e "${CLR_RED}[✗ FATAL]${CLR_RESET} $1" >&2; }

# Early help check
for arg in "$@"; do
  if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
    echo "Usage: sudo bash install.sh --role=<controller|collector> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --role=<controller|collector>  Deploy as Tier 2 Controller/Vault or Tier 1 Collector/Sensor"
    echo "  --interface=<iface>            Network interface for eBPF/XDP (e.g. eth0)"
    echo "  --xdp-mode=<native|generic>    eBPF driver mode (Default: native)"
    echo "  --grpc-port=<port>             Controller telemetry ingestion port (Default: 50051)"
    echo "  --port=<port>                  Web Cockpit HTTP port (Default: 8080)"
    echo "  --controller=<addr>            Target Controller address (Default: 192.168.1.8:50051)"
    echo "  --db-path=<path>               SQLite Ledger path (Default: /var/lib/copsec/vault.db)"
    echo "  --whitelist-yaml=<path>        CIDR whitelist YAML path (Default: /etc/copsec/whitelist.yaml)"
    echo "  --ban-reaper-interval=<dur>    Dynamic ban TTL expiration interval (Default: 15s)"
    echo "  --mirror-sock=<path>           TLS Decryption Mirror UNIX socket (Default: /run/copsec/mirror.sock)"
    exit 0
  fi
done

if [[ "$EUID" -ne 0 ]]; then
  log_error "This installer must be run as root (sudo)."
  exit 1
fi

log_banner

# Defaults
ROLE=""
INTERFACE=""
XDP_MODE="native"
GRPC_PORT="50051"
WEB_PORT="8080"
CONTROLLER_ADDR="192.168.1.8:50051"
DB_PATH="/var/lib/copsec/vault.db"
WHITELIST_YAML="/etc/copsec/whitelist.yaml"
BAN_REAPER_INTERVAL="15s"
MIRROR_SOCK="/run/copsec/mirror.sock"

# Parse CLI args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role=*)
      ROLE="${1#*=}"
      shift
      ;;
    --role)
      ROLE="$2"
      shift 2
      ;;
    --interface=*)
      INTERFACE="${1#*=}"
      shift
      ;;
    --interface|-i)
      INTERFACE="$2"
      shift 2
      ;;
    --xdp-mode=*)
      XDP_MODE="${1#*=}"
      shift
      ;;
    --grpc-port=*)
      GRPC_PORT="${1#*=}"
      shift
      ;;
    --port=*)
      WEB_PORT="${1#*=}"
      shift
      ;;
    --controller=*)
      CONTROLLER_ADDR="${1#*=}"
      shift
      ;;
    --db-path=*)
      DB_PATH="${1#*=}"
      shift
      ;;
    --whitelist-yaml=*)
      WHITELIST_YAML="${1#*=}"
      shift
      ;;
    --ban-reaper-interval=*)
      BAN_REAPER_INTERVAL="${1#*=}"
      shift
      ;;
    --mirror-sock=*)
      MIRROR_SOCK="${1#*=}"
      shift
      ;;
    --help|-h)
      echo "Usage: sudo bash install.sh --role=<controller|collector> [OPTIONS]"
      exit 0
      ;;
    *)
      log_warn "Unknown parameter: $1"
      shift
      ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  log_warn "No --role specified. Defaulting to 'collector'."
  ROLE="collector"
fi

ROLE="$(echo "$ROLE" | tr '[:upper:]' '[:lower:]')"

# Detect Interface if not provided
if [[ -z "$INTERFACE" ]]; then
  INTERFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || echo 'eth0')"
  if [[ -z "$INTERFACE" ]]; then
    INTERFACE="eth0"
  fi
fi

# 1. System Package Dependencies
log_step "Validating system packages"
INSTALL_PKGS=()
for cmd in curl git sqlite3 openssl; do
  if ! command -v "$cmd" &>/dev/null; then
    INSTALL_PKGS+=("$cmd")
  fi
done

if [[ "$ROLE" == "collector" || "$ROLE" == "agent" ]]; then
  for cmd in iptables; do
    if ! command -v "$cmd" &>/dev/null; then
      INSTALL_PKGS+=("$cmd")
    fi
  done
fi

if [[ ${#INSTALL_PKGS[@]} -gt 0 ]]; then
  log_info "Installing missing dependencies: ${INSTALL_PKGS[*]}..."
  if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq "${INSTALL_PKGS[@]}"
  elif command -v dnf &>/dev/null; then
    dnf install -y -q "${INSTALL_PKGS[@]}"
  elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm "${INSTALL_PKGS[@]}"
  fi
fi

# Ensure Go toolchain is available for autonomous compilation
if ! command -v go &>/dev/null; then
  log_info "Go compiler not found. Installing Go toolchain..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq golang-go || true
  fi
  if ! command -v go &>/dev/null; then
    GO_TAR="go1.22.4.linux-amd64.tar.gz"
    ARCH="$(uname -m)"
    if [[ "$ARCH" == "aarch64" ]]; then GO_TAR="go1.22.4.linux-arm64.tar.gz"; fi
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH=$PATH:/usr/local/go/bin
    rm -f "/tmp/${GO_TAR}"
  fi
fi

# 2. Setup Directory Hierarchy
log_step "Configuring directory hierarchy"
BIN_DIR="/opt/copsec/bin"
CONF_DIR="/etc/copsec"
DATA_DIR="/var/lib/copsec"
LOG_DIR="/var/log/copsec"
FORENSICS_DIR="${LOG_DIR}/forensics"
RUN_DIR="/run/copsec"

mkdir -p "$BIN_DIR" "$CONF_DIR" "$DATA_DIR" "$LOG_DIR" "$FORENSICS_DIR" "$RUN_DIR"
chmod 755 "$BIN_DIR"
chmod 700 "$DATA_DIR"
chmod 700 "$FORENSICS_DIR"
chmod 755 "$RUN_DIR"

# 3. Locate or Clone Source Code and Build
log_step "Compiling autonomous CoPSeC binaries for role: $ROLE"
SRC_ROOT=""
if [[ -d "/home/copdasten/copsec/collector" && -d "/home/copdasten/copsec/controller" ]]; then
  SRC_ROOT="/home/copdasten/copsec"
elif [[ -d "./collector" && -d "./controller" ]]; then
  SRC_ROOT="$(pwd)"
else
  BUILD_TMP="/tmp/copsec_build_$$"
  mkdir -p "$BUILD_TMP"
  log_info "Cloning repository from GitHub into ${BUILD_TMP}..."
  git clone --depth 1 https://github.com/CoPdasten/copsec.git "$BUILD_TMP"
  SRC_ROOT="$BUILD_TMP"
fi

export CGO_ENABLED=1

# Compile Binaries
if [[ "$ROLE" == "controller" || "$ROLE" == "vault" ]]; then
  log_info "Building copsec-controller..."
  (cd "${SRC_ROOT}/controller" && go build -ldflags="-s -w" -o "${BIN_DIR}/copsec-controller" .)
  chmod +x "${BIN_DIR}/copsec-controller"
  log_success "copsec-controller binary installed at ${BIN_DIR}/copsec-controller"

  # Initialize SQLite database with immutable audit triggers
  log_step "Initializing Banking-Grade SQLite Ledger with Immutable Triggers"
  mkdir -p "$(dirname "$DB_PATH")"
  sqlite3 "$DB_PATH" << 'SQL_EOF'
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS security_audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    actor_identity TEXT NOT NULL,
    actor_ip TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    justification TEXT NOT NULL,
    cryptographic_hash TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON security_audit_trail
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Updates to security_audit_trail are strictly forbidden by Zero-Trust policy');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON security_audit_trail
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Deletions from security_audit_trail are strictly forbidden by Zero-Trust policy');
END;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);

CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(FAIL, 'CRYPTOGRAPHIC_VIOLATION: audit_logs ledger is strictly immutable');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(FAIL, 'CRYPTOGRAPHIC_VIOLATION: audit_logs ledger is strictly immutable');
END;

CREATE TABLE IF NOT EXISTS active_bans (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    ban_time_ms INTEGER NOT NULL,
    duration_seconds INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
);
SQL_EOF
  chmod 600 "$DB_PATH"
  log_success "SQLite ledger initialized at ${DB_PATH} with hard-abort triggers."

  # Systemd Service for Controller
  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-controller.service
[Unit]
Description=CoPSeC Tier 2 Primary Vault & Security Controller
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-controller --db-path=${DB_PATH} --grpc-port=${GRPC_PORT} --port=${WEB_PORT} --allow-external-bind=true
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
  systemctl daemon-reload
  systemctl enable copsec-controller.service || true
  log_success "copsec-controller.service created and enabled."

elif [[ "$ROLE" == "collector" || "$ROLE" == "agent" ]]; then
  log_info "Building copsec-collector..."
  (cd "${SRC_ROOT}/collector" && go build -ldflags="-s -w" -o "${BIN_DIR}/copsec-collector" .)
  chmod +x "${BIN_DIR}/copsec-collector"
  log_success "copsec-collector binary installed at ${BIN_DIR}/copsec-collector"

  # Provision Whitelist YAML
  if [[ -f "${SRC_ROOT}/config/whitelist.yaml" ]]; then
    cp "${SRC_ROOT}/config/whitelist.yaml" "$WHITELIST_YAML"
  else
    cat << 'WHITELIST_EOF' > "$WHITELIST_YAML"
# CoPSeC Enterprise CIDR Whitelist Configuration
trusted_cidrs:
  - 127.0.0.1/32
  - 127.0.0.0/8
  - "::1/128"
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 100.64.0.0/10
  - 198.51.100.50/32
  - 203.0.113.10/32
WHITELIST_EOF
  fi
  chmod 644 "$WHITELIST_YAML"
  log_success "CIDR Whitelist configured at ${WHITELIST_YAML}"

  # Systemd Service for Collector
  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-collector.service
[Unit]
Description=CoPSeC Tier 1 Edge Sensor & L7 DPI Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-collector --controller=${CONTROLLER_ADDR} --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK}
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
  systemctl daemon-reload
  systemctl enable copsec-collector.service || true
  log_success "copsec-collector.service created and enabled."
fi

# Clean temporary build dir if created
if [[ "$SRC_ROOT" == /tmp/copsec_build_* ]]; then
  rm -rf "$SRC_ROOT"
fi

echo ""
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo -e "${CLR_GREEN} CoPSeC Autonomous Provisioning Completed Successfully! [Role: ${ROLE}]${CLR_RESET}"
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
if [[ "$ROLE" == "controller" || "$ROLE" == "vault" ]]; then
  echo -e "  To launch controller manually:"
  echo -e "    ${CLR_CYAN}sudo ${BIN_DIR}/copsec-controller --db-path=${DB_PATH} --grpc-port=${GRPC_PORT}${CLR_RESET}"
  echo -e "  To start via systemd:"
  echo -e "    ${CLR_CYAN}sudo systemctl start copsec-controller${CLR_RESET}"
else
  echo -e "  To launch collector manually with native XDP:"
  echo -e "    ${CLR_CYAN}sudo ${BIN_DIR}/copsec-collector --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK}${CLR_RESET}"
  echo -e "  To start via systemd:"
  echo -e "    ${CLR_CYAN}sudo systemctl start copsec-collector${CLR_RESET}"
fi
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
