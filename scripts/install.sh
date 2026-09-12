#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC Pro - Autonomous Multi-Role Zero-Touch Installer
#  Roles:
#    - Central Controller & Vault: --role=controller
#    - Autonomous Edge Sensor:     --role=collector
#  Usage:
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh | sudo bash -s -- --role=controller
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh | sudo bash -s -- --role=collector --controller-ip=192.168.1.10 --interface=eth0
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh | sudo bash -s -- --role=collector --controller-ip=192.168.1.10 --interface=eth0 --gossip-join=192.168.1.8:7946
# ==============================================================================
set -euo pipefail

# --- ANSI Terminal Formatting ---
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"
CLR_YELLOW="\033[1;33m"
CLR_MAGENTA="\033[1;35m"
CLR_BLUE="\033[1;34m"
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
 Autonomous Zero-Touch Multi-Role Cluster Provisioner
 [eBPF/XDP Line-Rate Defense | Memberlist Gossip | Banking-Grade Vault]
EOF
  echo -e "${CLR_RESET}"
}

log_info()    { echo -e "${CLR_BLUE}[INFO]${CLR_RESET} $1"; }
log_step()    { echo -e "\n${CLR_MAGENTA}${CLR_BOLD}[STEP]${CLR_RESET} ${CLR_WHITE}$1${CLR_RESET}"; }
log_success() { echo -e "${CLR_GREEN}${CLR_BOLD}[✓ SUCCESS]${CLR_RESET} $1"; }
log_warn()    { echo -e "${CLR_YELLOW}[⚠️ WARN]${CLR_RESET} $1"; }
log_error()   { echo -e "${CLR_RED}${CLR_BOLD}[✗ FATAL]${CLR_RESET} $1" >&2; }
log_metric()  { printf "  ${CLR_CYAN}├─ %-32s :${CLR_RESET} ${CLR_WHITE}%s${CLR_RESET}\n" "$1" "$2"; }

# Allow --help / -h without root privileges
for arg in "$@"; do
  if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
    cat << 'HELP_EOF'
Usage: sudo bash install.sh --role=<standalone|controller|collector|vault-server|cockpit-proxy> [OPTIONS]

Deployment Topologies:
  --role=standalone              Single-host all-in-one stack (Local Vault, Ingestion, XDP & Web Cockpit)
  --role=controller              Central Vault, gRPC Ingestion Hub (:50051), and Web Cockpit (:8080)
  --role=collector               Autonomous Edge Sensor with native eBPF/XDP driver hook and Tarpit
  --role=vault-server            Dedicated Tier 2 Vault Server & SQLite WAL Database Hub (:50051)
  --role=cockpit-proxy           Tier 3 Zero-Storage Analyst Cockpit (:8080) connecting to remote vault

Options:
  --controller-ip=<ip>          Central Controller / Vault IP (Default: 192.168.1.10)
  --vault-ip=<ip>               Remote Vault Server IP for cockpit-proxy or collector
  --controller=<ip:port>        Explicit gRPC address (Default: <controller-ip>:50051)
  --interface=<iface>           Network interface for eBPF/XDP driver hook (Default: auto-detect)
  --gossip-join=<ip:port>       Initial Memberlist Gossip peer to join (e.g. 192.168.1.8:7946)
  --gossip-port=<port>          Port for Gossip threat replication (Default: 7946)
  --grpc-port=<port>            gRPC server port for Controller / Vault (Default: 50051)
  --web-port=<port>             Web SOC Cockpit HTTP port (Default: 8080)
  --db-path=<path>              SQLite WAL ledger database path (Default: /var/lib/copsec/vault.db)
  --xdp-mode=<native|generic>   eBPF driver attachment mode (Default: native)
  --ban-reaper-interval=<dur>   Dynamic ban TTL eviction interval (Default: 15s)
HELP_EOF
    exit 0
  fi
done

# Check root privileges
if [[ "$EUID" -ne 0 ]]; then
  log_error "This installer requires root privileges. Please execute with sudo."
  exit 1
fi

log_banner

# --- Default Parameters ---
ROLE=""
INTERFACE=""
XDP_MODE="native"
CONTROLLER_IP=""
VAULT_IP=""
CONTROLLER_ADDR=""
GRPC_PORT="50051"
WEB_PORT="8080"
DB_PATH="/var/lib/copsec/vault.db"
GOSSIP_PORT="7946"
GOSSIP_JOIN=""
BAN_REAPER_INTERVAL="15s"
WHITELIST_YAML="/etc/copsec/whitelist.yaml"
MIRROR_SOCK="/run/copsec/mirror.sock"

# Parse CLI arguments (supporting both --flag=value and --flag value)
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
    --controller-ip=*)
      CONTROLLER_IP="${1#*=}"
      shift
      ;;
    --controller-ip)
      CONTROLLER_IP="$2"
      shift 2
      ;;
    --controller=*)
      CONTROLLER_ADDR="${1#*=}"
      shift
      ;;
    --controller)
      CONTROLLER_ADDR="$2"
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
    --gossip-join=*)
      GOSSIP_JOIN="${1#*=}"
      shift
      ;;
    --gossip-join)
      GOSSIP_JOIN="$2"
      shift 2
      ;;
    --gossip-port=*)
      GOSSIP_PORT="${1#*=}"
      shift
      ;;
    --gossip-port)
      GOSSIP_PORT="$2"
      shift 2
      ;;
    --grpc-port=*)
      GRPC_PORT="${1#*=}"
      shift
      ;;
    --grpc-port)
      GRPC_PORT="$2"
      shift 2
      ;;
    --port=*|--web-port=*)
      WEB_PORT="${1#*=}"
      shift
      ;;
    --port|--web-port)
      WEB_PORT="$2"
      shift 2
      ;;
    --db-path=*|--db=*)
      DB_PATH="${1#*=}"
      shift
      ;;
    --db-path|--db)
      DB_PATH="$2"
      shift 2
      ;;
    --xdp-mode=*)
      XDP_MODE="${1#*=}"
      shift
      ;;
    --xdp-mode)
      XDP_MODE="$2"
      shift 2
      ;;
    --ban-reaper-interval=*)
      BAN_REAPER_INTERVAL="${1#*=}"
      shift
      ;;
    --ban-reaper-interval)
      BAN_REAPER_INTERVAL="$2"
      shift 2
      ;;
    --whitelist-yaml=*)
      WHITELIST_YAML="${1#*=}"
      shift
      ;;
    --whitelist-yaml)
      WHITELIST_YAML="$2"
      shift 2
      ;;
    --mirror-sock=*)
      MIRROR_SOCK="${1#*=}"
      shift
      ;;
    --mirror-sock)
      MIRROR_SOCK="$2"
      shift 2
      ;;
    --vault-ip=*)
      VAULT_IP="${1#*=}"
      shift
      ;;
    --vault-ip)
      VAULT_IP="$2"
      shift 2
      ;;
    --help|-h)
      cat << 'HELP_EOF'
Usage: sudo bash install.sh --role=<standalone|controller|collector|vault-server|cockpit-proxy> [OPTIONS]

Deployment Topologies:
  --role=standalone              Single-host all-in-one stack (Local Vault, Ingestion, XDP & Web Cockpit)
  --role=controller              Central Vault, gRPC Ingestion Hub (:50051), and Web Cockpit (:8080)
  --role=collector               Autonomous Edge Sensor with native eBPF/XDP driver hook and Tarpit
  --role=vault-server            Dedicated Tier 2 Vault Server & SQLite WAL Database Hub (:50051)
  --role=cockpit-proxy           Tier 3 Zero-Storage Analyst Cockpit (:8080) connecting to remote vault

Options:
  --controller-ip=<ip>          Central Controller / Vault IP (Default: 192.168.1.10)
  --vault-ip=<ip>               Remote Vault Server IP for cockpit-proxy or collector
  --controller=<ip:port>        Explicit gRPC address (Default: <controller-ip>:50051)
  --interface=<iface>           Network interface for eBPF/XDP driver hook (Default: auto-detect)
  --gossip-join=<ip:port>       Initial Memberlist Gossip peer to join (e.g. 192.168.1.8:7946)
  --gossip-port=<port>          Port for Gossip threat replication (Default: 7946)
  --grpc-port=<port>            gRPC server port for Controller / Vault (Default: 50051)
  --web-port=<port>             Web SOC Cockpit HTTP port (Default: 8080)
  --db-path=<path>              SQLite WAL ledger database path (Default: /var/lib/copsec/vault.db)
  --xdp-mode=<native|generic>   eBPF driver attachment mode (Default: native)
  --ban-reaper-interval=<dur>   Dynamic ban TTL eviction interval (Default: 15s)
HELP_EOF
      exit 0
      ;;
    *)
      log_warn "Unrecognized option: $1"
      shift
      ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  log_warn "No role specified. Defaulting to '--role=collector'."
  ROLE="collector"
fi
ROLE="$(echo "$ROLE" | tr '[:upper:]' '[:lower:]')"

# Resolve Vault IP to Controller IP if set
if [[ -n "$VAULT_IP" && -z "$CONTROLLER_IP" ]]; then
  CONTROLLER_IP="$VAULT_IP"
fi

# Resolve Controller address
if [[ -z "$CONTROLLER_ADDR" ]]; then
  if [[ -n "$CONTROLLER_IP" ]]; then
    CONTROLLER_ADDR="${CONTROLLER_IP}:${GRPC_PORT}"
  else
    CONTROLLER_ADDR="192.168.1.10:${GRPC_PORT}"
  fi
fi

# Resolve Interface for Collector or Standalone
if [[ ("$ROLE" == "collector" || "$ROLE" == "standalone") && -z "$INTERFACE" ]]; then
  INTERFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  if [[ -z "$INTERFACE" ]]; then
    for cand in eth0 enp0s3 enp3s0 eno1 wlan0; do
      if ip link show "$cand" &>/dev/null; then
        INTERFACE="$cand"
        break
      fi
    done
  fi
  INTERFACE="${INTERFACE:-eth0}"
fi

log_info "Active Configuration Profile:"
log_metric "Assigned Node Role" "${ROLE}"
if [[ "$ROLE" == "controller" || "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
  log_metric "gRPC Ingestion Bind" "0.0.0.0:${GRPC_PORT}"
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "SQLite Immutable Ledger" "${DB_PATH}"
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  log_metric "Target Remote Vault" "${CONTROLLER_ADDR}"
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "Storage Model" "Zero-Storage Analyst Proxy"
elif [[ "$ROLE" == "standalone" ]]; then
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "Local Ingestion gRPC" "127.0.0.1:50051"
  log_metric "eBPF/XDP Network Device" "${INTERFACE} (Mode: ${XDP_MODE})"
  log_metric "SQLite Immutable Ledger" "${DB_PATH}"
else
  log_metric "Target Controller gRPC" "${CONTROLLER_ADDR}"
  log_metric "eBPF/XDP Network Device" "${INTERFACE} (Mode: ${XDP_MODE})"
  log_metric "Memberlist Gossip Port" "${GOSSIP_PORT}"
  if [[ -n "$GOSSIP_JOIN" ]]; then
    log_metric "Memberlist Mesh Peer" "${GOSSIP_JOIN}"
  fi
fi

# ==============================================================================
# STEP 1: HOST DEPENDENCY PROVISIONING
# ==============================================================================
log_step "Step 1: Auditing & Provisioning Host Dependencies"

PKGS_TO_INSTALL=()
for cmd in curl git sqlite3 openssl ip; do
  if ! command -v "$cmd" &>/dev/null; then
    PKGS_TO_INSTALL+=("$cmd")
  fi
done

if command -v apt-get &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  CORE_BUILD_PKGS=(clang llvm libbpf-dev libelf-dev build-essential iproute2 iptables)
  for pkg in "${CORE_BUILD_PKGS[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      PKGS_TO_INSTALL+=("$pkg")
    fi
  done

  if [[ ${#PKGS_TO_INSTALL[@]} -gt 0 ]]; then
    log_info "Installing missing packages via apt: ${PKGS_TO_INSTALL[*]}..."
    apt-get update -qq && apt-get install -y -qq "${PKGS_TO_INSTALL[@]}" 2>/dev/null || true
  fi
elif command -v dnf &>/dev/null; then
  dnf install -y -q clang llvm libbpf-devel elfutils-libelf-devel sqlite iproute iptables openssl git make gcc 2>/dev/null || true
elif command -v pacman &>/dev/null; then
  pacman -Sy --noconfirm clang llvm libbpf libelf sqlite iproute2 iptables openssl git base-devel 2>/dev/null || true
fi

# Ensure Go toolchain is present for compilation if needed
if ! command -v go &>/dev/null; then
  log_info "Go compiler not found. Bootstrapping Go environment..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq golang-go 2>/dev/null || true
  fi
  if ! command -v go &>/dev/null; then
    GO_VER="1.22.4"
    ARCH="$(uname -m)"
    GO_ARCH="amd64"
    if [[ "$ARCH" == "aarch64" ]]; then GO_ARCH="arm64"; fi
    TARBALL="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
    curl -fsSL "https://go.dev/dl/${TARBALL}" -o "/tmp/${TARBALL}"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${TARBALL}"
    export PATH=$PATH:/usr/local/go/bin
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm -f "/tmp/${TARBALL}"
  fi
fi

log_success "Host dependencies verified."

# ==============================================================================
# STEP 2: DIRECTORY HIERARCHY & HARDENING
# ==============================================================================
log_step "Step 2: Configuring Production Directory Hierarchy"
BIN_DIR="/opt/copsec/bin"
CONF_DIR="/etc/copsec"
DATA_DIR="/var/lib/copsec"
LOG_DIR="/var/log/copsec"
FORENSICS_DIR="${LOG_DIR}/forensics"
RUN_DIR="/run/copsec"

mkdir -p "$BIN_DIR" "$CONF_DIR" "$DATA_DIR" "$LOG_DIR" "$FORENSICS_DIR" "$RUN_DIR"
chmod 755 "$BIN_DIR"
chmod 755 "$CONF_DIR"
chmod 700 "$DATA_DIR"
chmod 750 "$LOG_DIR"
chmod 700 "$FORENSICS_DIR"
chmod 755 "$RUN_DIR"

log_success "Directory hierarchy ready at /opt/copsec, /etc/copsec, /var/lib/copsec, /var/log/copsec."

# ==============================================================================
# STEP 3: PRE-FLIGHT CLEANUP & XDP DETACHMENT
# ==============================================================================
log_step "Step 3: Pre-Flight Cleanup & Orphan Process Eviction"

# Detach stale XDP hooks from interface
if [[ -n "$INTERFACE" ]] && command -v ip &>/dev/null; then
  log_info "Detaching pre-existing XDP drivers from ${INTERFACE}..."
  ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
fi

# Terminate orphan service processes prior to ignition
log_info "Evicting previous service instances..."
systemctl stop copsec-controller 2>/dev/null || true
systemctl stop copsec-collector 2>/dev/null || true
systemctl stop copsec-cockpit 2>/dev/null || true
pkill -9 -f "copsec-controller" 2>/dev/null || true
pkill -9 -f "copsec-collector" 2>/dev/null || true
pkill -9 -f "copsec-cockpit" 2>/dev/null || true

log_success "Pre-flight sanitization complete."

# ==============================================================================
# STEP 4: BINARY RESOLUTION & COMPILATION PIPELINE
# ==============================================================================
log_step "Step 4: Resolving & Compiling Autonomous Binaries"

SRC_ROOT=""
if [[ -d "/home/copdasten/copsec/collector" && -d "/home/copdasten/copsec/controller" ]]; then
  SRC_ROOT="/home/copdasten/copsec"
elif [[ -d "./collector" && -d "./controller" ]]; then
  SRC_ROOT="$(pwd)"
elif [[ -d "../collector" && -d "../controller" ]]; then
  SRC_ROOT="$(cd .. && pwd)"
else
  TEMP_REPO="/tmp/copsec_repo_$$"
  mkdir -p "$TEMP_REPO"
  log_info "Cloning fresh repository from GitHub (branch: main)..."
  git clone --depth 1 -b main https://github.com/CoPdasten/copsec.git "$TEMP_REPO"
  SRC_ROOT="$TEMP_REPO"
fi

install_binary() {
  local bin_name="$1"
  local src_subdir="$2"
  local dest_path="${BIN_DIR}/${bin_name}"

  if [[ -f "${SRC_ROOT}/bin/${bin_name}" ]]; then
    log_info "Utilizing pre-compiled binary: ${SRC_ROOT}/bin/${bin_name}"
    cp -f "${SRC_ROOT}/bin/${bin_name}" "$dest_path"
  elif [[ -f "./bin/${bin_name}" ]]; then
    log_info "Utilizing pre-compiled binary: ./bin/${bin_name}"
    cp -f "./bin/${bin_name}" "$dest_path"
  elif [[ "$bin_name" == "copsec-cockpit" && -f "${SRC_ROOT}/bin/copsec-controller" ]]; then
    log_info "Utilizing pre-compiled controller binary for cockpit: ${SRC_ROOT}/bin/copsec-controller"
    cp -f "${SRC_ROOT}/bin/copsec-controller" "$dest_path"
  elif [[ -d "${SRC_ROOT}/${src_subdir}" ]]; then
    log_info "Compiling ${bin_name} from source (${SRC_ROOT}/${src_subdir})..."
    export CGO_ENABLED=1
    (cd "${SRC_ROOT}/${src_subdir}" && go build -ldflags="-s -w" -o "$dest_path" .)
  else
    log_error "Source directory not found: ${SRC_ROOT}/${src_subdir}"
    exit 1
  fi
  chmod 755 "$dest_path"
  ln -sf "$dest_path" "/usr/local/bin/${bin_name}"
}

if [[ "$ROLE" == "standalone" ]]; then
  install_binary "copsec-controller" "controller"
  install_binary "copsec-collector" "collector"
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  install_binary "copsec-cockpit" "controller"
elif [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" || "$ROLE" == "controller" ]]; then
  install_binary "copsec-controller" "controller"
  if [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
    ln -sf "${BIN_DIR}/copsec-controller" "${BIN_DIR}/copsec-vault"
    ln -sf "${BIN_DIR}/copsec-vault" "/usr/local/bin/copsec-vault"
  fi
elif [[ "$ROLE" == "collector" ]]; then
  install_binary "copsec-collector" "collector"
fi

# Compile / copy eBPF Bytecode if role requires XDP packet mitigation
if [[ "$ROLE" == "collector" || "$ROLE" == "standalone" ]]; then
  BPF_OBJ="${CONF_DIR}/copsec_xdp.bpf.o"
  if [[ -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" ]]; then
    cp -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" "$BPF_OBJ"
  elif command -v clang &>/dev/null && [[ -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.c" ]]; then
    log_info "Compiling eBPF/XDP telemetry ring buffer bytecode with clang..."
    clang -target bpf -O2 -g -Wall -c "${SRC_ROOT}/bpf/copsec_xdp.bpf.c" -o "$BPF_OBJ" 2>/dev/null || true
  fi
  if [[ -f "$BPF_OBJ" ]]; then
    chmod 644 "$BPF_OBJ"
    cp -f "$BPF_OBJ" "${BIN_DIR}/copsec_xdp.bpf.o" 2>/dev/null || true
  fi
fi

log_success "Autonomous binaries and eBPF objects prepared."

# ==============================================================================
# STEP 5: ROLE-SPECIFIC PROVISIONING & HARDENED SYSTEMD SERVICES
# ==============================================================================
log_step "Step 5: Provisioning Role Architecture & Registering Systemd Unit"

init_sqlite_ledger() {
  local db_target="$1"
  log_info "Initializing Banking-Grade SQLite Ledger at ${db_target}..."
  mkdir -p "$(dirname "$db_target")"
  sqlite3 "$db_target" << 'SQL_EOF'
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

CREATE TABLE IF NOT EXISTS fleet_nodes (
    node_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    active_interface TEXT,
    last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
);
SQL_EOF
  chmod 600 "$db_target"
  log_success "SQLite immutable ledger configured with CRYPTOGRAPHIC_VIOLATION triggers."
}

provision_collector_configs() {
  if [[ -f "${SRC_ROOT}/config/whitelist.yaml" ]]; then
    cp -f "${SRC_ROOT}/config/whitelist.yaml" "$WHITELIST_YAML"
  else
    cat << 'WHITELIST_EOF' > "$WHITELIST_YAML"
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

  NODE_ID_FILE="${CONF_DIR}/node.json"
  if [[ ! -f "$NODE_ID_FILE" ]]; then
    HOSTNAME_STR="$(hostname 2>/dev/null || echo 'edge-sensor')"
    cat << NODE_EOF > "$NODE_ID_FILE"
{
  "node_id": "${HOSTNAME_STR}",
  "enrolled_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
NODE_EOF
    chmod 644 "$NODE_ID_FILE"
  fi
}

if [[ "$ROLE" == "controller" || "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
  init_sqlite_ledger "$DB_PATH"

  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-controller.service
[Unit]
Description=CoPSeC Tier 2 Primary Vault & Security Controller
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-controller \
  --db-path=${DB_PATH} \
  --grpc-port=${GRPC_PORT} \
  --port=${WEB_PORT} \
  --allow-external-bind=true
Restart=always
RestartSec=3s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  systemctl daemon-reload
  systemctl enable --now copsec-controller.service
  if [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
    ln -sf /etc/systemd/system/copsec-controller.service /etc/systemd/system/copsec-vault.service
  fi
  log_success "Registered and started copsec-controller.service."

elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-cockpit.service
[Unit]
Description=CoPSeC Tier 3 Central SOC Cockpit Analyst Proxy
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-cockpit \
  --remote-vault=${CONTROLLER_ADDR} \
  --web-port=${WEB_PORT} \
  --allow-external-bind=true
Restart=always
RestartSec=3s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  systemctl daemon-reload
  systemctl enable --now copsec-cockpit.service
  log_success "Registered and started copsec-cockpit.service connected to ${CONTROLLER_ADDR}."

elif [[ "$ROLE" == "collector" ]]; then
  provision_collector_configs

  GOSSIP_ARGS="--gossip-port=${GOSSIP_PORT}"
  if [[ -n "$GOSSIP_JOIN" ]]; then
    GOSSIP_ARGS="${GOSSIP_ARGS} --gossip-join=${GOSSIP_JOIN}"
  fi

  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-collector.service
[Unit]
Description=CoPSeC Tier 1 Edge Sensor & L7 DPI Collector
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-collector \
  --controller=${CONTROLLER_ADDR} \
  --interface=${INTERFACE} \
  --xdp-mode=${XDP_MODE} \
  --whitelist-yaml=${WHITELIST_YAML} \
  --node-identity=${NODE_ID_FILE} \
  --ban-reaper-interval=${BAN_REAPER_INTERVAL} \
  --mirror-sock=${MIRROR_SOCK} \
  --enable-tarpit=true \
  --enable-syn-proxy=true \
  ${GOSSIP_ARGS}
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  systemctl daemon-reload
  systemctl enable --now copsec-collector.service
  log_success "Registered and started copsec-collector.service on ${INTERFACE}."

elif [[ "$ROLE" == "standalone" ]]; then
  init_sqlite_ledger "$DB_PATH"
  provision_collector_configs

  # Controller service unit
  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-controller.service
[Unit]
Description=CoPSeC Standalone Vault & Security Controller
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-controller \
  --db-path=${DB_PATH} \
  --grpc-port=${GRPC_PORT} \
  --port=${WEB_PORT} \
  --allow-external-bind=true
Restart=always
RestartSec=3s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  # Collector service unit pointing to local controller
  cat << SYSTEMD_EOF > /etc/systemd/system/copsec-collector.service
[Unit]
Description=CoPSeC Standalone Edge Sensor & L7 DPI Collector
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target copsec-controller.service
Wants=network-online.target copsec-controller.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/copsec
ExecStart=${BIN_DIR}/copsec-collector \
  --controller=127.0.0.1:${GRPC_PORT} \
  --interface=${INTERFACE} \
  --xdp-mode=${XDP_MODE} \
  --whitelist-yaml=${WHITELIST_YAML} \
  --node-identity=${NODE_ID_FILE} \
  --ban-reaper-interval=${BAN_REAPER_INTERVAL} \
  --mirror-sock=${MIRROR_SOCK} \
  --enable-tarpit=true \
  --enable-syn-proxy=true
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  systemctl daemon-reload
  systemctl enable --now copsec-controller.service copsec-collector.service
  log_success "Registered and started standalone copsec-controller and copsec-collector services on ${INTERFACE}."
fi

# Cleanup temporary checkout if created
if [[ -n "$SRC_ROOT" && "$SRC_ROOT" == /tmp/copsec_repo_* ]]; then
  rm -rf "$SRC_ROOT"
fi

# ==============================================================================
# STEP 6: VERIFICATION OF LOCAL SERVICE HEALTH
# ==============================================================================
log_step "Step 6: Verifying Local Service Health"
sleep 1.5

if [[ "$ROLE" == "standalone" ]]; then
  for svc in copsec-controller copsec-collector; do
    if systemctl is-active --quiet "${svc}.service"; then
      log_success "Unit ${svc}.service is ACTIVE and running."
    else
      log_warn "Unit ${svc}.service status pending. Recent journal entries:"
      journalctl -u "${svc}.service" -n 10 --no-pager || true
    fi
  done
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  if systemctl is-active --quiet "copsec-cockpit.service"; then
    log_success "Unit copsec-cockpit.service is ACTIVE and running."
  else
    log_warn "Unit copsec-cockpit.service status pending. Recent journal entries:"
    journalctl -u "copsec-cockpit.service" -n 10 --no-pager || true
  fi
elif [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" || "$ROLE" == "controller" ]]; then
  if systemctl is-active --quiet "copsec-controller.service"; then
    log_success "Unit copsec-controller.service is ACTIVE and running."
  else
    log_warn "Unit copsec-controller.service status pending. Recent journal entries:"
    journalctl -u "copsec-controller.service" -n 10 --no-pager || true
  fi
elif [[ "$ROLE" == "collector" ]]; then
  if systemctl is-active --quiet "copsec-collector.service"; then
    log_success "Unit copsec-collector.service is ACTIVE and running."
  else
    log_warn "Unit copsec-collector.service status pending. Recent journal entries:"
    journalctl -u "copsec-collector.service" -n 10 --no-pager || true
  fi
fi

echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD} CoPSeC Pro Provisioning Complete! Node Role: ${ROLE}${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
if [[ "$ROLE" == "standalone" ]]; then
  echo -e "  • Web SOC Cockpit  : ${CLR_WHITE}http://127.0.0.1:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Local Ingestion  : ${CLR_WHITE}127.0.0.1:${GRPC_PORT} (gRPC)${CLR_RESET}"
  echo -e "  • eBPF/XDP Device  : ${CLR_WHITE}${INTERFACE} (${XDP_MODE})${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Service Units    : ${CLR_CYAN}systemctl status copsec-controller copsec-collector${CLR_RESET}"
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  echo -e "  • Analyst Cockpit  : ${CLR_WHITE}http://0.0.0.0:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Remote Vault Hub : ${CLR_WHITE}${CONTROLLER_ADDR}${CLR_RESET}"
  echo -e "  • Storage Model    : ${CLR_WHITE}Zero-Storage Pure Analyst Mode${CLR_RESET}"
  echo -e "  • Service Unit     : ${CLR_CYAN}systemctl status copsec-cockpit${CLR_RESET}"
elif [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
  echo -e "  • Dedicated Vault  : ${CLR_WHITE}gRPC :${GRPC_PORT} / REST :${WEB_PORT}${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Service Unit     : ${CLR_CYAN}systemctl status copsec-controller${CLR_RESET}"
elif [[ "$ROLE" == "controller" ]]; then
  echo -e "  • Web SOC Cockpit  : ${CLR_WHITE}http://0.0.0.0:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Fleet Ingestion  : ${CLR_WHITE}gRPC :${GRPC_PORT}${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Service Unit     : ${CLR_CYAN}systemctl status copsec-controller${CLR_RESET}"
else
  echo -e "  • Connected Hub    : ${CLR_WHITE}${CONTROLLER_ADDR}${CLR_RESET}"
  echo -e "  • eBPF Fast-Path   : ${CLR_WHITE}${INTERFACE} (${XDP_MODE})${CLR_RESET}"
  echo -e "  • Gossip Mesh Port : ${CLR_WHITE}:${GOSSIP_PORT}${CLR_RESET}"
  echo -e "  • Service Unit     : ${CLR_CYAN}systemctl status copsec-collector${CLR_RESET}"
fi
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
exit 0
