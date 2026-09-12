#!/bin/sh
# ==============================================================================
#  CoPSeC Pro - Dedicated Alpine Linux (OpenRC & Musl) Zero-Touch Installer
#  POSlX /bin/sh & BusyBox Ash Compliant
#
#  Roles:
#    --role=standalone     Single-host all-in-one stack (Local Vault, XDP & Cockpit)
#    --role=controller     Central Vault, gRPC Ingestion Hub (:50051) & Cockpit (:8080)
#    --role=collector      Autonomous Edge Sensor with native eBPF/XDP & Tarpit
#    --role=vault-server   Dedicated Tier 2 Vault Server & SQLite WAL Hub
#    --role=cockpit-proxy  Tier 3 Zero-Storage Analyst Cockpit (:8080)
#
#  Usage:
#    curl -sSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install-alpine.sh | sh -s -- --role=collector --controller-ip=192.168.1.10 --interface=eth0
# ==============================================================================
set -eu

# ANSI Colors
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
  printf "${CLR_CYAN}"
  cat << 'EOF'
  ██████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗ 
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝ 
 ██║     ██║   ██║██████╔╝███████╗█████╗  ██║      
 ██║     ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║      
 ╚██████╗╚██████╔╝██║     ███████║███████╗╚██████╗ 
  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝ 
  Alpine Linux Dedicated Zero-Touch Installer
  [OpenRC Init | Musl Static Go | eBPF/XDP Fast-Path | Banking-Grade Vault]
EOF
  printf "${CLR_RESET}\n"
}

log_info()    { printf "${CLR_BLUE}[INFO]${CLR_RESET} %s\n" "$1"; }
log_step()    { printf "\n${CLR_MAGENTA}${CLR_BOLD}[STEP]${CLR_RESET} ${CLR_WHITE}%s${CLR_RESET}\n" "$1"; }
log_success() { printf "${CLR_GREEN}${CLR_BOLD}[✓ SUCCESS]${CLR_RESET} %s\n" "$1"; }
log_warn()    { printf "${CLR_YELLOW}[⚠️ WARN]${CLR_RESET} %s\n" "$1"; }
log_error()   { printf "${CLR_RED}${CLR_BOLD}[✗ FATAL]${CLR_RESET} %s\n" "$1" >&2; }
log_metric()  { printf "  ${CLR_CYAN}├─ %-32s :${CLR_RESET} ${CLR_WHITE}%s${CLR_RESET}\n" "$1" "$2"; }

# Allow --help / -h without root privileges
for arg in "$@"; do
  if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
    cat << 'HELP_EOF'
Usage: sh install-alpine.sh --role=<standalone|controller|collector|vault-server|cockpit-proxy> [OPTIONS]

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
  --api-key=<key>               Master API key for Web SOC authentication (Default: auto-generated/persisted)
  --xdp-mode=<native|generic>   eBPF driver attachment mode (Default: native)
  --ban-reaper-interval=<dur>   Dynamic ban TTL eviction interval (Default: 15s)
HELP_EOF
    exit 0
  fi
done

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  log_error "This installer requires root privileges. Please execute with sudo or as root."
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
API_KEY="${COPSEC_API_KEY:-}"
GOSSIP_PORT="7946"
GOSSIP_JOIN=""
BAN_REAPER_INTERVAL="15s"
WHITELIST_YAML="/etc/copsec/whitelist.yaml"
MIRROR_SOCK="/run/copsec/mirror.sock"

# Parse CLI arguments (POSIX compatible)
while [ $# -gt 0 ]; do
  case "$1" in
    --api-key=*)
      API_KEY="${1#*=}"
      shift
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
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
    *)
      log_warn "Unrecognized option: $1"
      shift
      ;;
  esac
done

if [ -z "$ROLE" ]; then
  log_warn "No role specified. Defaulting to '--role=collector'."
  ROLE="collector"
fi
ROLE="$(echo "$ROLE" | tr '[:upper:]' '[:lower:]')"

if [ -n "$VAULT_IP" ] && [ -z "$CONTROLLER_IP" ]; then
  CONTROLLER_IP="$VAULT_IP"
fi

if [ -z "$CONTROLLER_ADDR" ]; then
  if [ -n "$CONTROLLER_IP" ]; then
    CONTROLLER_ADDR="${CONTROLLER_IP}:${GRPC_PORT}"
  else
    CONTROLLER_ADDR="192.168.1.10:${GRPC_PORT}"
  fi
fi

if [ "$ROLE" = "collector" ] || [ "$ROLE" = "standalone" ]; then
  if [ -z "$INTERFACE" ]; then
    INTERFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
    if [ -z "$INTERFACE" ]; then
      for cand in eth0 eth1 enp0s3 enp3s0 eno1 wlan0; do
        if ip link show "$cand" >/dev/null 2>&1; then
          INTERFACE="$cand"
          break
        fi
      done
    fi
    INTERFACE="${INTERFACE:-eth0}"
  fi
fi

# Resolve Master API Key
if [ -z "$API_KEY" ]; then
  if [ -f "/etc/copsec/api_key" ]; then
    API_KEY="$(cat /etc/copsec/api_key 2>/dev/null | tr -d ' \r\n' || true)"
  elif [ -f "/etc/copsec/copsec.env" ]; then
    API_KEY="$(grep -E '^COPSEC_API_KEY=' /etc/copsec/copsec.env 2>/dev/null | cut -d'=' -f2- | tr -d ' "\x27\r\n' || true)"
  fi
fi
if [ -z "$API_KEY" ]; then
  API_KEY="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

log_info "Active Alpine Configuration Profile:"
log_metric "Assigned Node Role" "${ROLE}"
log_metric "Operating System" "Alpine Linux ($(cat /etc/alpine-release 2>/dev/null || echo 'generic'))"
log_metric "Init System Engine" "OpenRC (/etc/init.d/)"

if [ "$ROLE" = "controller" ] || [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ]; then
  log_metric "gRPC Ingestion Bind" "0.0.0.0:${GRPC_PORT}"
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "SQLite Immutable Ledger" "${DB_PATH}"
  log_metric "Master API Key" "${API_KEY:0:8}********************************"
elif [ "$ROLE" = "cockpit-proxy" ] || [ "$ROLE" = "cockpit" ]; then
  log_metric "Target Remote Vault" "${CONTROLLER_ADDR}"
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "Storage Model" "Zero-Storage Analyst Proxy"
  log_metric "Master API Key" "${API_KEY:0:8}********************************"
elif [ "$ROLE" = "standalone" ]; then
  log_metric "Web SOC Cockpit Bind" "0.0.0.0:${WEB_PORT}"
  log_metric "Local Ingestion gRPC" "127.0.0.1:50051"
  log_metric "eBPF/XDP Network Device" "${INTERFACE} (Mode: ${XDP_MODE})"
  log_metric "SQLite Immutable Ledger" "${DB_PATH}"
  log_metric "Master API Key" "${API_KEY:0:8}********************************"
else
  log_metric "Target Controller gRPC" "${CONTROLLER_ADDR}"
  log_metric "eBPF/XDP Network Device" "${INTERFACE} (Mode: ${XDP_MODE})"
  log_metric "Memberlist Gossip Port" "${GOSSIP_PORT}"
  if [ -n "$GOSSIP_JOIN" ]; then
    log_metric "Memberlist Mesh Peer" "${GOSSIP_JOIN}"
  fi
fi

# ==============================================================================
# STEP 1: HOST DEPENDENCY PROVISIONING (APK)
# ==============================================================================
log_step "Step 1: Auditing & Provisioning Host Dependencies via apk"

if ! command -v apk >/dev/null 2>&1; then
  log_error "apk package manager not found. This script is intended for Alpine Linux."
  exit 1
fi

log_info "Updating apk repository indexes..."
apk update

log_info "Installing core Alpine build and eBPF dependencies..."
apk add --no-cache \
  build-base \
  clang \
  llvm \
  libbpf-dev \
  linux-headers \
  elfutils-dev \
  iproute2 \
  iptables \
  openssl \
  git \
  make \
  sqlite \
  curl \
  bash \
  openrc

# Ensure Go toolchain is installed
if ! command -v go >/dev/null 2>&1; then
  log_info "Installing Go toolchain from apk repositories..."
  apk add --no-cache go
fi

# ==============================================================================
# STEP 2: eBPF BPF-FS & KERNEL PREPARATION
# ==============================================================================
log_step "Step 2: Preparing eBPF Virtual Filesystem (bpffs)"

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  log_info "Mounting bpffs at /sys/fs/bpf..."
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi

# Persist bpffs mount in /etc/fstab if missing
if ! grep -q "bpf /sys/fs/bpf" /etc/fstab 2>/dev/null; then
  log_info "Appending bpffs mount to /etc/fstab for persistence..."
  printf "bpf /sys/fs/bpf bpf defaults 0 0\n" >> /etc/fstab
fi

# ==============================================================================
# STEP 3: DIRECTORY HIERARCHY & HARDENING
# ==============================================================================
log_step "Step 3: Configuring Production Directory Hierarchy"
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

# Persist Master API Key
echo "$API_KEY" > "${CONF_DIR}/api_key"
chmod 600 "${CONF_DIR}/api_key"

cat << ENV_EOF > "${CONF_DIR}/copsec.env"
COPSEC_API_KEY="${API_KEY}"
ENV_EOF
chmod 600 "${CONF_DIR}/copsec.env"

log_success "Directory hierarchy and credentials ready at /opt/copsec, /etc/copsec, /var/lib/copsec, /var/log/copsec."

# ==============================================================================
# STEP 4: PRE-FLIGHT CLEANUP & XDP DETACHMENT
# ==============================================================================
log_step "Step 4: Pre-Flight Cleanup & Orphan Process Eviction"

if [ -n "$INTERFACE" ] && command -v ip >/dev/null 2>&1; then
  log_info "Detaching pre-existing XDP drivers from ${INTERFACE}..."
  ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
fi

# Terminate existing OpenRC service instances
if command -v rc-service >/dev/null 2>&1; then
  rc-service copsec-controller stop 2>/dev/null || true
  rc-service copsec-collector stop 2>/dev/null || true
  rc-service copsec-cockpit stop 2>/dev/null || true
fi

killall -9 copsec-controller 2>/dev/null || true
killall -9 copsec-collector 2>/dev/null || true
killall -9 copsec-cockpit 2>/dev/null || true

log_success "Pre-flight sanitization complete."

# ==============================================================================
# STEP 5: BINARY RESOLUTION & COMPILATION PIPELINE
# ==============================================================================
log_step "Step 5: Resolving & Compiling Musl-Compatible Static Binaries"

SRC_ROOT=""
if [ -d "/home/copdasten/copsec/collector" ] && [ -d "/home/copdasten/copsec/controller" ]; then
  SRC_ROOT="/home/copdasten/copsec"
elif [ -d "./collector" ] && [ -d "./controller" ]; then
  SRC_ROOT="$(pwd)"
elif [ -d "../collector" ] && [ -d "../controller" ]; then
  SRC_ROOT="$(cd .. && pwd)"
else
  TEMP_REPO="/tmp/copsec_repo_$$"
  mkdir -p "$TEMP_REPO"
  log_info "Cloning fresh repository from GitHub (branch: main)..."
  git clone --depth 1 -b main https://github.com/CoPdasten/copsec.git "$TEMP_REPO"
  SRC_ROOT="$TEMP_REPO"
fi

install_binary() {
  bin_name="$1"
  src_subdir="$2"
  dest_path="${BIN_DIR}/${bin_name}"

  if [ -f "${SRC_ROOT}/bin/${bin_name}" ]; then
    log_info "Utilizing pre-compiled binary: ${SRC_ROOT}/bin/${bin_name}"
    cp -f "${SRC_ROOT}/bin/${bin_name}" "$dest_path"
  elif [ -f "./bin/${bin_name}" ]; then
    log_info "Utilizing pre-compiled binary: ./bin/${bin_name}"
    cp -f "./bin/${bin_name}" "$dest_path"
  elif [ "$bin_name" = "copsec-cockpit" ] && [ -f "${SRC_ROOT}/bin/copsec-controller" ]; then
    log_info "Utilizing pre-compiled controller binary for cockpit: ${SRC_ROOT}/bin/copsec-controller"
    cp -f "${SRC_ROOT}/bin/copsec-controller" "$dest_path"
  elif [ -d "${SRC_ROOT}/${src_subdir}" ]; then
    log_info "Compiling ${bin_name} from source (${SRC_ROOT}/${src_subdir}) with static CGO_ENABLED=0..."
    (cd "${SRC_ROOT}/${src_subdir}" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$dest_path" .)
  else
    log_error "Source directory not found: ${SRC_ROOT}/${src_subdir}"
    exit 1
  fi
  chmod 755 "$dest_path"
  ln -sf "$dest_path" "/usr/local/bin/${bin_name}"
}

if [ "$ROLE" = "standalone" ]; then
  install_binary "copsec-controller" "controller"
  install_binary "copsec-collector" "collector"
elif [ "$ROLE" = "cockpit-proxy" ] || [ "$ROLE" = "cockpit" ]; then
  install_binary "copsec-cockpit" "controller"
elif [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ] || [ "$ROLE" = "controller" ]; then
  install_binary "copsec-controller" "controller"
  if [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ]; then
    ln -sf "${BIN_DIR}/copsec-controller" "${BIN_DIR}/copsec-vault"
    ln -sf "${BIN_DIR}/copsec-vault" "/usr/local/bin/copsec-vault"
  fi
elif [ "$ROLE" = "collector" ]; then
  install_binary "copsec-collector" "collector"
fi

# Always install unified copsec CLI utility
install_binary "copsec" "cmd/copsec"
ln -sf "/usr/local/bin/copsec" "/usr/bin/copsec" 2>/dev/null || true

# Compile / copy eBPF Bytecode if role requires XDP packet mitigation
if [ "$ROLE" = "collector" ] || [ "$ROLE" = "standalone" ]; then
  BPF_OBJ="${CONF_DIR}/copsec_xdp.bpf.o"
  if [ -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" ]; then
    cp -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" "$BPF_OBJ"
  elif command -v clang >/dev/null 2>&1 && [ -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.c" ]; then
    log_info "Compiling eBPF/XDP telemetry ring buffer bytecode with clang on Alpine..."
    clang -target bpf -O2 -g -Wall -c "${SRC_ROOT}/bpf/copsec_xdp.bpf.c" -o "$BPF_OBJ" 2>/dev/null || true
  fi
  if [ -f "$BPF_OBJ" ]; then
    chmod 644 "$BPF_OBJ"
    cp -f "$BPF_OBJ" "${BIN_DIR}/copsec_xdp.bpf.o" 2>/dev/null || true
  fi
fi

log_success "Autonomous binaries and eBPF objects prepared."

# ==============================================================================
# STEP 6: ROLE CONFIGURATION & OPENRC SERVICE REGISTRATION
# ==============================================================================
log_step "Step 6: Configuring OpenRC Services & Immutable Ledger"

init_sqlite_ledger() {
  db_target="$1"
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
    target_resource TEXT NOT NULL,
    status TEXT NOT NULL,
    immutable_signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    source TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    status_code INTEGER,
    timestamp_ms INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    mitre_technique_id TEXT,
    threat_score INTEGER NOT NULL,
    ai_analysis TEXT,
    analyst_notes TEXT,
    playbook_progress INTEGER DEFAULT 0,
    triage_status TEXT DEFAULT 'PENDING',
    containment_state TEXT DEFAULT 'ACTIVE',
    prev_hash TEXT,
    entry_hash TEXT
);

CREATE TABLE IF NOT EXISTS cluster_nodes (
    node_id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    role TEXT NOT NULL,
    active_interface TEXT,
    last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
);
SQL_EOF
  chmod 600 "$db_target"
  log_success "SQLite immutable ledger configured."
}

provision_collector_configs() {
  if [ -f "${SRC_ROOT}/config/whitelist.yaml" ]; then
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
  if [ ! -f "$NODE_ID_FILE" ]; then
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

# OpenRC Service Script Generator
create_openrc_service() {
  svc_name="$1"
  svc_desc="$2"
  svc_bin="$3"
  svc_args="$4"

  cat << OPENRC_EOF > "/etc/init.d/${svc_name}"
#!/sbin/openrc-run

name="${svc_name}"
description="${svc_desc}"

if [ -f /etc/copsec/copsec.env ]; then
    export \$(grep -E '^[A-Za-z0-9_]+=' /etc/copsec/copsec.env | xargs 2>/dev/null || true)
fi

command="${svc_bin}"
command_args="${svc_args}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/copsec/${svc_name}.log"
error_log="/var/log/copsec/${svc_name}.err"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 -o root:root /var/log/copsec
    checkpath -d -m 0700 -o root:root /var/lib/copsec
    checkpath -d -m 0755 -o root:root /run/copsec

    if [ ! -d /sys/fs/bpf ]; then
        mkdir -p /sys/fs/bpf
    fi
    if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    fi
}
OPENRC_EOF
  chmod 755 "/etc/init.d/${svc_name}"
}

if [ "$ROLE" = "controller" ] || [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ]; then
  init_sqlite_ledger "$DB_PATH"
  create_openrc_service "copsec-controller" \
    "CoPSeC Tier 2 Primary Vault & Security Controller" \
    "${BIN_DIR}/copsec-controller" \
    "--db-path=${DB_PATH} --grpc-port=${GRPC_PORT} --port=${WEB_PORT} --api-key=${API_KEY} --allow-external-bind=true"

  rc-update add copsec-controller default
  rc-service copsec-controller restart 2>/dev/null || rc-service copsec-controller start
  log_success "Registered and started OpenRC copsec-controller service."

elif [ "$ROLE" = "cockpit-proxy" ] || [ "$ROLE" = "cockpit" ]; then
  create_openrc_service "copsec-cockpit" \
    "CoPSeC Tier 3 Central SOC Cockpit Analyst Proxy" \
    "${BIN_DIR}/copsec-cockpit" \
    "--remote-vault=${CONTROLLER_ADDR} --web-port=${WEB_PORT} --api-key=${API_KEY} --allow-external-bind=true"

  rc-update add copsec-cockpit default
  rc-service copsec-cockpit restart 2>/dev/null || rc-service copsec-cockpit start
  log_success "Registered and started OpenRC copsec-cockpit service."

elif [ "$ROLE" = "collector" ]; then
  provision_collector_configs

  GOSSIP_ARGS="--gossip-port=${GOSSIP_PORT}"
  if [ -n "$GOSSIP_JOIN" ]; then
    GOSSIP_ARGS="${GOSSIP_ARGS} --gossip-join=${GOSSIP_JOIN}"
  fi

  COLLECTOR_ARGS="--controller=${CONTROLLER_ADDR} --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --node-identity=${NODE_ID_FILE} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK} --enable-tarpit=true --enable-syn-proxy=true ${GOSSIP_ARGS}"

  create_openrc_service "copsec-collector" \
    "CoPSeC Tier 1 Edge Sensor & L7 DPI Collector" \
    "${BIN_DIR}/copsec-collector" \
    "${COLLECTOR_ARGS}"

  rc-update add copsec-collector default
  rc-service copsec-collector restart 2>/dev/null || rc-service copsec-collector start
  log_success "Registered and started OpenRC copsec-collector service on ${INTERFACE}."

elif [ "$ROLE" = "standalone" ]; then
  init_sqlite_ledger "$DB_PATH"
  provision_collector_configs

  create_openrc_service "copsec-controller" \
    "CoPSeC Standalone Vault & Security Controller" \
    "${BIN_DIR}/copsec-controller" \
    "--db-path=${DB_PATH} --grpc-port=${GRPC_PORT} --port=${WEB_PORT} --api-key=${API_KEY} --allow-external-bind=true"

  STANDALONE_COLL_ARGS="--controller=127.0.0.1:${GRPC_PORT} --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --node-identity=${NODE_ID_FILE} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK} --enable-tarpit=true --enable-syn-proxy=true"

  create_openrc_service "copsec-collector" \
    "CoPSeC Standalone Edge Sensor & L7 DPI Collector" \
    "${BIN_DIR}/copsec-collector" \
    "${STANDALONE_COLL_ARGS}"

  rc-update add copsec-controller default
  rc-update add copsec-collector default
  rc-service copsec-controller restart 2>/dev/null || rc-service copsec-controller start
  rc-service copsec-collector restart 2>/dev/null || rc-service copsec-collector start
  log_success "Registered and started standalone OpenRC copsec-controller and copsec-collector services on ${INTERFACE}."
fi

# Cleanup temporary checkout if created
if [ -n "$SRC_ROOT" ]; then
  case "$SRC_ROOT" in
    /tmp/copsec_repo_*) rm -rf "$SRC_ROOT" ;;
  esac
fi

# ==============================================================================
# STEP 7: VERIFICATION OF OPENRC SERVICE HEALTH
# ==============================================================================
log_step "Step 7: Verifying OpenRC Service Health"
sleep 1.5

if [ "$ROLE" = "standalone" ]; then
  for svc in copsec-controller copsec-collector; do
    if rc-service "$svc" status >/dev/null 2>&1; then
      log_success "OpenRC service ${svc} is ACTIVE and running."
    else
      log_warn "OpenRC service ${svc} status check returned non-zero. Recent log entries:"
      tail -n 10 "/var/log/copsec/${svc}.log" 2>/dev/null || true
    fi
  done
elif [ "$ROLE" = "cockpit-proxy" ] || [ "$ROLE" = "cockpit" ]; then
  if rc-service copsec-cockpit status >/dev/null 2>&1; then
    log_success "OpenRC service copsec-cockpit is ACTIVE and running."
  else
    log_warn "OpenRC service copsec-cockpit status check returned non-zero. Recent log entries:"
    tail -n 10 /var/log/copsec/copsec-cockpit.log 2>/dev/null || true
  fi
elif [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ] || [ "$ROLE" = "controller" ]; then
  if rc-service copsec-controller status >/dev/null 2>&1; then
    log_success "OpenRC service copsec-controller is ACTIVE and running."
  else
    log_warn "OpenRC service copsec-controller status check returned non-zero. Recent log entries:"
    tail -n 10 /var/log/copsec/copsec-controller.log 2>/dev/null || true
  fi
elif [ "$ROLE" = "collector" ]; then
  if rc-service copsec-collector status >/dev/null 2>&1; then
    log_success "OpenRC service copsec-collector is ACTIVE and running."
  else
    log_warn "OpenRC service copsec-collector status check returned non-zero. Recent log entries:"
    tail -n 10 /var/log/copsec/copsec-collector.log 2>/dev/null || true
  fi
fi

SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || hostname -i 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"

echo ""
printf "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}\n"
printf "${CLR_GREEN}${CLR_BOLD} CoPSeC Pro Alpine Provisioning Complete! Node Role: %s${CLR_RESET}\n" "${ROLE}"
printf "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}\n"
if [ "$ROLE" = "standalone" ]; then
  printf "  • Web SOC Cockpit  : ${CLR_WHITE}http://%s:%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}"
  printf "  • Local Ingestion  : ${CLR_WHITE}127.0.0.1:%s (gRPC)${CLR_RESET}\n" "${GRPC_PORT}"
  printf "  • eBPF/XDP Device  : ${CLR_WHITE}%s (%s)${CLR_RESET}\n" "${INTERFACE}" "${XDP_MODE}"
  printf "  • SQLite Ledger    : ${CLR_WHITE}%s${CLR_RESET}\n" "${DB_PATH}"
  printf "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}%s${CLR_RESET}\n" "${API_KEY}"
  printf "  • Direct Login URL : ${CLR_CYAN}http://%s:%s/?token=%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}" "${API_KEY}"
  printf "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}\n"
  printf "  • Service Status   : ${CLR_CYAN}rc-service copsec-controller status && rc-service copsec-collector status${CLR_RESET}\n"
elif [ "$ROLE" = "cockpit-proxy" ] || [ "$ROLE" = "cockpit" ]; then
  printf "  • Analyst Cockpit  : ${CLR_WHITE}http://%s:%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}"
  printf "  • Remote Vault Hub : ${CLR_WHITE}%s${CLR_RESET}\n" "${CONTROLLER_ADDR}"
  printf "  • Storage Model    : ${CLR_WHITE}Zero-Storage Pure Analyst Mode${CLR_RESET}\n"
  printf "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}%s${CLR_RESET}\n" "${API_KEY}"
  printf "  • Direct Login URL : ${CLR_CYAN}http://%s:%s/?token=%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}" "${API_KEY}"
  printf "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}\n"
  printf "  • Service Status   : ${CLR_CYAN}rc-service copsec-cockpit status${CLR_RESET}\n"
elif [ "$ROLE" = "vault-server" ] || [ "$ROLE" = "vault" ]; then
  printf "  • Dedicated Vault  : ${CLR_WHITE}gRPC :%s / REST :%s${CLR_RESET}\n" "${GRPC_PORT}" "${WEB_PORT}"
  printf "  • SQLite Ledger    : ${CLR_WHITE}%s${CLR_RESET}\n" "${DB_PATH}"
  printf "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}%s${CLR_RESET}\n" "${API_KEY}"
  printf "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}\n"
  printf "  • Service Status   : ${CLR_CYAN}rc-service copsec-controller status${CLR_RESET}\n"
elif [ "$ROLE" = "controller" ]; then
  printf "  • Web SOC Cockpit  : ${CLR_WHITE}http://%s:%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}"
  printf "  • Fleet Ingestion  : ${CLR_WHITE}gRPC :%s${CLR_RESET}\n" "${GRPC_PORT}"
  printf "  • SQLite Ledger    : ${CLR_WHITE}%s${CLR_RESET}\n" "${DB_PATH}"
  printf "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}%s${CLR_RESET}\n" "${API_KEY}"
  printf "  • Direct Login URL : ${CLR_CYAN}http://%s:%s/?token=%s${CLR_RESET}\n" "${SERVER_IP}" "${WEB_PORT}" "${API_KEY}"
  printf "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}\n"
  printf "  • Service Status   : ${CLR_CYAN}rc-service copsec-controller status${CLR_RESET}\n"
else
  printf "  • Connected Hub    : ${CLR_WHITE}%s${CLR_RESET}\n" "${CONTROLLER_ADDR}"
  printf "  • eBPF Fast-Path   : ${CLR_WHITE}%s (%s)${CLR_RESET}\n" "${INTERFACE}" "${XDP_MODE}"
  printf "  • Gossip Mesh Port : ${CLR_WHITE}:%s${CLR_RESET}\n" "${GOSSIP_PORT}"
  printf "  • Service Status   : ${CLR_CYAN}rc-service copsec-collector status${CLR_RESET}\n"
fi
printf "  • Terminal Support : ${CLR_CYAN}copsec help${CLR_RESET} or ${CLR_CYAN}copsec status${CLR_RESET}\n"
printf "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}\n"
exit 0
