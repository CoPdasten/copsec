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
log_success() { echo -e "${CLR_GREEN}${CLR_BOLD}[[OK] SUCCESS]${CLR_RESET} $1"; }
log_warn()    { echo -e "${CLR_YELLOW}[[WARN] WARN]${CLR_RESET} $1"; }
log_error()   { echo -e "${CLR_RED}${CLR_BOLD}[[FAIL] FATAL]${CLR_RESET} $1" >&2; }
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
  --api-key=<key>               Master API key for Web SOC authentication (Default: auto-generated/persisted)
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
API_KEY="${COPSEC_API_KEY:-}"
GOSSIP_PORT="7946"
GOSSIP_JOIN=""
BAN_REAPER_INTERVAL="15s"
WHITELIST_YAML="/etc/copsec/whitelist.yaml"
MIRROR_SOCK="/run/copsec/mirror.sock"

# Parse CLI arguments (supporting both --flag=value and --flag value)
while [[ $# -gt 0 ]]; do
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
  --api-key=<key>               Master API key for Web SOC authentication (Default: auto-generated/persisted)
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

# Resolve Master API Key
if [[ -z "$API_KEY" ]]; then
  if [[ -f "/etc/copsec/api_key" ]]; then
    API_KEY="$(cat /etc/copsec/api_key 2>/dev/null | tr -d ' \r\n' || true)"
  elif [[ -f "/etc/copsec/copsec.env" ]]; then
    API_KEY="$(grep -E '^COPSEC_API_KEY=' /etc/copsec/copsec.env 2>/dev/null | cut -d'=' -f2- | tr -d ' "\x27\r\n' || true)"
  fi
fi
if [[ -z "$API_KEY" ]]; then
  API_KEY="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

# Detect Operating System & Init System
OS_FAMILY="linux"
INIT_SYSTEM="systemd"

if [[ -f /etc/alpine-release ]] || command -v apk &>/dev/null; then
  OS_FAMILY="alpine"
  INIT_SYSTEM="openrc"
elif command -v rc-service &>/dev/null || command -v rc-update &>/dev/null; then
  INIT_SYSTEM="openrc"
elif ! command -v systemctl &>/dev/null && [[ -d /etc/init.d ]]; then
  INIT_SYSTEM="openrc"
fi

log_info "Active Configuration Profile:"
log_metric "Assigned Node Role" "${ROLE}"
log_metric "Host OS / Init Engine" "${OS_FAMILY} (${INIT_SYSTEM})"
if [[ "$ROLE" != "collector" ]]; then
  log_metric "Master API Key" "${API_KEY:0:10}... (saved in /etc/copsec/api_key)"
fi
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

print_topology_diagram() {
  echo -e "\n${CLR_CYAN}${CLR_BOLD}--- Active Deployment Architecture Schema ---${CLR_RESET}"
  if [[ "$ROLE" == "standalone" ]]; then
    cat << 'TOPOLOGY_EOF'
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    TOPOLOGY 1: STANDALONE ALL-IN-ONE                    │
  │   [Attacker / Client] ───> [eth0 (eBPF/XDP Line-Rate Drop <10µs)]       │
  │                                      │ (Local Loopback)                 │
  │   ┌──────────────────────────────────┴───────────────────────────────┐  │
  │   │  copsec-collector (:2223 Tarpit, :8088 Honeypot, RAM RingBuffer) │  │
  │   │     └─> gRPC Telemetry Stream (127.0.0.1:50051)                  │  │
  │   │  copsec-controller (Otonom SOAR & 72 Kurallı Tehdit Motoru)      │  │
  │   │     ├─> Değişmez Kasa: /var/lib/copsec/vault.db                  │  │
  │   │     └─> Web SOC Kokpiti: http://127.0.0.1:8080                   │  │
  │   └──────────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────┘
TOPOLOGY_EOF
  elif [[ "$ROLE" == "controller" || "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
    cat << 'TOPOLOGY_EOF'
  ┌─────────────────────────────────────────────────────────────────────────┐
  │               TOPOLOGY 2/3: CENTRAL VAULT & CONTROLLER HUB              │
  │   [Edge Sensör 1] ───(gRPC :50051 mTLS)───> [BU DÜĞÜM (Controller)]   │
  │   [Edge Sensör 2] ───(gRPC :50051 mTLS)───> [BU DÜĞÜM (Controller)]   │
  │                                                      │                  │
  │   ┌──────────────────────────────────────────────────┴───────────────┐  │
  │   │  copsec-controller (:50051 Ingestion Hub & :8080 Web Kokpit)     │  │
  │   │  ├─ 72 Tespit Kuralı & Otonom SOAR Karar Motoru                  │  │
  │   │  ├─ Kriptografik SQLite WAL Kasası (SHA-256 Merkle Chain)        │  │
  │   │  ├─ SIEM Exporter (CEF / RFC 5424 -> Wazuh / Splunk / Elastic)   │  │
  │   │  └─ Minimalist Web SOC Arayüzü: http://<SERVER_IP>:8080          │  │
  │   └──────────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────┘
TOPOLOGY_EOF
  elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
    cat << 'TOPOLOGY_EOF'
  ┌─────────────────────────────────────────────────────────────────────────┐
  │              TOPOLOGY 3: ZERO-STORAGE ANALYST COCKPIT PROXY             │
  │   [SOC Analisti] ───> [Web Kokpiti :8080] ───> [Uzak Kasa Sunucusu]     │
  │   (Bu makinede hiçbir yerel veritabanı veya telemetri saklanmaz)         │
  └─────────────────────────────────────────────────────────────────────────┘
TOPOLOGY_EOF
  else
    cat << 'TOPOLOGY_EOF'
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                 TOPOLOGY 2/3: AUTONOMOUS EDGE SENSOR                    │
  │   [Gelen Ağ Trafiği] ───> [eth0 (eBPF/XDP Line-Rate Drop <10µs)]       │
  │                                     │                                   │
  │   ┌─────────────────────────────────┴────────────────────────────────┐  │
  │   │  copsec-collector (Bu Düğüm)                                     │  │
  │   │  ├─ TCP Tarpit (:2223) & Shadow Honeypot (:8088)                 │  │
  │   │  ├─ RAM İçi 30s Uçucu PCAP Halka Tamponu                         │  │
  │   │  ├─ [FASTPATH] Dedikodu Ağı (:7946 Gossip) <──> Komşu Sensörler          │  │
  │   │  └─ Çift Yönlü Telemetri Akışı ──(gRPC :50051)─> Controller      │  │
  │   └──────────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────┘
TOPOLOGY_EOF
  fi
  echo -e "${CLR_CYAN}---------------------------------------------${CLR_RESET}\n"
}

print_topology_diagram

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
elif command -v apk &>/dev/null; then
  log_info "Alpine Linux detected (apk package manager)..."
  apk update
  apk add --no-cache clang llvm libbpf-dev linux-headers elfutils-dev make gcc musl-dev iproute2 iptables openssl git curl bash sqlite
  if ! command -v go &>/dev/null; then
    apk add --no-cache go
  fi
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
log_step "Step 2: Configuring Production Directory Hierarchy & bpffs"
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

# Ensure eBPF bpffs virtual filesystem is mounted
mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  log_info "Mounting bpffs at /sys/fs/bpf..."
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi
if [[ "$INIT_SYSTEM" == "openrc" ]] && ! grep -q "bpf /sys/fs/bpf" /etc/fstab 2>/dev/null; then
  log_info "Persisting bpffs in /etc/fstab for OpenRC..."
  echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
fi

# Persist Master API Key & Controller URL for CLI tools
echo "$API_KEY" > "${CONF_DIR}/api_key"
chmod 644 "${CONF_DIR}/api_key"

local_ctrl_url="http://127.0.0.1:${WEB_PORT:-8080}"
if [[ "$ROLE" == "collector" && -n "$CONTROLLER_IP" ]]; then
  local_ctrl_url="http://${CONTROLLER_IP}:${WEB_PORT:-8080}"
fi
echo "$local_ctrl_url" > "${CONF_DIR}/controller_url"
chmod 644 "${CONF_DIR}/controller_url"

cat << ENV_EOF > "${CONF_DIR}/copsec.env"
COPSEC_API_KEY="${API_KEY}"
COPSEC_CONTROLLER_URL="${local_ctrl_url}"
COPSEC_CONTROLLER_ENDPOINT="${local_ctrl_url}"
ENV_EOF
chmod 600 "${CONF_DIR}/copsec.env"

log_success "Directory hierarchy and credentials ready at /opt/copsec, /etc/copsec, /var/lib/copsec, /var/log/copsec."

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
if command -v rc-service &>/dev/null; then
  rc-service copsec-controller stop 2>/dev/null || true
  rc-service copsec-collector stop 2>/dev/null || true
  rc-service copsec-cockpit stop 2>/dev/null || true
fi
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
if [[ -d "./collector" && -d "./controller" ]]; then
  SRC_ROOT="$(pwd)"
elif [[ -n "${BASH_SOURCE[0]:-}" && -d "$(dirname "${BASH_SOURCE[0]}")/../collector" && -d "$(dirname "${BASH_SOURCE[0]}")/../controller" ]]; then
  SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
elif [[ -d "../collector" && -d "../controller" ]]; then
  SRC_ROOT="$(cd .. && pwd)"
elif [[ -d "/tmp/copsec/collector" && -d "/tmp/copsec/controller" ]]; then
  SRC_ROOT="/tmp/copsec"
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
    log_info "Compiling ${bin_name} from source (${SRC_ROOT}/${src_subdir}) with static CGO_ENABLED=0..."
    export CGO_ENABLED=0
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

# Always install unified copsec CLI utility
install_binary "copsec" "cmd/copsec"
ln -sf "/usr/local/bin/copsec" "/usr/bin/copsec" 2>/dev/null || true

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

create_openrc_service() {
  local svc_name="$1"
  local svc_desc="$2"
  local svc_bin="$3"
  local svc_args="$4"

  cat << OPENRC_EOF > "/etc/init.d/${svc_name}"
#!/sbin/openrc-run

name="${svc_name}"
description="${svc_desc}"

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

if [[ "$ROLE" == "controller" || "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
  init_sqlite_ledger "$DB_PATH"

  if [[ "$INIT_SYSTEM" == "openrc" ]]; then
    create_openrc_service "copsec-controller" \
      "CoPSeC Tier 2 Primary Vault & Security Controller" \
      "${BIN_DIR}/copsec-controller" \
      "--db-path=${DB_PATH} --grpc-port=${GRPC_PORT} --port=${WEB_PORT} --api-key=${API_KEY} --allow-external-bind=true"

    rc-update add copsec-controller default
    rc-service copsec-controller restart 2>/dev/null || rc-service copsec-controller start
    if [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
      ln -sf /etc/init.d/copsec-controller /etc/init.d/copsec-vault
    fi
    log_success "Registered and started OpenRC copsec-controller service."
  else
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
EnvironmentFile=-/etc/copsec/copsec.env
Environment="COPSEC_API_KEY=${API_KEY}"
ExecStart=${BIN_DIR}/copsec-controller \
  --db-path=${DB_PATH} \
  --grpc-port=${GRPC_PORT} \
  --port=${WEB_PORT} \
  --api-key=${API_KEY} \
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
  fi

elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  if [[ "$INIT_SYSTEM" == "openrc" ]]; then
    create_openrc_service "copsec-cockpit" \
      "CoPSeC Tier 3 Central SOC Cockpit Analyst Proxy" \
      "${BIN_DIR}/copsec-cockpit" \
      "--remote-vault=${CONTROLLER_ADDR} --web-port=${WEB_PORT} --allow-external-bind=true"

    rc-update add copsec-cockpit default
    rc-service copsec-cockpit restart 2>/dev/null || rc-service copsec-cockpit start
    log_success "Registered and started OpenRC copsec-cockpit service."
  else
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
  fi

elif [[ "$ROLE" == "collector" ]]; then
  provision_collector_configs

  GOSSIP_ARGS="--gossip-port=${GOSSIP_PORT}"
  if [[ -n "$GOSSIP_JOIN" ]]; then
    GOSSIP_ARGS="${GOSSIP_ARGS} --gossip-join=${GOSSIP_JOIN}"
  fi

  COLL_ARGS="--controller=${CONTROLLER_ADDR} --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --node-identity=${NODE_ID_FILE} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK} --enable-tarpit=true --enable-syn-proxy=true ${GOSSIP_ARGS}"

  if [[ "$INIT_SYSTEM" == "openrc" ]]; then
    create_openrc_service "copsec-collector" \
      "CoPSeC Tier 1 Edge Sensor & L7 DPI Collector" \
      "${BIN_DIR}/copsec-collector" \
      "${COLL_ARGS}"

    rc-update add copsec-collector default
    rc-service copsec-collector restart 2>/dev/null || rc-service copsec-collector start
    log_success "Registered and started OpenRC copsec-collector service on ${INTERFACE}."
  else
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
  fi

elif [[ "$ROLE" == "standalone" ]]; then
  init_sqlite_ledger "$DB_PATH"
  provision_collector_configs

  STANDALONE_COLL_ARGS="--controller=127.0.0.1:${GRPC_PORT} --interface=${INTERFACE} --xdp-mode=${XDP_MODE} --whitelist-yaml=${WHITELIST_YAML} --node-identity=${NODE_ID_FILE} --ban-reaper-interval=${BAN_REAPER_INTERVAL} --mirror-sock=${MIRROR_SOCK} --enable-tarpit=true --enable-syn-proxy=true"

  if [[ "$INIT_SYSTEM" == "openrc" ]]; then
    create_openrc_service "copsec-controller" \
      "CoPSeC Standalone Vault & Security Controller" \
      "${BIN_DIR}/copsec-controller" \
      "--db-path=${DB_PATH} --grpc-port=${GRPC_PORT} --port=${WEB_PORT} --api-key=${API_KEY} --allow-external-bind=true"

    create_openrc_service "copsec-collector" \
      "CoPSeC Standalone Edge Sensor & L7 DPI Collector" \
      "${BIN_DIR}/copsec-collector" \
      "${STANDALONE_COLL_ARGS}"

    rc-update add copsec-controller default
    rc-update add copsec-collector default
    rc-service copsec-controller restart 2>/dev/null || rc-service copsec-controller start
    rc-service copsec-collector restart 2>/dev/null || rc-service copsec-collector start
    log_success "Registered and started standalone OpenRC copsec-controller and copsec-collector services on ${INTERFACE}."
  else
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
EnvironmentFile=-/etc/copsec/copsec.env
Environment="COPSEC_API_KEY=${API_KEY}"
ExecStart=${BIN_DIR}/copsec-controller \
  --db-path=${DB_PATH} \
  --grpc-port=${GRPC_PORT} \
  --port=${WEB_PORT} \
  --api-key=${API_KEY} \
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

check_service_health() {
  local svc="$1"
  if [[ "$INIT_SYSTEM" == "openrc" ]]; then
    if rc-service "$svc" status >/dev/null 2>&1; then
      log_success "OpenRC service ${svc} is ACTIVE and running."
    else
      log_warn "OpenRC service ${svc} status check returned non-zero. Recent log entries:"
      tail -n 10 "/var/log/copsec/${svc}.log" 2>/dev/null || true
    fi
  else
    if systemctl is-active --quiet "${svc}.service"; then
      log_success "Unit ${svc}.service is ACTIVE and running."
    else
      log_warn "Unit ${svc}.service status pending. Recent journal entries:"
      journalctl -u "${svc}.service" -n 10 --no-pager || true
    fi
  fi
}

if [[ "$ROLE" == "standalone" ]]; then
  check_service_health "copsec-controller"
  check_service_health "copsec-collector"
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  check_service_health "copsec-cockpit"
elif [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" || "$ROLE" == "controller" ]]; then
  check_service_health "copsec-controller"
elif [[ "$ROLE" == "collector" ]]; then
  check_service_health "copsec-collector"
fi

echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD} CoPSeC Pro Provisioning Complete! Node Role: ${ROLE}${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"

if [[ "$INIT_SYSTEM" == "openrc" ]]; then
  SVC_DISPLAY_STANDALONE="rc-service copsec-controller status && rc-service copsec-collector status"
  SVC_DISPLAY_COCKPIT="rc-service copsec-cockpit status"
  SVC_DISPLAY_CONTROLLER="rc-service copsec-controller status"
  SVC_DISPLAY_COLLECTOR="rc-service copsec-collector status"
else
  SVC_DISPLAY_STANDALONE="systemctl status copsec-controller copsec-collector"
  SVC_DISPLAY_COCKPIT="systemctl status copsec-cockpit"
  SVC_DISPLAY_CONTROLLER="systemctl status copsec-controller"
  SVC_DISPLAY_COLLECTOR="systemctl status copsec-collector"
fi

SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"

if [[ "$ROLE" == "standalone" ]]; then
  echo -e "  • Web SOC Cockpit  : ${CLR_WHITE}http://127.0.0.1:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Local Ingestion  : ${CLR_WHITE}127.0.0.1:${GRPC_PORT} (gRPC)${CLR_RESET}"
  echo -e "  • eBPF/XDP Device  : ${CLR_WHITE}${INTERFACE} (${XDP_MODE})${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}${API_KEY}${CLR_RESET}"
  echo -e "  • Direct Login URL : ${CLR_CYAN}http://127.0.0.1:${WEB_PORT}/?token=${API_KEY}${CLR_RESET}"
  echo -e "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}"
  echo -e "  • Service Status   : ${CLR_CYAN}${SVC_DISPLAY_STANDALONE}${CLR_RESET}"
elif [[ "$ROLE" == "cockpit-proxy" || "$ROLE" == "cockpit" ]]; then
  echo -e "  • Analyst Cockpit  : ${CLR_WHITE}http://${SERVER_IP}:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Remote Vault Hub : ${CLR_WHITE}${CONTROLLER_ADDR}${CLR_RESET}"
  echo -e "  • Storage Model    : ${CLR_WHITE}Zero-Storage Pure Analyst Mode${CLR_RESET}"
  echo -e "  • Service Status   : ${CLR_CYAN}${SVC_DISPLAY_COCKPIT}${CLR_RESET}"
elif [[ "$ROLE" == "vault-server" || "$ROLE" == "vault" ]]; then
  echo -e "  • Dedicated Vault  : ${CLR_WHITE}gRPC :${GRPC_PORT} / REST :${WEB_PORT}${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}${API_KEY}${CLR_RESET}"
  echo -e "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}"
  echo -e "  • Service Status   : ${CLR_CYAN}${SVC_DISPLAY_CONTROLLER}${CLR_RESET}"
elif [[ "$ROLE" == "controller" ]]; then
  echo -e "  • Web SOC Cockpit  : ${CLR_WHITE}http://${SERVER_IP}:${WEB_PORT}${CLR_RESET}"
  echo -e "  • Fleet Ingestion  : ${CLR_WHITE}gRPC :${GRPC_PORT}${CLR_RESET}"
  echo -e "  • SQLite Ledger    : ${CLR_WHITE}${DB_PATH}${CLR_RESET}"
  echo -e "  • Master API Key   : ${CLR_YELLOW}${CLR_BOLD}${API_KEY}${CLR_RESET}"
  echo -e "  • Direct Login URL : ${CLR_CYAN}http://${SERVER_IP}:${WEB_PORT}/?token=${API_KEY}${CLR_RESET}"
  echo -e "  • Credential File  : ${CLR_WHITE}/etc/copsec/api_key${CLR_RESET}"
  echo -e "  • Service Status   : ${CLR_CYAN}${SVC_DISPLAY_CONTROLLER}${CLR_RESET}"
else
  echo -e "  • Connected Hub    : ${CLR_WHITE}${CONTROLLER_ADDR}${CLR_RESET}"
  echo -e "  • eBPF Fast-Path   : ${CLR_WHITE}${INTERFACE} (${XDP_MODE})${CLR_RESET}"
  echo -e "  • Gossip Mesh Port : ${CLR_WHITE}:${GOSSIP_PORT}${CLR_RESET}"
  echo -e "  • Service Status   : ${CLR_CYAN}${SVC_DISPLAY_COLLECTOR}${CLR_RESET}"
fi
echo -e "  • Terminal Support : ${CLR_CYAN}copsec help${CLR_RESET} or ${CLR_CYAN}copsec status${CLR_RESET}"
echo -e "  • Topology Guide   : ${CLR_CYAN}https://github.com/CoPdasten/copsec/blob/main/docs/DEPLOYMENT_TOPOLOGIES.md${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
exit 0
