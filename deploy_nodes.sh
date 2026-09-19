#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC Enterprise - 4-Node Distributed Cluster Orchestration & Deployment
#  Target: Controller (192.168.1.11), Pardus Edge (192.168.1.13), Fedora Edge (192.168.1.10)
# ==============================================================================
#  Security Profile:
#   - Idempotent execution (safe to re-run multiple times)
#   - Strict bash error handling (set -euo pipefail)
#   - OS detection: Debian/Pardus (apt) vs. Fedora/RHEL (dnf)
#   - Host firewall automation: firewalld / nftables / iptables
#   - eBPF/XDP Native driver attachment with automated fallback
#   - Hardened directory permissions (0700) and env files (0600)
#   - Management gRPC (:50052) bound strictly to loopback (127.0.0.1)
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
CLR_GRAY="\033[0;90m"
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
 Distributed Node Deployment & eBPF Driver Orchestration
EOF
  echo -e "${CLR_RESET}"
}

log_step()    { echo -e "\n${CLR_MAGENTA}${CLR_BOLD}[STEP] $1${CLR_RESET}"; }
log_info()    { echo -e "${CLR_BLUE}[INFO]${CLR_RESET} $1"; }
log_success() { echo -e "${CLR_GREEN}${CLR_BOLD}[SUCCESS]${CLR_RESET} $1"; }
log_warn()    { echo -e "${CLR_YELLOW}[WARN]${CLR_RESET} $1"; }
log_error()   { echo -e "${CLR_RED}${CLR_BOLD}[ERROR]${CLR_RESET} $1" >&2; }
log_metric()  { printf "${CLR_GRAY}  ├─ %-35s :${CLR_RESET} ${CLR_WHITE}%s${CLR_RESET}\n" "$1" "$2"; }

# --- 1. Fast Help Check ---
for arg in "$@"; do
  if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
    cat << EOF
Usage: sudo bash $(basename "$0") [OPTIONS]

Options:
  --role <controller|sensor>    Explicitly set node role (auto-detected if omitted)
  --controller-ip <IP>          Target Controller IP (default: 192.168.1.11)
  --interface <IFACE>           Network interface for eBPF/XDP (auto-detected if omitted)
  --xdp-mode <native|generic>   eBPF driver mode (default: native)
  --fleet-key <KEY>             Shared fleet enrollment secret (or set COPSEC_FLEET_KEY)
  --api-key <KEY>               Master API key for Web SOC (or set COPSEC_API_KEY)
  --mgmt-secret <SECRET>        Bearer secret for management gRPC (or set COPSEC_MGMT_KEY)
  --gossip-join <HOST:PORT>     Initial gossip peer address for mesh join
  --help, -h                    Show this help message and exit

Lab Topology Defaults:
  192.168.1.11 -> Role: controller
  192.168.1.13 -> Role: sensor (Primary Pardus Edge)
  192.168.1.10 -> Role: sensor (Secondary Fedora Edge)
EOF
    exit 0
  fi
done

# --- 2. Root Enforcement ---
if [[ "$EUID" -ne 0 ]]; then
  log_error "This deployment script must be executed as root (sudo)."
  exit 1
fi

# --- 2. Configuration & Parameter Defaults ---
NODE_ROLE=""
CONTROLLER_IP="${CONTROLLER_IP:-192.168.1.11}"
CONTROLLER_GRPC_PORT=50051
CONTROLLER_WEB_PORT=8080
GOSSIP_PORT=7946
TARPIT_PORT=2223
MGMT_PORT=50052

PRIMARY_IFACE=""
XDP_MODE="${XDP_MODE:-native}"
FLEET_KEY="${COPSEC_FLEET_KEY:-CoPSeC-Cluster-Fleet-Key-2026!}"
API_KEY="${COPSEC_API_KEY:-CoPSeC-Master-API-Key-2026!}"
MGMT_SECRET="${COPSEC_MGMT_KEY:-CoPSeC-Mgmt-Token-2026!}"
GOSSIP_JOIN=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COPSEC_HOME="/etc/copsec"
COPSEC_LIB="/var/lib/copsec"
COPSEC_LOG="/var/log/copsec"
COPSEC_SHARE="/usr/local/share/copsec"
ENV_FILE="${COPSEC_HOME}/copsec.env"

show_help() {
  cat << EOF
Usage: sudo bash $(basename "$0") [OPTIONS]

Options:
  --role <controller|sensor>    Explicitly set node role (auto-detected if omitted)
  --controller-ip <IP>          Target Controller IP (default: 192.168.1.11)
  --interface <IFACE>           Network interface for eBPF/XDP (auto-detected if omitted)
  --xdp-mode <native|generic>   eBPF driver mode (default: native)
  --fleet-key <KEY>             Shared fleet enrollment secret (or set COPSEC_FLEET_KEY)
  --api-key <KEY>               Master API key for Web SOC (or set COPSEC_API_KEY)
  --mgmt-secret <SECRET>        Bearer secret for management gRPC (or set COPSEC_MGMT_KEY)
  --gossip-join <HOST:PORT>     Initial gossip peer address for mesh join
  --help, -h                    Show this help message and exit

Lab Topology Defaults:
  192.168.1.11 -> Role: controller
  192.168.1.13 -> Role: sensor (Primary Pardus Edge)
  192.168.1.10 -> Role: sensor (Secondary Fedora Edge)
EOF
  exit 0
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      NODE_ROLE="$2"
      shift 2
      ;;
    --controller-ip)
      CONTROLLER_IP="$2"
      shift 2
      ;;
    --interface)
      PRIMARY_IFACE="$2"
      shift 2
      ;;
    --xdp-mode)
      XDP_MODE="$2"
      shift 2
      ;;
    --fleet-key)
      FLEET_KEY="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --mgmt-secret)
      MGMT_SECRET="$2"
      shift 2
      ;;
    --gossip-join)
      GOSSIP_JOIN="$2"
      shift 2
      ;;
    --help|-h)
      show_help
      ;;
    *)
      log_warn "Unknown parameter: $1"
      shift
      ;;
  esac
done

log_banner

# --- 3. Host OS & Interface Discovery ---
log_step "Detecting Host Operating System & Primary Network Interface"

OS_FAMILY=""
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  source /etc/os-release
  case "${ID:-}" in
    debian|pardus|ubuntu|kali|linuxmint)
      OS_FAMILY="debian"
      ;;
    fedora|rhel|centos|rocky|almalinux)
      OS_FAMILY="fedora"
      ;;
    *)
      if [[ "${ID_LIKE:-}" =~ (debian|ubuntu) ]]; then
        OS_FAMILY="debian"
      elif [[ "${ID_LIKE:-}" =~ (rhel|fedora|centos) ]]; then
        OS_FAMILY="fedora"
      else
        OS_FAMILY="unknown"
      fi
      ;;
  esac
  log_metric "Operating System ID" "${PRETTY_NAME:-$ID}"
else
  log_error "Unable to identify OS from /etc/os-release"
  exit 1
fi
log_metric "OS Family Detected" "$OS_FAMILY"

# Auto-detect IP address & Primary Network Interface
HOST_IPS=()
while IFS= read -r ip_entry; do
  [[ -n "$ip_entry" ]] && HOST_IPS+=("$ip_entry")
done < <(ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d'/' -f1)

log_metric "Detected Local IPv4" "${HOST_IPS[*]:-None}"

# Resolve primary network interface via default route
if [[ -z "$PRIMARY_IFACE" ]]; then
  PRIMARY_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  if [[ -z "$PRIMARY_IFACE" ]]; then
    # Fallback to first non-loopback UP interface
    PRIMARY_IFACE="$(ip link show up | awk -F: '$0 !~ "lo|virbr|docker" && /^[0-9]+: / {print $2; exit}' | tr -d ' ' || true)"
  fi
fi

if [[ -z "$PRIMARY_IFACE" ]]; then
  log_error "Failed to resolve active network interface. Please specify with --interface <name>."
  exit 1
fi
log_metric "Target Network Interface" "$PRIMARY_IFACE"

# Auto-detect Role if not explicitly provided
if [[ -z "$NODE_ROLE" ]]; then
  for ip in "${HOST_IPS[@]}"; do
    if [[ "$ip" == "192.168.1.11" ]]; then
      NODE_ROLE="controller"
      break
    elif [[ "$ip" == "192.168.1.13" || "$ip" == "192.168.1.10" ]]; then
      NODE_ROLE="sensor"
      break
    fi
  done
  if [[ -z "$NODE_ROLE" ]]; then
    # Default to sensor if still unresolved
    NODE_ROLE="sensor"
    log_warn "Node IP did not match default topology; defaulting role to 'sensor'."
  fi
fi
log_metric "Assigned Node Role" "${NODE_ROLE^^}"

# If sensor on 192.168.1.10 (Fedora) and no gossip join specified, default join to 192.168.1.13:7946
if [[ "$NODE_ROLE" == "sensor" && -z "$GOSSIP_JOIN" ]]; then
  for ip in "${HOST_IPS[@]}"; do
    if [[ "$ip" == "192.168.1.10" ]]; then
      GOSSIP_JOIN="192.168.1.13:7946"
      log_metric "Gossip Mesh Peer" "$GOSSIP_JOIN"
      break
    fi
  done
fi

# --- 4. Package Installation & Toolchain Provisioning ---
log_step "Installing Build Toolchain, Kernel Headers & Dependencies"

case "$OS_FAMILY" in
  debian)
    log_info "Configuring Debian / Pardus package toolchain..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      llvm \
      libbpf-dev \
      libpcap-dev \
      libelf-dev \
      pkg-config \
      git \
      make \
      curl \
      iproute2 \
      ethtool \
      ca-certificates
    
    # Install kernel headers with graceful fallbacks
    apt-get install -y --no-install-recommends linux-headers-"$(uname -r)" 2>/dev/null || \
      apt-get install -y --no-install-recommends linux-headers-amd64 2>/dev/null || \
      log_warn "Kernel headers package not found in repos; proceeding with system headers."

    # Check if Go compiler is installed and available
    if ! command -v go &>/dev/null; then
      log_info "Go binary not found; installing golang package..."
      apt-get install -y golang-go || true
    fi
    ;;
  
  fedora)
    log_info "Configuring Fedora / RHEL package toolchain..."
    dnf install -y \
      clang \
      llvm \
      libbpf-devel \
      kernel-headers \
      libpcap-devel \
      elfutils-libelf-devel \
      gcc \
      gcc-c++ \
      make \
      git \
      curl \
      iproute \
      ethtool \
      ca-certificates
    
    dnf install -y kernel-devel-"$(uname -r)" 2>/dev/null || \
      dnf install -y kernel-devel 2>/dev/null || \
      log_warn "kernel-devel package not found; proceeding with system headers."

    if ! command -v go &>/dev/null; then
      log_info "Go binary not found; installing golang..."
      dnf install -y golang || true
    fi
    ;;

  *)
    log_warn "Unknown OS family ($OS_FAMILY). Attempting to proceed assuming toolchain is present..."
    ;;
esac

if ! command -v clang &>/dev/null; then
  log_error "Clang compiler is required for eBPF bytecode generation. Please install clang."
  exit 1
fi

if ! command -v go &>/dev/null; then
  log_error "Go compiler is required to build CoPSeC binaries. Please install Go 1.21+."
  exit 1
fi
log_success "Compiler toolchain verified (Clang: $(clang --version | head -n1), Go: $(go version))"

# --- 5. Host Firewall Automation ---
log_step "Configuring Host Firewall (Allowing CoPSeC Services)"

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
  log_info "Active firewalld detected (Fedora/RHEL). Applying persistent firewall rules..."
  if [[ "$NODE_ROLE" == "controller" ]]; then
    firewall-cmd --permanent --add-port=${CONTROLLER_GRPC_PORT}/tcp
    firewall-cmd --permanent --add-port=${CONTROLLER_WEB_PORT}/tcp
  else
    firewall-cmd --permanent --add-port=${GOSSIP_PORT}/tcp
    firewall-cmd --permanent --add-port=${GOSSIP_PORT}/udp
    firewall-cmd --permanent --add-port=${TARPIT_PORT}/tcp
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
  fi
  firewall-cmd --reload
  log_success "firewalld rules applied successfully."

elif command -v iptables &>/dev/null; then
  log_info "Configuring iptables / nftables filtering rules..."
  if [[ "$NODE_ROLE" == "controller" ]]; then
    iptables -C INPUT -p tcp --dport ${CONTROLLER_GRPC_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport ${CONTROLLER_GRPC_PORT} -j ACCEPT
    iptables -C INPUT -p tcp --dport ${CONTROLLER_WEB_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport ${CONTROLLER_WEB_PORT} -j ACCEPT
  else
    iptables -C INPUT -p tcp --dport ${GOSSIP_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport ${GOSSIP_PORT} -j ACCEPT
    iptables -C INPUT -p udp --dport ${GOSSIP_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p udp --dport ${GOSSIP_PORT} -j ACCEPT
    iptables -C INPUT -p tcp --dport ${TARPIT_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport ${TARPIT_PORT} -j ACCEPT
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport 80 -j ACCEPT
  fi
  log_success "iptables packet acceptance rules inserted."
fi

# --- 6. Kernel & Network Stack Optimization ---
log_step "Tuning Linux Kernel Subsystems for eBPF/XDP High Throughput"

sysctl -w net.core.bpf_jit_enable=1 >/dev/null
sysctl -w net.core.bpf_jit_harden=0 >/dev/null 2>&1 || true
sysctl -w net.core.rmem_max=67108864 >/dev/null
sysctl -w net.core.wmem_max=67108864 >/dev/null
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
sysctl -w net.core.netdev_max_backlog=100000 >/dev/null 2>&1 || true

# Maximize locked memory for eBPF maps
ulimit -l unlimited 2>/dev/null || true
log_success "Kernel parameters optimized (BPF JIT enabled, rmem/wmem expanded, memlock raised)."

# --- 7. Compilation of eBPF Bytecode & Binaries ---
log_step "Compiling eBPF Kernel Targets & Go Executables"

cd "$SCRIPT_DIR"

# Ensure multiarch asm headers are accessible for eBPF toolchains
if [[ ! -e /usr/include/asm && -d /usr/include/"$(uname -m)"-linux-gnu/asm ]]; then
  ln -sf /usr/include/"$(uname -m)"-linux-gnu/asm /usr/include/asm 2>/dev/null || true
fi

log_info "Building eBPF C bytecode (make bpf)..."
make bpf

log_info "Building Go binaries (make all)..."
make all

# Staging directories
mkdir -p "$COPSEC_HOME" "$COPSEC_LIB" "$COPSEC_LOG" "${COPSEC_SHARE}/bpf"
chmod 755 "$COPSEC_HOME"
chmod 700 "$COPSEC_LIB" "$COPSEC_LOG"

# Install binaries
cp -f bin/copsec-controller /usr/local/bin/ 2>/dev/null || true
cp -f bin/copsec-collector /usr/local/bin/ 2>/dev/null || true
cp -f bin/copsec /usr/local/bin/ 2>/dev/null || true
chmod 755 /usr/local/bin/copsec*
ln -sf /usr/local/bin/copsec /usr/bin/copsec 2>/dev/null || true

# Install eBPF bytecode objects
cp -f bpf/*.o "${COPSEC_SHARE}/bpf/"
chmod 644 "${COPSEC_SHARE}/bpf/"*.o

# Install rules/config if available
if [[ -d "${SCRIPT_DIR}/config" ]]; then
  cp -rf "${SCRIPT_DIR}/config"/* "$COPSEC_HOME/" 2>/dev/null || true
fi
if [[ -d "${SCRIPT_DIR}/rules" ]]; then
  cp -rf "${SCRIPT_DIR}/rules" "$COPSEC_HOME/" 2>/dev/null || true
fi

log_success "Binaries and bytecode installed to /usr/local/bin, /usr/bin, and ${COPSEC_SHARE}/bpf"

# --- 8. Environment File & Credential Hardening ---
log_step "Generating Hardened Environment & Credentials (/etc/copsec/copsec.env)"

cat > "$ENV_FILE" << EOF
# CoPSeC Enterprise Cluster Runtime Configuration
# Permissions: 0600 (Strictly owned by root)
COPSEC_FLEET_KEY="${FLEET_KEY}"
COPSEC_API_KEY="${API_KEY}"
COPSEC_MGMT_KEY="${MGMT_SECRET}"
COPSEC_CONTROLLER_ENDPOINT="${CONTROLLER_IP}:${CONTROLLER_GRPC_PORT}"
COPSEC_INTERFACE="${PRIMARY_IFACE}"
COPSEC_XDP_MODE="${XDP_MODE}"
EOF

chmod 600 "$ENV_FILE"
echo "${API_KEY}" > "${COPSEC_HOME}/api_key"
chmod 644 "${COPSEC_HOME}/api_key"
echo "http://${CONTROLLER_IP}:8080" > "${COPSEC_HOME}/controller_url"
chmod 644 "${COPSEC_HOME}/controller_url"
log_success "Environment file (0600), CLI api_key (0644), and controller_url (0644) written successfully."

# --- 9. Systemd Service Deployment & Service Activation ---
log_step "Configuring and Starting Background Systemd Service"

if [[ "$NODE_ROLE" == "controller" ]]; then
  SERVICE_FILE="/etc/systemd/system/copsec-controller.service"
  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CoPSeC Central Controller & Cryptographic Vault Hub
Documentation=https://github.com/CoPdasten/copsec
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/local/bin/copsec-controller \\
  --grpc-addr 0.0.0.0:${CONTROLLER_GRPC_PORT} \\
  --web-addr 0.0.0.0:${CONTROLLER_WEB_PORT} \\
  --allow-external-bind \\
  --db ${COPSEC_LIB}/vault.db \\
  --auto-ban \\
  --auto-ban-threshold 80
Restart=always
RestartSec=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

  log_info "Enabling and launching copsec-controller.service..."
  systemctl daemon-reload
  systemctl enable --now copsec-controller.service
  systemctl restart copsec-controller.service
  
  sleep 2
  if systemctl is-active --quiet copsec-controller.service; then
    log_success "copsec-controller.service is active and running."
    log_metric "Controller gRPC Port" "0.0.0.0:${CONTROLLER_GRPC_PORT}"
    log_metric "Web SOC Dashboard" "http://${HOST_IPS[0]:-127.0.0.1}:${CONTROLLER_WEB_PORT}"
    log_metric "SQLite Vault DB" "${COPSEC_LIB}/vault.db"
  else
    log_error "copsec-controller.service failed to start. Check: journalctl -u copsec-controller -n 20"
  fi

else
  # Role: sensor
  SERVICE_FILE="/etc/systemd/system/copsec-collector.service"
  GOSSIP_ARG=""
  if [[ -n "$GOSSIP_JOIN" ]]; then
    GOSSIP_ARG="--gossip-join ${GOSSIP_JOIN}"
  fi

  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CoPSeC Edge Sensor & Native eBPF/XDP Defense Daemon
Documentation=https://github.com/CoPdasten/copsec
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/local/bin/copsec-collector \\
  --interface ${PRIMARY_IFACE} \\
  --xdp-mode ${XDP_MODE} \\
  --controller ${CONTROLLER_IP}:${CONTROLLER_GRPC_PORT} \\
  --gossip-port ${GOSSIP_PORT} \\
  ${GOSSIP_ARG} \\
  --mgmt-listen 127.0.0.1:${MGMT_PORT} \\
  --enable-tarpit \\
  --enable-syn-proxy \\
  --buffer-db ${COPSEC_LIB}/buffer.db
Restart=always
RestartSec=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

  log_info "Enabling and launching copsec-collector.service..."
  systemctl daemon-reload
  systemctl enable --now copsec-collector.service
  systemctl restart copsec-collector.service

  sleep 2
  if systemctl is-active --quiet copsec-collector.service; then
    log_success "copsec-collector.service is active and running."
    log_metric "Protected Interface" "${PRIMARY_IFACE} (mode: ${XDP_MODE})"
    log_metric "Controller Target" "${CONTROLLER_IP}:${CONTROLLER_GRPC_PORT}"
    log_metric "Gossip Mesh Port" "0.0.0.0:${GOSSIP_PORT}"
    log_metric "Zero-Window Tarpit" "Port :${TARPIT_PORT} (Active)"
    log_metric "Management gRPC" "127.0.0.1:${MGMT_PORT} (Loopback Hardened)"
  else
    log_warn "copsec-collector.service did not immediately report active. Checking status..."
    systemctl status copsec-collector.service --no-pager || true
  fi
fi

# --- 10. Final Verification & Summary ---
log_step "Deployment Complete"
echo -e "${CLR_GREEN}${CLR_BOLD}CoPSeC node deployment finished successfully for role: ${NODE_ROLE^^}${CLR_RESET}\n"
