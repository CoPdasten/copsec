#!/usr/bin/env bash
# ==============================================================================
#  CoPSeC Enterprise Edge Collector - Hardened Production Deployment Pipeline
#  Filename: deploy.sh
# ==============================================================================
#  Security Profile:
#   - Strict Error Trapping: set -euo pipefail (Zero Silent Error Swallowing)
#   - Hardened Endpoint Resolution: Strict CLI > ENV > Interactive Validation
#   - Automated Mutual TLS (mTLS): Root CA & Node-Specific X.509 Provisioning
#   - Principle of Least Privilege: Restricted File Permissions (chmod 600/700)
# ==============================================================================

set -euo pipefail

# --- ANSI Terminal Color Formatting ---
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"
CLR_YELLOW="\033[1;33m"
CLR_MAGENTA="\033[1;35m"
CLR_BLUE="\033[1;34m"
CLR_GRAY="\033[0;90m"

log_banner() {
  echo -e "${CLR_CYAN}"
  cat << 'ASCII_BANNER'
  ██████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║     ██║   ██║██████╔╝███████╗█████╗  ██║     
 ██║     ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║     
 ╚██████╗╚██████╔╝██║     ███████║███████╗╚██████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝
 Enterprise Hardened Collector & Zero-Trust Sensor Provisioning
ASCII_BANNER
  echo -e "${CLR_RESET}"
}

log_step() {
  echo -e "\n${CLR_MAGENTA}${CLR_BOLD}[STEP] $1${CLR_RESET}"
}

log_info() {
  echo -e "${CLR_BLUE}[INFO]${CLR_RESET} $1"
}

log_success() {
  echo -e "${CLR_GREEN}[✓ SUCCESS]${CLR_RESET} $1"
}

log_warn() {
  echo -e "${CLR_YELLOW}[⚠️  WARNING]${CLR_RESET} $1"
}

log_error() {
  echo -e "${CLR_RED}[✗ FATAL]${CLR_RESET} $1" >&2
}

# --- 1. Root Privilege Enforcement ---
if [[ "$EUID" -ne 0 ]]; then
  log_error "This provisioning script must be executed as root (sudo)."
  exit 1
fi

# --- 2. Configuration & Parameter Parsing ---
CONTROLLER_ADDR_CLI=""
NODE_GROUP="${NODE_GROUP:-DEFAULT_EDGE}"
NODE_ID_CLI=""
API_KEY_CLI=""
CA_CERT_SOURCE=""
CA_KEY_SOURCE=""
FORCE_REINSTALL=false

CONF_DIR="/etc/copsec"
CERTS_DIR="${CONF_DIR}/certs"
ENV_FILE="${CONF_DIR}/collector.env"
SYSTEMD_SERVICE="/etc/systemd/system/copsec-collector.service"

show_help() {
  cat << EOF
Usage: sudo bash $(basename "$0") [OPTIONS]

Options:
  --controller, -c <IP:PORT>  Central Controller gRPC endpoint (Strict syntax: IPv4:Port)
  --group, -g <GROUP>         Fleet cluster group (e.g. DMZ_INGRESS, PROD_APP, DB_TIER)
  --node-id, -n <ID>          Explicit unique node identifier (Default: auto from hostname)
  --api-key, -k <KEY>         Master API key for telemetry authentication
  --ca-cert <PATH>            Path to existing Root CA certificate (ingest mode)
  --ca-key <PATH>             Path to existing Root CA private key (ingest mode)
  --force, -f                 Force overwrite existing credentials and configurations
  --help, -h                  Display this help message and exit

Environment Variables:
  COPSEC_CONTROLLER_ENDPOINT  Central Controller gRPC endpoint (IPv4:Port)
  NODE_GROUP                  Cluster grouping tag
  NODE_ID                     Explicit Node identifier
  COPSEC_API_KEY              Master authentication key

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller|-c)
      CONTROLLER_ADDR_CLI="$2"; shift 2 ;;
    --group|-g)
      NODE_GROUP="$2"; shift 2 ;;
    --node-id|-n)
      NODE_ID_CLI="$2"; shift 2 ;;
    --api-key|-k)
      API_KEY_CLI="$2"; shift 2 ;;
    --ca-cert)
      CA_CERT_SOURCE="$2"; shift 2 ;;
    --ca-key)
      CA_KEY_SOURCE="$2"; shift 2 ;;
    --force|-f)
      FORCE_REINSTALL=true; shift ;;
    --help|-h)
      log_banner; show_help; exit 0 ;;
    *)
      log_error "Unknown argument: $1"
      show_help; exit 1 ;;
  esac
done

log_banner

# --- 3. Dynamic Controller Endpoint Resolution ---
log_step "Resolving and Validating Controller Endpoint"

validate_ipv4_endpoint() {
  local ep="$1"
  # Regex format: 1-3 digits per octet, followed by colon and port (1-65535)
  local pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}:([0-9]{1,5})$"
  if [[ ! "$ep" =~ $pattern ]]; then
    return 1
  fi

  local ip_part="${ep%:*}"
  local port_part="${ep#*:}"

  # Validate IP octets (0-255)
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip_part"
  if [[ "$o1" -gt 255 || "$o2" -gt 255 || "$o3" -gt 255 || "$o4" -gt 255 ]]; then
    return 1
  fi

  # Validate port range (1-65535)
  if [[ "$port_part" -lt 1 || "$port_part" -gt 65535 ]]; then
    return 1
  fi

  # Prohibit unroutable / loopback default traps
  if [[ "$ip_part" == "0.0.0.0" ]]; then
    return 1
  fi

  return 0
}

FINAL_CONTROLLER_ADDR=""

# Precedence 1: Command-line flag
if [[ -n "$CONTROLLER_ADDR_CLI" ]]; then
  if validate_ipv4_endpoint "$CONTROLLER_ADDR_CLI"; then
    FINAL_CONTROLLER_ADDR="$CONTROLLER_ADDR_CLI"
    log_info "Controller address supplied via CLI flag: ${CLR_BOLD}${FINAL_CONTROLLER_ADDR}${CLR_RESET}"
  else
    log_error "Invalid IPv4:Port endpoint specified in CLI flag: '$CONTROLLER_ADDR_CLI'"
    exit 1
  fi
# Precedence 2: Environment variable
elif [[ -n "${COPSEC_CONTROLLER_ENDPOINT:-}" ]]; then
  if validate_ipv4_endpoint "$COPSEC_CONTROLLER_ENDPOINT"; then
    FINAL_CONTROLLER_ADDR="$COPSEC_CONTROLLER_ENDPOINT"
    log_info "Controller address resolved from COPSEC_CONTROLLER_ENDPOINT: ${CLR_BOLD}${FINAL_CONTROLLER_ADDR}${CLR_RESET}"
  else
    log_error "Invalid IPv4:Port endpoint found in COPSEC_CONTROLLER_ENDPOINT: '$COPSEC_CONTROLLER_ENDPOINT'"
    exit 1
  fi
# Precedence 3: Interactive prompt with strict re-validation
else
  if [[ -t 0 ]]; then
    echo -e "${CLR_YELLOW}[?] Central Controller endpoint is required for gRPC telemetry streaming.${CLR_RESET}"
    while true; do
      read -rp "Enter Controller gRPC endpoint [e.g. 192.168.1.10:50051]: " USER_INPUT
      USER_INPUT=$(echo "$USER_INPUT" | tr -d '[:space:]')
      if validate_ipv4_endpoint "$USER_INPUT"; then
        FINAL_CONTROLLER_ADDR="$USER_INPUT"
        break
      else
        echo -e "${CLR_RED}Invalid format. Must be an IPv4 address and valid port (1-65535). Example: 192.168.1.10:50051${CLR_RESET}"
      fi
    done
  else
    log_error "Unattended non-interactive installation failed: CONTROLLER_ADDR not provided."
    log_error "Specify via --controller <IP:PORT> or export COPSEC_CONTROLLER_ENDPOINT=<IP:PORT>."
    exit 1
  fi
fi

log_success "Verified Controller gRPC Endpoint: ${FINAL_CONTROLLER_ADDR}"

# --- 4. OS Detection & Modular Dependency Validation ---
log_step "Validating System Package Toolchains & Kernel Modules"

OS_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  source /etc/os-release
  OS_FAMILY="${ID_LIKE:-$ID}"
fi

install_debian_deps() {
  log_info "Synchronizing Debian/Ubuntu/Pardus package repositories..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq

  local required_pkgs=(
    "suricata"
    "libpcap-dev"
    "clang"
    "llvm"
    "libelf-dev"
    "ethtool"
    "jq"
    "openssl"
    "iptables"
    "conntrack"
    "iproute2"
    "ipset"
    "curl"
    "tar"
    "gzip"
  )

  log_info "Installing strict dependencies: ${required_pkgs[*]}"
  apt-get install -y -qq "${required_pkgs[@]}"
}

install_rhel_deps() {
  local pkg_mgr="dnf"
  if ! command -v dnf >/dev/null 2>&1; then
    pkg_mgr="yum"
  fi

  log_info "Synchronizing RHEL/CentOS/Rocky/AlmaLinux repositories via $pkg_mgr..."
  $pkg_mgr install -y -q epel-release
  $pkg_mgr makecache -q

  local required_pkgs=(
    "suricata"
    "libpcap-devel"
    "clang"
    "llvm"
    "elfutils-libelf-devel"
    "ethtool"
    "jq"
    "openssl"
    "iptables"
    "conntrack-tools"
    "iproute"
    "ipset"
    "curl"
    "tar"
    "gzip"
  )

  log_info "Installing strict dependencies: ${required_pkgs[*]}"
  $pkg_mgr install -y -q "${required_pkgs[@]}"
}

install_arch_deps() {
  log_info "Synchronizing Arch/CachyOS package databases..."
  pacman -Sy --noconfirm

  local required_pkgs=(
    "suricata"
    "libpcap"
    "clang"
    "llvm"
    "libelf"
    "ethtool"
    "jq"
    "openssl"
    "iptables"
    "conntrack-tools"
    "iproute2"
    "ipset"
    "curl"
    "tar"
    "gzip"
  )

  log_info "Installing strict dependencies: ${required_pkgs[*]}"
  pacman -S --needed --noconfirm "${required_pkgs[@]}"
}

case "$OS_FAMILY" in
  *debian*|*ubuntu*|*pardus*)
    install_debian_deps ;;
  *rhel*|*centos*|*fedora*|*rocky*|*alma*)
    install_rhel_deps ;;
  *arch*|*cachyos*)
    install_arch_deps ;;
  *)
    log_error "Unsupported operating system distribution: $OS_FAMILY"
    exit 1 ;;
esac

# Pre-flight Binary Verification
declare -A BINARY_CHECKS=(
  ["openssl"]="OpenSSL Cryptographic Toolkit"
  ["suricata"]="Suricata NIDS/NIPS Engine"
  ["clang"]="LLVM/Clang eBPF Compiler"
  ["llvm-strip"]="LLVM Toolchain Utilities"
  ["ethtool"]="Ethernet Driver Query Tool"
  ["jq"]="JSON Processing Engine"
  ["iptables"]="Kernel Packet Filtering"
  ["conntrack"]="Netfilter Connection Tracker"
)

log_info "Performing post-installation binary validation assertions..."
for bin in "${!BINARY_CHECKS[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log_error "Dependency verification failed: '${bin}' (${BINARY_CHECKS[$bin]}) not found in PATH."
    exit 1
  fi
  printf "  %-14s : ${CLR_GREEN}[✓ OK]${CLR_RESET} (%s)\n" "$bin" "$(command -v "$bin")"
done
log_success "All required toolchains installed and verified."

# --- 5. Node Identity & Master Key Initialization ---
log_step "Initializing Node Identity & Cryptographic Secrets"

NODE_ID="${NODE_ID_CLI:-${NODE_ID:-}}"
if [[ -z "$NODE_ID" ]]; then
  NODE_ID="node-$(hostname -s 2>/dev/null || echo 'collector')-$(openssl rand -hex 3)"
fi

API_KEY="${API_KEY_CLI:-${COPSEC_API_KEY:-}}"
if [[ -z "$API_KEY" ]]; then
  API_KEY=$(openssl rand -hex 32)
fi

install -d -m 700 "$CONF_DIR"
install -d -m 700 "$CERTS_DIR"
install -d -m 750 "/var/log/copsec"
install -d -m 750 "/var/log/copsec/forensics"
install -d -m 750 "/var/lib/copsec"

log_metric "Node Identifier" "$NODE_ID"
log_metric "Cluster Fleet Group" "$NODE_GROUP"
log_metric "Configuration Root" "$CONF_DIR (Permissions: 0700)"

# --- 6. Automated Mutual TLS (mTLS) Certificate Bootstrapping ---
log_step "Bootstrapping Mutual TLS (mTLS) Infrastructure"

CA_KEY="${CERTS_DIR}/ca.key"
CA_CRT="${CERTS_DIR}/ca.crt"
CLIENT_KEY="${CERTS_DIR}/collector.key"
CLIENT_CSR="${CERTS_DIR}/collector.csr"
CLIENT_CRT="${CERTS_DIR}/collector.crt"

# 6.1 Certificate Authority (CA) Setup
if [[ -n "$CA_CERT_SOURCE" && -n "$CA_KEY_SOURCE" ]]; then
  log_info "Ingesting external Root CA credentials..."
  cp -f "$CA_CERT_SOURCE" "$CA_CRT"
  cp -f "$CA_KEY_SOURCE" "$CA_KEY"
elif [[ -f "$CA_CRT" && -f "$CA_KEY" && "$FORCE_REINSTALL" == false ]]; then
  log_info "Reusing existing Root CA credentials in ${CERTS_DIR}."
else
  log_info "Generating self-contained 4096-bit RSA Root Certificate Authority..."
  openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
    -keyout "$CA_KEY" \
    -out "$CA_CRT" \
    -subj "/C=US/ST=Security/L=Vault/O=CoPSeC-Enterprise/OU=PKI/CN=CoPSeC-Root-CA" \
    2>/dev/null
  log_success "Created Root CA: ${CA_CRT}"
fi

# 6.2 Node Client Certificate Generation (mTLS Client Auth)
if [[ ! -f "$CLIENT_CRT" || ! -f "$CLIENT_KEY" || "$FORCE_REINSTALL" == true ]]; then
  log_info "Generating 4096-bit RSA client keypair for node '${NODE_ID}'..."
  openssl req -newkey rsa:4096 -nodes \
    -keyout "$CLIENT_KEY" \
    -out "$CLIENT_CSR" \
    -subj "/C=US/ST=Security/L=Vault/O=CoPSeC-Enterprise/OU=EdgeCollector/CN=${NODE_ID}" \
    2>/dev/null

  # Sign client certificate using CA with clientAuth extended key usage
  cat << 'EXT_EOF' > "${CERTS_DIR}/client_ext.cnf"
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "CoPSeC Edge Sensor Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXT_EOF

  openssl x509 -req -days 730 \
    -in "$CLIENT_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$CLIENT_CRT" \
    -extfile "${CERTS_DIR}/client_ext.cnf" \
    2>/dev/null

  rm -f "$CLIENT_CSR" "${CERTS_DIR}/client_ext.cnf" "${CERTS_DIR}/ca.srl"
  log_success "Generated and signed client certificate: ${CLIENT_CRT}"
fi

# 6.3 Strict Permission Hardening on Cryptographic Artifacts
chmod 600 "$CA_KEY"
chmod 644 "$CA_CRT"
chmod 600 "$CLIENT_KEY"
chmod 644 "$CLIENT_CRT"
chown -R root:root "$CERTS_DIR"
log_success "Cryptographic key permissions restricted strictly to chmod 600."

# --- 7. Generate Production Environment File (/etc/copsec/collector.env) ---
log_step "Generating Secure Environment Configuration"

cat << ENV_EOF > "$ENV_FILE"
# ==============================================================================
#  CoPSeC Collector Edge Sensor Environment Configuration
#  Provisioned: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# ==============================================================================

# Central Controller Connectivity (Strict IPv4:Port)
COPSEC_CONTROLLER_ENDPOINT=${FINAL_CONTROLLER_ADDR}

# Node Fleet Identification
COPSEC_NODE_ID=${NODE_ID}
COPSEC_NODE_GROUP=${NODE_GROUP}

# Authentication & Security
COPSEC_API_KEY=${API_KEY}

# Mutual TLS (mTLS) Cryptographic Assets
COPSEC_TLS_CA_CERT=${CA_CRT}
COPSEC_TLS_CLIENT_CERT=${CLIENT_CRT}
COPSEC_TLS_CLIENT_KEY=${CLIENT_KEY}
COPSEC_TLS_MIN_VERSION=1.3

# Storage & Buffer Paths (Tier 1 Edge is Stateless)
COPSEC_BUFFER_DB=/var/lib/copsec/buffer.db
COPSEC_OFFSET_FILE=/var/lib/copsec/offsets.json
COPSEC_FORENSICS_DIR=/var/log/copsec/forensics
COPSEC_WHITELIST_FILE=/etc/copsec/whitelist.json

# Defensive Subsystems
COPSEC_HONEYPOT_ENABLED=true
COPSEC_HONEYPOT_HTTP_PORT=8088
COPSEC_TARPIT_PORT=2223
COPSEC_XDP_ENABLED=true
ENV_EOF

# Enforce strict 0600 permissions
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE"
log_success "Environment schema persisted to ${ENV_FILE} (chmod 600, root:root)."

# --- 8. Systemd Service Unit Generation ---
log_step "Configuring Systemd Hardened Service Unit"

cat << 'SERVICE_EOF' > "$SYSTEMD_SERVICE"
[Unit]
Description=CoPSeC Hardened Edge Collector & Autonomous Sensor
Documentation=https://github.com/CoPdasten/copsec
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/copsec
EnvironmentFile=/etc/copsec/collector.env
ExecStart=/usr/local/bin/copsec-collector \
  --controller=${COPSEC_CONTROLLER_ENDPOINT} \
  --node-identity=/etc/copsec/node.json \
  --buffer-db=${COPSEC_BUFFER_DB} \
  --offset-file=${COPSEC_OFFSET_FILE} \
  --whitelist=${COPSEC_WHITELIST_FILE}
Restart=always
RestartSec=3s

# Security Hardening & Linux Capability Bounding
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_BPF
ProtectHome=read-only
PrivateTmp=true
ProtectKernelModules=false
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

chmod 644 "$SYSTEMD_SERVICE"
systemctl daemon-reload
log_success "Registered systemd unit at ${SYSTEMD_SERVICE}."

# --- 9. Deployment Summary & Verification ---
log_step "Deployment Finalized Successfully"
echo -e "${CLR_GREEN}${CLR_BOLD}"
cat << 'SUMMARY_EOF'
================================================================================
           CoPSeC COLLECTOR EDGE SENSOR PROVISIONING COMPLETE
================================================================================
SUMMARY_EOF
echo -e "${CLR_RESET}"

log_metric "Controller gRPC Target" "$FINAL_CONTROLLER_ADDR"
log_metric "Assigned Node ID" "$NODE_ID"
log_metric "mTLS CA Certificate" "$CA_CRT"
log_metric "mTLS Client Certificate" "$CLIENT_CRT"
log_metric "Environment Spec" "$ENV_FILE (chmod 600)"
log_metric "Service Unit" "systemctl status copsec-collector"

echo -e "\n${CLR_CYAN}${CLR_BOLD}Next Steps:${CLR_RESET}"
echo -e "  1. Copy ${CLR_WHITE}${CA_CRT}${CLR_RESET} to your Controller node to authorize this client."
echo -e "  2. Start the collector service: ${CLR_BOLD}sudo systemctl enable --now copsec-collector${CLR_RESET}"
echo -e "  3. Verify connection: ${CLR_BOLD}journalctl -u copsec-collector -f${CLR_RESET}\n"
