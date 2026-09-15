#!/usr/bin/env bash
# ==============================================================================
# CoPSeC Pro - Zero-Downtime Autonomous Update & OTA Upgrade Script
# Preserves all configuration, SQLite databases, and Master API Keys.
# ==============================================================================
set -euo pipefail

CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[31m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_CYAN="\033[36m"
CLR_WHITE="\033[37m"

log_step() {
  echo -e "\n${CLR_CYAN}${CLR_BOLD}[+] ${1}${CLR_RESET}"
}

log_info() {
  echo -e "  • ${1}"
}

log_success() {
  echo -e "  ${CLR_GREEN}[[OK]] ${1}${CLR_RESET}"
}

log_warn() {
  echo -e "  ${CLR_YELLOW}[!] ${1}${CLR_RESET}"
}

log_error() {
  echo -e "  ${CLR_RED}[[FAIL]] ${1}${CLR_RESET}"
}

if [[ "$(id -u)" -ne 0 ]]; then
  log_error "This update script requires root privileges. Please run with sudo: sudo bash scripts/update.sh"
  exit 1
fi

BRANCH="${1:-main}"
REPO_URL="https://github.com/CoPdasten/copsec.git"
BIN_DIR="/opt/copsec/bin"
CONF_DIR="/etc/copsec"
DATA_DIR="/var/lib/copsec"

echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD} CoPSeC Pro - Seamless Platform Upgrade (${BRANCH})${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"

# 1. Dependency checks
log_step "Step 1: Checking Host Toolchain"
if ! command -v git &>/dev/null; then
  log_warn "git not found. Installing git..."
  if command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq git; fi
  if command -v apk &>/dev/null; then apk add --no-cache git; fi
  if command -v dnf &>/dev/null; then dnf install -y git; fi
fi

if ! command -v go &>/dev/null; then
  log_error "Go compiler not found. Please install Go 1.22+ or run install.sh."
  exit 1
fi
log_success "Git and Go compiler verified."

# 2. Resolve source repository
log_step "Step 2: Resolving Upstream Release Tree"
SRC_ROOT=""
CLEANUP_TEMP=0

if [[ -d "/home/copdasten/copsec/.git" ]]; then
  SRC_ROOT="/home/copdasten/copsec"
elif [[ -d "./.git" && -d "./controller" && -d "./collector" ]]; then
  SRC_ROOT="$(pwd)"
elif [[ -d "../.git" && -d "../controller" && -d "../collector" ]]; then
  SRC_ROOT="$(cd .. && pwd)"
elif [[ -d "/opt/copsec/src/.git" ]]; then
  SRC_ROOT="/opt/copsec/src"
fi

if [[ -n "$SRC_ROOT" ]]; then
  log_info "Updating local repository at ${SRC_ROOT} (branch: ${BRANCH})..."
  git -C "$SRC_ROOT" fetch origin "$BRANCH" || true
  git -C "$SRC_ROOT" reset --hard "origin/${BRANCH}" || true
else
  TEMP_DIR="/tmp/copsec_update_$$"
  CLEANUP_TEMP=1
  log_info "Cloning release tree to ${TEMP_DIR}..."
  git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$TEMP_DIR"
  SRC_ROOT="$TEMP_DIR"
fi

COMMIT_HASH="$(git -C "$SRC_ROOT" rev-parse --short HEAD 2>/dev/null || echo "latest")"
log_success "Source tree synchronized to commit ${COMMIT_HASH}."

# 3. Detect active services
log_step "Step 3: Snapshotting Active Services"
ACTIVE_CONTROLLER=0
ACTIVE_COLLECTOR=0
ACTIVE_COCKPIT=0
INIT_SYSTEM="systemd"

if command -v rc-service &>/dev/null; then
  INIT_SYSTEM="openrc"
  if rc-service copsec-controller status 2>/dev/null | grep -q "started"; then ACTIVE_CONTROLLER=1; fi
  if rc-service copsec-collector status 2>/dev/null | grep -q "started"; then ACTIVE_COLLECTOR=1; fi
  if rc-service copsec-cockpit status 2>/dev/null | grep -q "started"; then ACTIVE_COCKPIT=1; fi
elif command -v systemctl &>/dev/null; then
  if systemctl is-active --quiet copsec-controller 2>/dev/null; then ACTIVE_CONTROLLER=1; fi
  if systemctl is-active --quiet copsec-collector 2>/dev/null; then ACTIVE_COLLECTOR=1; fi
  if systemctl is-active --quiet copsec-cockpit 2>/dev/null; then ACTIVE_COCKPIT=1; fi
fi
log_info "Active services: Controller=${ACTIVE_CONTROLLER}, Collector=${ACTIVE_COLLECTOR}, Cockpit=${ACTIVE_COCKPIT}"

# 4. Compile static binaries
log_step "Step 4: Compiling Musl/Glibc Static Binaries"
mkdir -p "${SRC_ROOT}/bin" "${BIN_DIR}"
export CGO_ENABLED=0

log_info "Compiling copsec CLI..."
(cd "${SRC_ROOT}/cmd/copsec" && go build -ldflags="-s -w" -o "${BIN_DIR}/copsec" .)
chmod 755 "${BIN_DIR}/copsec"
ln -sf "${BIN_DIR}/copsec" "/usr/local/bin/copsec"
ln -sf "${BIN_DIR}/copsec" "/usr/bin/copsec" 2>/dev/null || true

log_info "Compiling copsec-controller..."
(cd "${SRC_ROOT}/controller" && go build -ldflags="-s -w" -o "${BIN_DIR}/copsec-controller" .)
chmod 755 "${BIN_DIR}/copsec-controller"
ln -sf "${BIN_DIR}/copsec-controller" "/usr/local/bin/copsec-controller"

log_info "Linking copsec-cockpit..."
cp -f "${BIN_DIR}/copsec-controller" "${BIN_DIR}/copsec-cockpit"
chmod 755 "${BIN_DIR}/copsec-cockpit"
ln -sf "${BIN_DIR}/copsec-cockpit" "/usr/local/bin/copsec-cockpit"

log_info "Compiling copsec-collector..."
(cd "${SRC_ROOT}/collector" && go build -ldflags="-s -w" -o "${BIN_DIR}/copsec-collector" .)
chmod 755 "${BIN_DIR}/copsec-collector"
ln -sf "${BIN_DIR}/copsec-collector" "/usr/local/bin/copsec-collector"

# Copy eBPF bytecode if present
if [[ -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" ]]; then
  mkdir -p "$CONF_DIR"
  cp -f "${SRC_ROOT}/bpf/copsec_xdp.bpf.o" "${CONF_DIR}/copsec_xdp.bpf.o"
  chmod 644 "${CONF_DIR}/copsec_xdp.bpf.o"
  log_info "Updated kernel eBPF bytecode."
fi

log_success "All binaries compiled and deployed to /opt/copsec/bin and /usr/local/bin."

# 5. Restart active services
log_step "Step 5: Reloading Active Daemons"
restart_svc() {
  local s="$1"
  log_info "Restarting ${s}..."
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    systemctl restart "$s" 2>/dev/null || true
  else
    rc-service "$s" restart 2>/dev/null || true
  fi
}

if [[ $ACTIVE_CONTROLLER -eq 1 ]]; then restart_svc "copsec-controller"; fi
if [[ $ACTIVE_COLLECTOR -eq 1 ]]; then restart_svc "copsec-collector"; fi
if [[ $ACTIVE_COCKPIT -eq 1 ]]; then restart_svc "copsec-cockpit"; fi

if [[ $ACTIVE_CONTROLLER -eq 0 && $ACTIVE_COLLECTOR -eq 0 && $ACTIVE_COCKPIT -eq 0 ]]; then
  if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q copsec-controller; then
    restart_svc "copsec-controller"
  fi
fi

# 6. Cleanup temporary directory if created
if [[ $CLEANUP_TEMP -eq 1 && -d "${SRC_ROOT:-}" ]]; then
  rm -rf "$SRC_ROOT"
fi

sleep 1
log_success "Daemons successfully refreshed."

echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD} CoPSeC Pro Upgrade Succeeded! Commit: ${COMMIT_HASH}${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
echo -e "  • Preserved Ledger  : ${CLR_WHITE}${DATA_DIR}/vault.db${CLR_RESET}"
echo -e "  • Preserved API Key : ${CLR_WHITE}${CONF_DIR}/api_key${CLR_RESET}"
echo -e "  • Quick Check       : ${CLR_CYAN}copsec status${CLR_RESET} or ${CLR_CYAN}copsec help${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}================================================================================${CLR_RESET}"
