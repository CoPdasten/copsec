#!/usr/bin/env bash
# ==============================================================================
# CoPSeC Enterprise 3-Tier Zero-Trust & Cryptographic Audit Orchestrator
# Filename: orchestrate_copsec_audit.sh
#
# Role: Principal DevSecOps & Security Automation Engineer
# Platform: Autonomous Kernel-Level SIEM/SOAR (CoPSeC)
# Target: 4-Node Multi-Tier Enterprise Lab (pardus1, pardus2, chachy, kali)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCHESTRATOR_PY="${SCRIPT_DIR}/orchestrate_copsec_audit.py"

# Default Topology & Credentials
export LAB_PASSWORD="${LAB_PASSWORD:-2951453}"
export PARDUS1_IP="${PARDUS1_IP:-192.168.1.8}"
export PARDUS2_IP="${PARDUS2_IP:-192.168.1.11}"
export CHACHY_IP="${CHACHY_IP:-192.168.1.10}"
export KALI_IP="${KALI_IP:-192.168.1.12}"

# ANSI Colors
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}==========================================================================================${RESET}"
echo -e "${CYAN}  CoPSeC Enterprise 3-Tier Zero-Trust & Cryptographic Audit Runner${RESET}"
echo -e "${CYAN}==========================================================================================${RESET}"

# Pre-flight local tool verification
for tool in python3 ssh openssl; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[✗ FAIL] Required local tool '${tool}' is not installed or not in PATH.${RESET}" >&2
        exit 1
    fi
done

if [[ ! -f "${ORCHESTRATOR_PY}" ]]; then
    echo -e "${RED}[✗ FAIL] Python orchestrator not found at '${ORCHESTRATOR_PY}'.${RESET}" >&2
    exit 1
fi

chmod +x "${ORCHESTRATOR_PY}"

echo -e "${GREEN}[✓ PASS] Environment validated. Launching Python 3 Audit Orchestrator...${RESET}\n"

exec python3 "${ORCHESTRATOR_PY}" \
    --pardus1-ip "${PARDUS1_IP}" \
    --pardus2-ip "${PARDUS2_IP}" \
    --chachy-ip "${CHACHY_IP}" \
    --kali-ip "${KALI_IP}" \
    --password "${LAB_PASSWORD}" \
    "$@"
