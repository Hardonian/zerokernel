#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo ">> Running ZeroKernel On-Chain Agent Governance & Slashing Demo..."
PYTHONPATH="${REPO_ROOT}/sdk/python" python3 "${SCRIPT_DIR}/testnet_agent_governance.py"

