#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "ZeroKernel: Autonomous Agent Execution & Egress Audit Demo"
echo "=========================================================="

# 1. Audit benign agent
echo ">> Step 1: Auditing compliant autonomous agent (hermes-worker)..."
cargo run --release --bin zerokernel -- audit-agent \
  --agent-id hermes-worker \
  --lifecycle-steps 128 \
  --output benign_agent.zk.json

echo ">> Step 2: Verifying benign agent receipt with --strict..."
cargo run --release --bin zerokernel -- verify \
  --receipt-path benign_agent.zk.json \
  --strict

# 2. Audit rogue agent attempting exfiltration
echo ">> Step 3: Auditing rogue agent injecting unauthorized egress/C2..."
cargo run --release --bin zerokernel -- audit-agent \
  --agent-id rogue-c2-agent \
  --lifecycle-steps 128 \
  --inject-exfiltration \
  --output rogue_agent.zk.json

echo ">> Step 4: Verifying cryptographic proof seal of audit detection..."
cargo run --release --bin zerokernel -- verify \
  --receipt-path rogue_agent.zk.json

# 3. Export to EVM calldata & JSON-LD attestation
echo ">> Step 5: Exporting EVM verifier calldata & W3C Verifiable Credential..."
cargo run --release --bin zerokernel -- export-evm \
  --receipt-path benign_agent.zk.json \
  --output evm_params.json

cargo run --release --bin zerokernel -- export-attestation \
  --receipt-path benign_agent.zk.json \
  --output agent_attestation.jsonld

# Cleanup
rm -f benign_agent.zk.json rogue_agent.zk.json evm_params.json agent_attestation.jsonld
echo ">> Autonomous agent audit demonstration successfully completed!"

