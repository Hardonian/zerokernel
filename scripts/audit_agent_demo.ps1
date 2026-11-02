Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "ZeroKernel: Autonomous Agent Execution & Egress Audit Demo" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Audit benign agent
Write-Host ">> Step 1: Auditing compliant autonomous agent (hermes-worker)..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- audit-agent `
  --agent-id hermes-worker `
  --lifecycle-steps 128 `
  --output benign_agent.zk.json

Write-Host ">> Step 2: Verifying benign agent receipt with --strict..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- verify `
  --receipt-path benign_agent.zk.json `
  --strict

# 2. Audit rogue agent attempting exfiltration
Write-Host ">> Step 3: Auditing rogue agent injecting unauthorized egress/C2..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- audit-agent `
  --agent-id rogue-c2-agent `
  --lifecycle-steps 128 `
  --inject-exfiltration `
  --output rogue_agent.zk.json

Write-Host ">> Step 4: Verifying cryptographic proof seal of audit detection..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- verify `
  --receipt-path rogue_agent.zk.json

# 3. Export to EVM calldata & JSON-LD attestation
Write-Host ">> Step 5: Exporting EVM verifier calldata & W3C Verifiable Credential..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- export-evm `
  --receipt-path benign_agent.zk.json `
  --output evm_params.json

cargo run --release --bin zerokernel -- export-attestation `
  --receipt-path benign_agent.zk.json `
  --output agent_attestation.jsonld

# Cleanup
Remove-Item -Force benign_agent.zk.json, rogue_agent.zk.json, evm_params.json, agent_attestation.jsonld
Write-Host ">> Autonomous agent audit demonstration successfully completed!" -ForegroundColor Green

