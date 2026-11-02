$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

Write-Host ">> Running ZeroKernel On-Chain Agent Governance & Slashing Demo..." -ForegroundColor Cyan
$env:PYTHONPATH = "$repoRoot\sdk\python"
python "$scriptDir\testnet_agent_governance.py"

