Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "ZeroKernel: High-Throughput Prover & Accumulator Benchmark" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$env:RUST_LOG = "info"

Write-Host ">> Running 4K event batch..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- bench --batch-size 4096 --iterations 3

Write-Host ">> Running 32K event batch..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- bench --batch-size 32768 --iterations 3

Write-Host ">> Running 65K event batch (MAX_BATCH_EVENTS)..." -ForegroundColor Yellow
cargo run --release --bin zerokernel -- bench --batch-size 65536 --iterations 3

Write-Host ">> All benchmarks completed successfully." -ForegroundColor Green

