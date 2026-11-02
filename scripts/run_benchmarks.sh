#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "ZeroKernel: High-Throughput Prover & Accumulator Benchmark"
echo "=========================================================="

export RUST_LOG="${RUST_LOG:-info}"

echo ">> Running 4K event batch..."
cargo run --release --bin zerokernel -- bench --batch-size 4096 --iterations 3

echo ">> Running 32K event batch..."
cargo run --release --bin zerokernel -- bench --batch-size 32768 --iterations 3

echo ">> Running 65K event batch (MAX_BATCH_EVENTS)..."
cargo run --release --bin zerokernel -- bench --batch-size 65536 --iterations 3

echo ">> All benchmarks completed successfully."

