#!/usr/bin/env bash
set -euo pipefail
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-64}"
export RUST_LOG="${RUST_LOG:-info}"
cargo run --release --bin zerokernel -- bench --batch-size 65536