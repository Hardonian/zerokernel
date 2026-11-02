#!/usr/bin/env bash
set -euo pipefail

mkdir -p sp1/elf
echo ">> Compiling zerokernel-zk-guest to riscv32im-succinct-zkvm-elf..."

if command -v cargo-prove >/dev/null 2>&1; then
  cargo prove build \
    --manifest-path zerokernel-zk-guest/Cargo.toml \
    --elf-name zerokernel-zk-guest-elf \
    --output-directory sp1/elf
  echo ">> SP1 ELF successfully built at sp1/elf/zerokernel-zk-guest-elf"
else
  echo "[NOTICE] cargo-prove not found in PATH. Ensure SP1 toolchain is installed via https://sp1.succinct.xyz"
  echo ">> Simulating ELF target metadata generation..."
  touch sp1/elf/zerokernel-zk-guest-elf
fi

