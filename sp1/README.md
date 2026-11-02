# ZeroKernel SP1 zkVM Toolchain Pipeline

This directory provides the build scripts and verification artifacts for running ZeroKernel's RISC-V 32IM guest circuit inside the Succinct SP1 zkVM.

---

## 1. Prerequisites

Install the SP1 toolchain and CLI (`sp1up` / `cargo-prove`):

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
cargo prove --version
```

---

## 2. Compile Guest to RISC-V 32IM ELF

Run the compilation script:

```bash
./sp1/build.sh
```

Or manually:

```bash
cargo prove build \
  --manifest-path zerokernel-zk-guest/Cargo.toml \
  --elf-name zerokernel-zk-guest-elf \
  --output-directory sp1/elf
```

This compiles the pure `no_std` guest circuit into an uncompressed, stripped ELF targeting `riscv32im-succinct-zkvm-elf`.

---

## 3. Generate Hardware-Accelerated SP1 STARK Proofs

With the compiled ELF, execute the host prover using CPU or NVIDIA CUDA acceleration:

```bash
# SP1 CPU Prover
cargo run --release --bin zerokernel -- prove \
  --prover sp1-cpu \
  --event-count 4096 \
  --output sp1_receipt.zk.json

# SP1 CUDA GPU Prover (requires NVIDIA GPU & CUDA 12+)
cargo run --release --bin zerokernel -- prove \
  --prover sp1-cuda \
  --event-count 65536 \
  --output sp1_gpu_receipt.zk.json
```

The emitted receipt contains:
- `vkey_hash`: The circuit fingerprint.
- `sp1_descriptor`: Estimated cycles (~120 cycles/event), shard allocation, and STARK execution journal.
- `proof_seal_hex`: Cryptographic proof seal for sub-millisecond verification.

---

## 4. On-Chain Verification

The generated proofs can be verified on Ethereum, Base, Arbitrum, or local testnets using `contracts/ZeroKernelVerifier.sol`:

```bash
cargo run --release --bin zerokernel -- export-evm \
  --receipt-path sp1_receipt.zk.json \
  --output evm_params.json
```

