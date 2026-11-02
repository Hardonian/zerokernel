# ZeroKernel (`zk-ebpf`)

**Sub-Second Cryptographic Zero-Knowledge Proofs of Linux Kernel Execution & Wire-Speed XDP Telemetry.**

ZeroKernel unites **Ring-0 Linux eBPF (`aya-ebpf`)** (`sys_enter_execve` + `XDP` raw packet inspection) with **RISC-V Zero-Knowledge Virtual Machines (`SP1` / `riscv32im`)** to emit succinct cryptographic receipts proving a Linux host or autonomous agent obeyed syscall, privilege, and egress invariants without exposing the underlying private trace.

## Quickstart

```bash
cargo test --workspace
cargo run --release --bin zerokernel -- prove --event-count 4096 --output receipt.zk.json
cargo run --release --bin zerokernel -- verify --receipt-path receipt.zk.json
./scripts/epyc_gpu_prove.sh
```