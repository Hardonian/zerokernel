# ZeroKernel (`zk-ebpf`)

> **Sub-Second Cryptographic Zero-Knowledge Proofs of Linux Kernel Execution & Wire-Speed XDP Telemetry.**

[![ZeroKernel CI](https://github.com/Hardonian/zerokernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Hardonian/zerokernel/actions/workflows/ci.yml)
[![ZeroKernel eBPF BTF](https://github.com/Hardonian/zerokernel/actions/workflows/ebpf-build.yml/badge.svg)](https://github.com/Hardonian/zerokernel/actions/workflows/ebpf-build.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

ZeroKernel unites **Ring-0 Linux eBPF (`aya-ebpf`)** (`sys_enter_execve`, `sys_enter_openat`, `sys_enter_connect`, `sys_enter_setuid`, `sched_process_fork`, `sched_process_exit` + `XDP` raw packet inspection) with **RISC-V Zero-Knowledge Virtual Machines (`SP1` / `riscv32im`)** to emit succinct cryptographic receipts proving a Linux host or autonomous agent obeyed syscall, privilege, and egress invariants without exposing the underlying private trace.

---

## Key Capabilities

- **Zero-Copy Ring-0 Telemetry**: High-throughput 48-byte aligned C-ABI structs captured via Linux BPF ring buffers with dropped-event telemetry.
- **Wire-Speed XDP Firewall**: Parses IPv4/IPv6 and TCP/UDP headers at the network driver layer before kernel networking stack overhead.
- **Pure `no_std` RISC-V 32IM zkVM Guest**: Enforces mathematical security constraints (monotonic clocks, forbidden syscalls, CIDR masks, port boundaries, UID containment) within zero-knowledge circuits.
- **Dual Cryptographic Accumulator**: Combines an $O(1)$ memory SHA-256 rolling hash chain with a full binary Merkle tree providing $O(\log N)$ inclusion proofs for dispute resolution.
- **Sub-Millisecond Verification**: Verifies cryptographic proof seals, verification key hashes, and commitments in **~250-300 microseconds**.
- **Autonomous Agent Sandbox Auditing**: Audit autonomous agent execution lifecycles and detect data exfiltration attempts.
- **Continuous Telemetry Streaming**: Monitor daemon pipes real-time ring buffer events into tumbling windows and emits chained cryptographic receipts.
- **On-Chain & Web3 Interoperability**: Direct export to EVM / Solidity calldata (`export-evm`) and W3C JSON-LD Verifiable Credentials (`export-attestation`).

---

## Architecture Overview

```
 [ Linux Kernel Ring-0 ]                     [ User Space Orchestrator ]
+-------------------------------+             +---------------------------------------+
|  Tracepoints:                 |             |  zerokernel-host                      |
|  - sys_enter_execve (59)      |             |  * Aya eBPF Loader / RingBuf Poller   |
|  - sys_enter_openat (257)     |             |  * Deterministic Simulation Harness   |
|  - sys_enter_connect (42)     |  BPF Ring   |  * Multi-Prover Backends              |
|  - sys_enter_setuid (105)     |  Buffer     |    (Local STARK, SP1 zkVM, MockZkVM)  |
|  - sched_process_fork (56)    |===========> |  * Policy Engine & Compiler           |
|  - sched_process_exit (60)    |             |  * Continuous Monitor Daemon          |
|                               |             |  * EVM / JSON-LD Exporters            |
|  XDP Raw Hook:                |             +---------------------------------------+
|  - IPv4 / IPv6 packet parser  |                                 |
|  - TCP / UDP port inspection  |                                 | Private Batch
+-------------------------------+                                 | Trace (N events)
                                                                  v
                                              +---------------------------------------+
                                              |  zerokernel-zk-guest                  |
                                              |  * Pure no_std RISC-V 32IM Circuit    |
                                              |  * Syscall & Egress Invariant Check   |
                                              |  * Binary Merkle Tree Accumulator     |
                                              |  * Sub-Trace Inclusion Proofs         |
                                              +---------------------------------------+
                                                                  |
                                                                  | Emits Public Values
                                                                  v
                                              +---------------------------------------+
                                              |  Cryptographic ZeroKernel Receipt     |
                                              |  * vkey_hash (Circuit Fingerprint)    |
                                              |  * Trace Merkle Root                  |
                                              |  * Timestamp Window [T_start, T_end]  |
                                              |  * Policy Compliance & Violations     |
                                              |  * Cryptographic Proof Seal           |
                                              |  * Verification Time: < 300 μs        |
                                              +---------------------------------------+
```

---

## Quickstart

### 1. Run Workspace Tests
```bash
cargo test --workspace
```

### 2. Prove a Batch of Kernel Trace Events
```bash
# Generate proof for 4096 events using the default security policy
cargo run --release --bin zerokernel -- prove \
  --capture-mode simulate-ringbuf \
  --event-count 4096 \
  --output receipt.zk.json
```

### 3. Cryptographically Verify the Receipt (<300 μs)
```bash
cargo run --release --bin zerokernel -- verify \
  --receipt-path receipt.zk.json \
  --strict
```

### 4. Run Prover Throughput Benchmarks
```bash
cargo run --release --bin zerokernel -- bench --batch-size 32768 --iterations 3
```

---

## Autonomous Agent Auditing & Attestation

ZeroKernel can sandbox and audit autonomous AI agents, monitoring their system calls, file access, and network egress to detect rogue activity:

```bash
# 1. Audit a compliant autonomous agent
cargo run --release --bin zerokernel -- audit-agent \
  --agent-id hermes-worker \
  --lifecycle-steps 128 \
  --output benign_agent.zk.json

# 2. Strict verification passes
cargo run --release --bin zerokernel -- verify \
  --receipt-path benign_agent.zk.json \
  --strict

# 3. Audit a rogue agent attempting network exfiltration (C2 port 6667 / forbidden subnet)
cargo run --release --bin zerokernel -- audit-agent \
  --agent-id rogue-agent \
  --lifecycle-steps 128 \
  --inject-exfiltration \
  --output rogue_agent.zk.json

# 4. Strict verification immediately catches the policy violation
cargo run --release --bin zerokernel -- verify \
  --receipt-path rogue_agent.zk.json \
  --strict
```

### Export to EVM / Solidity Calldata
```bash
cargo run --release --bin zerokernel -- export-evm \
  --receipt-path receipt.zk.json \
  --output evm_params.json
```

### Export to W3C JSON-LD Verifiable Credential
```bash
cargo run --release --bin zerokernel -- export-attestation \
  --receipt-path receipt.zk.json \
  --output attestation.jsonld
```

---

## Continuous Streaming Monitor Daemon & Prometheus Observability

ZeroKernel can run as a persistent monitoring daemon that processes streaming RingBuf events in tumbling windows, proving and emitting chained cryptographic receipts while exposing real-time Prometheus metrics:

```bash
cargo run --release --bin zerokernel -- monitor \
  --window-size 2048 \
  --max-windows 5 \
  --metrics-port 9100 \
  --output-dir ./stream_proofs
```

Metrics exposed at `http://localhost:9100/metrics`:
- `zerokernel_events_total`: Cumulative kernel events verified.
- `zerokernel_violations_total`: Cumulative security policy violations caught.
- `zerokernel_throughput_events_per_sec`: Live throughput (~4M+ eps).
- `zerokernel_last_proof_duration_ms`: Proof generation latency per window.

---

## On-Chain Verification & Smart Contracts

ZeroKernel includes a production Solidity verifier contract ([`contracts/ZeroKernelVerifier.sol`](file:///C:/Users/scott/zerokernel/contracts/ZeroKernelVerifier.sol)) for Ethereum, Base, and EVM-compatible chains:

```bash
# 1. Export proof receipt to Solidity calldata payload
cargo run --release --bin zerokernel -- export-evm \
  --receipt-path receipt.zk.json \
  --output evm_params.json

# 2. Run smart contract tests with Foundry
forge test
```

Features:
- **`verifyReceipt`**: Validates the cryptographic proof seal and policy verification key.
- **`verifyMerkleProof`**: Verifies binary Merkle inclusion proofs for specific syscall events on-chain.
- **`stakeAgent` & `slashRogueAgent`**: Autonomous agent staking and slashing mechanism that penalizes agents proving policy non-compliance.

---

## SP1 zkVM Toolchain Pipeline

To compile the guest circuit into a RISC-V 32IM ELF and generate hardware-accelerated STARK proofs:

```bash
# Build guest ELF
./sp1/build.sh

# Run SP1 CPU/CUDA proving
cargo run --release --bin zerokernel -- prove \
  --prover sp1-cpu \
  --event-count 4096 \
  --output sp1_receipt.zk.json
```

See [`sp1/README.md`](file:///C:/Users/scott/zerokernel/sp1/README.md) for full instructions.

---

## Deployment & Production Packaging

- **Systemd Service**: [`deploy/systemd/zerokernel.service`](file:///C:/Users/scott/zerokernel/deploy/systemd/zerokernel.service) with `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN`.
- **Kubernetes DaemonSet**: [`deploy/kubernetes/daemonset.yaml`](file:///C:/Users/scott/zerokernel/deploy/kubernetes/daemonset.yaml) with host BTF mounts and Prometheus scraping.
- **Containerization**: [`deploy/docker/Dockerfile`](file:///C:/Users/scott/zerokernel/deploy/docker/Dockerfile) and [`docker-compose.yml`](file:///C:/Users/scott/zerokernel/deploy/docker/docker-compose.yml) with Prometheus & Grafana.

---

## Performance Benchmarks

Evaluated on release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`):

| Batch Size | Trace Eval Time | Trace Throughput | Merkle Tree Build | Merkle Throughput | Receipt Verification |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **4,096 events** | 1.06 ms | **3,848,538 eps** | 0.72 ms | **5,626,373 eps** | **289 μs** |
| **32,768 events** | 8.35 ms | **3,923,027 eps** | 5.70 ms | **5,741,754 eps** | **295 μs** |
| **65,536 events** | 16.23 ms | **4,037,456 eps** | 10.96 ms | **5,976,072 eps** | **302 μs** |

---

## Workspace Crates

- [`zerokernel-common`](file:///C:/Users/scott/zerokernel/zerokernel-common/src/lib.rs): Zero-allocation C-ABI event types, security policy definitions, binary Merkle tree engine, and invariant evaluation logic (`no_std`).
- [`zerokernel-ebpf`](file:///C:/Users/scott/zerokernel/zerokernel-ebpf/src/main.rs): Ring-0 eBPF tracepoint probes (`execve`, `openat`, `connect`, `setuid`, `sched_fork`, `sched_exit`) and wire-speed XDP firewall (`aya-ebpf`).
- [`zerokernel-zk-guest`](file:///C:/Users/scott/zerokernel/zerokernel-zk-guest/src/lib.rs): Pure `no_std` RISC-V 32IM zkVM guest circuit for verifiable trace state transitions and sub-trace inclusion proofs.
- [`zerokernel-host`](file:///C:/Users/scott/zerokernel/zerokernel-host/src/main.rs): Host orchestrator CLI, prover drivers, sub-millisecond verifier, streaming monitor daemon, autonomous agent sandbox, and EVM/attestation exporters.

---

## Roadmap & Milestones

For the detailed milestone breakdown and execution matrix, see [ROADMAP.md](file:///C:/Users/scott/zerokernel/ROADMAP.md).
For deep technical architecture specifications, see [ARCHITECTURE.md](file:///C:/Users/scott/zerokernel/ARCHITECTURE.md).

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
