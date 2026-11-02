# ZeroKernel Architecture Specification

ZeroKernel bridges Linux Ring-0 kernel telemetry (`aya-ebpf`) and Zero-Knowledge Proof systems (`SP1` / `riscv32im`) to deliver verifiable, confidential execution receipts for autonomous agents, host workloads, and cloud environments.

```
                              ZeroKernel System Architecture

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

## 1. Zero-Copy C-ABI Memory Layout (`zerokernel-common`)

To ensure maximum throughput between Ring-0 eBPF, userspace consumers, and the RISC-V zkVM guest circuit, `KernelSyscallEvent` is constrained to exactly 48 bytes with 8-byte alignment:

```rust
#[repr(C, align(8))]
pub struct KernelSyscallEvent {
    pub timestamp_ns: u64,     // Offset  0..8  : Monotonic kernel time (ktime_get_ns)
    pub pid: u32,              // Offset  8..12 : Process ID
    pub tgid: u32,             // Offset 12..16 : Thread Group ID
    pub uid: u32,              // Offset 16..20 : Real UID of caller
    pub syscall_nr: u32,       // Offset 20..24 : System call number (or synthetic XDP code)
    pub target_ipv4: u32,      // Offset 24..28 : Destination IPv4 (network-byte-order parsed)
    pub target_port: u16,      // Offset 28..30 : Destination TCP/UDP port
    pub flags: u16,            // Offset 30..32 : Bitflags (Hook ID, Root, Privileges)
    pub comm: [u8; 16],        // Offset 32..48 : Process command name (TASK_COMM_LEN)
}
```

### Hook Identifier Flags
- `0x0001`: `HOOK_TRACEPOINT_EXECVE`
- `0x0002`: `HOOK_XDP_IPV4_PACKET`
- `0x0004`: `HOOK_TRACEPOINT_OPENAT`
- `0x0008`: `HOOK_TRACEPOINT_CONNECT`
- `0x0010`: `HOOK_TRACEPOINT_SETUID`
- `0x0020`: `HOOK_SCHED_PROCESS_FORK`
- `0x0040`: `HOOK_SCHED_PROCESS_EXIT`
- `0x0100`: `HOOK_XDP_IPV6_PACKET`

---

## 2. Cryptographic State Accumulators

ZeroKernel employs two complementary accumulators:

### A. Rolling Hash Chain
An incremental SHA-256 rolling hash chain that absorbs events sequentially:
$$\text{RollingHash}_{i} = \text{SHA256}(\text{RollingHash}_{i-1} \parallel \text{EventBytes}_i)$$
Provides linear-time streaming verification with constant $O(1)$ memory.

### B. Binary Merkle Tree
A full binary Merkle tree over all events in the trace window.
- Leaves: $\text{Leaf}_i = \text{SHA256}(\text{"ZK\_LEAF\_V1:"} \parallel \text{EventBytes}_i)$
- Nodes: $\text{Node} = \text{SHA256}(\text{"ZK\_NODE\_V1:"} \parallel \text{Left} \parallel \text{Right})$
- Allows generating succinct $O(\log N)$ inclusion proofs for verifying specific transactions or audit disputes without sharing the entire trace.

---

## 3. RISC-V 32IM zkVM Guest Circuit (`zerokernel-zk-guest`)

The guest circuit compiles to the `riscv32im-succinct-zkvm-elf` target and enforces mathematical constraints on the trace:
1. **Clock Monotonicity Constraint**:
   $$T_{i} \ge T_{i-1} \quad \forall i \in [1, N)$$
2. **Privilege Boundary Invariant**:
   If $\text{allow\_root} = \text{false}$, then $\text{UID}_i \neq 0$ and $\text{FLAG\_ROOT\_PRIVILEGE} \notin \text{Flags}_i$.
3. **Syscall Bitmask Invariant**:
   $$(\text{forbidden\_mask} \ \& \ (1 \ll \text{syscall\_nr}_i)) = 0$$
4. **Network Egress CIDR Constraint**:
   $$(\text{target\_ip}_i \ \& \ \text{mask}) \neq (\text{forbidden\_subnet} \ \& \ \text{mask})$$
5. **Port Containment**:
   $$\text{target\_port}_i \neq \text{forbidden\_port}$$

---

## 4. Host Orchestration & Verification (`zerokernel-host`)

The host binary provides full orchestration for proving, verifying, and monitoring:
- **Prove**: Synthesizes or consumes RingBuf traces, runs circuit, commits receipt.
- **Verify**: Verifies receipt seal, vkey hash, and public commitment in under 300 microseconds.
- **Audit Agent**: Captures agent lifecycle operations and guarantees zero unauthorized network exfiltrations.
- **Monitor Daemon**: Tumbling window pipeline emitting chained proof receipts.
- **Export EVM / Attestation**: Bridges off-chain proofs into smart contract calldata and W3C Verifiable Credentials.

