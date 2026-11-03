# Security Policy

ZeroKernel treats system-level security, cryptographic soundess, and kernel-level integrity as foundational pillars. This document details our vulnerability reporting guidelines, disclosure schedule, security audit standards, and bug bounty program.

## Supported Versions

Only the latest active major and patch releases of ZeroKernel receive security updates.

| Version | Supported | Security Maintenance Status |
| :--- | :---: | :--- |
| `v1.0.x` | Yes | Active LTS Support & Security Patches |
| `< 1.0.0` | No | Development pre-releases, unsupported |

## Reporting a Security Vulnerability

If you discover a potential vulnerability in ZeroKernel (including Ring-0 eBPF probes, the zkVM guest circuits, host provers, SDKs, or on-chain EVM verifiers), please report it responsibly:

- **Email**: Send encrypted disclosures to `security@zerokernel.dev`.
- **GPG Key Fingerprint**: `94B3 E82D 1085 F27A 690B 35D9 C381 A0D4 792F E8B1`
- **PGP Key ID**: `0x792FE8B1`
- **Response SLA**: Initial triage within 24 hours; status updates every 48 hours until remediation.

Please include:

- A detailed description of the vulnerability and attack vector.
- Affected components (`zerokernel-ebpf`, `zerokernel-zk-guest`, `zerokernel-common`, `zerokernel-host`, SDK, or `ZeroKernelVerifier.sol`).
- Reproduction steps or proof-of-concept (PoC) trace.
- Potential impact on system confidentiality, integrity, or prover soundness.

## Responsible Disclosure Timeline

We adhere to a standard 90-day responsible disclosure timeline:

1. **Acknowledgment**: Within 24 hours of receipt.
2. **Assessment & Triage**: Within 5 business days to confirm severity via CVSS v3.1.
3. **Patch Development & Testing**: Tested against our automated verification suites and formal models.
4. **Coordinated Public Release**: Upon release of the patch and advisory notification to registered operators.

## Bug Bounty Program

ZeroKernel maintains an active bug bounty program rewarding ethical security researchers for identifying vulnerabilities before they can impact production workloads.

### Bounty Tiers

| Severity | CVSS v3.1 Range | Scope / Impact | Reward (USD / USDC) |
| :--- | :--- | :--- | :--- |
| **Critical** | 9.0 – 10.0 | Circuit soundness break, false proof acceptance, unauthorized on-chain fund draining | \$25,000 – \$100,000 |
| **High** | 7.0 – 8.9 | Ring-0 kernel crash, arbitrary eBPF map corruption, host privilege escalation | \$10,000 – \$25,000 |
| **Medium** | 4.0 – 6.9 | Denial of Service in prover queue, memory leaks under malformed traces | \$2,500 – \$10,000 |
| **Low** | 0.1 – 3.9 | Informational security improvements, telemetry leakage | \$500 – \$2,500 |

### Out of Scope

- Attacks requiring physical access to the host machine or active root compromise before daemon startup.
- Denial of service attacks against public testnet RPC nodes.
- Social engineering, phishing, or physical security attacks against team members.

## Cryptographic & Circuit Assumptions

ZeroKernel's zkVM circuits operate under the hardness of:

- The discrete logarithm problem and hash-based polynomial commitments over the BabyBear finite field ($p = 2^{31} - 2^{27} + 1$).
- Collision resistance of standard SHA-256 (`ZK_LEAF_V1:` and `ZK_NODE_V1:` prefixes).
- Invariant enforcement guarantees within the Linux eBPF verifier (kernel 5.15+).
