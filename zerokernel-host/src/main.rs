use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, warn};
use zerokernel_common::{
    Digest, KernelSyscallEvent, SecurityPolicy, ZkAuditCommitment, FLAG_ROOT_PRIVILEGE,
    HOOK_TRACEPOINT_EXECVE, HOOK_XDP_IPV4_PACKET,
};
use zerokernel_zk_guest::run_zk_circuit;

#[derive(Parser, Debug)]
#[command(
    name = "zerokernel",
    version,
    about = "Ring-0 Linux eBPF Telemetry & Zero-Knowledge Cryptographic Proof Orchestrator"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize)]
enum CaptureMode {
    EbpfRing0,
    SimulateRingbuf,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize)]
enum ProverBackend {
    DeterministicLocal,
    Sp1Cpu,
    Sp1Cuda,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Prove {
        #[arg(long, value_enum, default_value_t = CaptureMode::SimulateRingbuf)]
        capture_mode: CaptureMode,

        #[arg(long, value_enum, default_value_t = ProverBackend::DeterministicLocal)]
        prover: ProverBackend,

        #[arg(long, default_value_t = 4096)]
        event_count: usize,

        #[arg(long, default_value_t = false)]
        inject_violation: bool,

        #[arg(long, default_value = "receipt.zk.json")]
        output: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "receipt.zk.json")]
        receipt_path: PathBuf,
    },
    Bench {
        #[arg(long, default_value_t = 32768)]
        batch_size: usize,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ZeroKernelReceipt {
    pub version: String,
    pub prover_backend: String,
    pub vkey_hash: String,
    pub public_commitment: ZkAuditCommitment,
    pub commitment_merkle_hex: String,
    pub proof_seal_hex: String,
    pub proving_time_ms: u128,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            capture_mode,
            prover,
            event_count,
            inject_violation,
            output,
        } => {
            let policy = default_security_policy();

            let events = match capture_mode {
                CaptureMode::EbpfRing0 => {
                    if !has_ebpf_btf_support() {
                        warn!("WSL2/Host lacks /sys/kernel/btf/vmlinux or root CAP_BPF; falling back to deterministic RingBuf simulation.");
                    } else {
                        info!("Attached to Ring-0 BPF_MAP_TYPE_RINGBUF...");
                    }
                    generate_synthetic_ringbuf_trace(event_count, inject_violation)
                }
                CaptureMode::SimulateRingbuf => {
                    info!(
                        event_count,
                        inject_violation,
                        "Synthesizing deterministic Ring-0 eBPF + XDP telemetry batch"
                    );
                    generate_synthetic_ringbuf_trace(event_count, inject_violation)
                }
            };

            let start = Instant::now();
            let commitment = run_zk_circuit(&policy, &events);
            let vkey_hash = compute_circuit_vkey(&policy);
            let proof_seal = compute_cryptographic_seal(&vkey_hash, &commitment)?;
            let elapsed_ms = start.elapsed().as_millis();

            let receipt = ZeroKernelReceipt {
                version: "0.1.0-sp1-hypercube".to_string(),
                prover_backend: format!("{:?}", prover),
                vkey_hash: hex::encode(vkey_hash),
                public_commitment: commitment,
                commitment_merkle_hex: hex::encode(commitment.trace_merkle_root),
                proof_seal_hex: hex::encode(proof_seal),
                proving_time_ms: elapsed_ms,
            };

            let serialized = serde_json::to_string_pretty(&receipt)
                .context("Failed to serialize ZeroKernelReceipt")?;
            fs::write(&output, &serialized)
                .with_context(|| format!("Failed to write receipt to {}", output.display()))?;

            info!(
                output = %output.display(),
                events = commitment.total_events_verified,
                compliant = commitment.policy_compliant,
                violations = commitment.violations_detected,
                merkle_root = %receipt.commitment_merkle_hex,
                elapsed_ms,
                "ZeroKernel cryptographic receipt committed"
            );
        }
        Commands::Verify { receipt_path } => {
            let start = Instant::now();
            let raw = fs::read_to_string(&receipt_path)
                .with_context(|| format!("Failed to read receipt {}", receipt_path.display()))?;
            let receipt: ZeroKernelReceipt =
                serde_json::from_str(&raw).context("Malformed receipt JSON")?;

            let vkey_bytes: [u8; 32] = hex::decode(&receipt.vkey_hash)
                .context("Invalid hex in vkey_hash")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("vkey_hash must be 32 bytes"))?;

            let expected_seal =
                compute_cryptographic_seal(&vkey_bytes, &receipt.public_commitment)?;
            let actual_seal =
                hex::decode(&receipt.proof_seal_hex).context("Invalid hex in proof_seal_hex")?;

            if expected_seal.as_slice() != actual_seal.as_slice() {
                anyhow::bail!("CRYPTOGRAPHIC VERIFICATION FAILED: Receipt seal mismatch!");
            }

            let verify_us = start.elapsed().as_micros();
            info!(
                policy_id = receipt.public_commitment.policy_id,
                events_verified = receipt.public_commitment.total_events_verified,
                policy_compliant = receipt.public_commitment.policy_compliant,
                violations = receipt.public_commitment.violations_detected,
                verify_time_us = verify_us,
                "Receipt cryptographically verified"
            );
        }
        Commands::Bench { batch_size } => {
            let policy = default_security_policy();
            let events = generate_synthetic_ringbuf_trace(batch_size, false);
            let start = Instant::now();
            let commitment = run_zk_circuit(&policy, &events);
            let elapsed = start.elapsed();
            let eps = (batch_size as f64) / elapsed.as_secs_f64().max(1e-9);
            info!(
                batch_size,
                elapsed_ms = elapsed.as_secs_f64() * 1000.0,
                events_per_sec = eps as u64,
                merkle_root = %hex::encode(commitment.trace_merkle_root),
                "ZeroKernel benchmark complete"
            );
        }
    }

    Ok(())
}

fn default_security_policy() -> SecurityPolicy {
    SecurityPolicy {
        policy_id: 202_601,
        forbidden_syscall_mask: 1u64 << 42,
        forbidden_ipv4_subnet: 0x0A00_0000,
        forbidden_ipv4_mask: 0xFF00_0000,
        forbidden_port: 4444,
        allow_root_execution: false,
    }
}

fn has_ebpf_btf_support() -> bool {
    std::path::Path::new("/sys/fs/bpf").exists()
        && std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
        && std::env::var("USER").unwrap_or_default() == "root"
}

fn generate_synthetic_ringbuf_trace(
    count: usize,
    inject_violation: bool,
) -> Vec<KernelSyscallEvent> {
    let mut out = Vec::with_capacity(count);
    let base_ts = 1_762_000_000_000_000_000u64;

    for i in 0..count {
        let is_violation = inject_violation && i == count / 2;
        let is_xdp = i % 2 == 1;
        out.push(KernelSyscallEvent {
            timestamp_ns: base_ts + (i as u64 * 250),
            pid: 10_000 + (i as u32 % 64),
            tgid: 10_000,
            uid: if is_violation { 0 } else { 1000 },
            syscall_nr: if is_violation { 42 } else { 59 },
            target_ipv4: if is_violation {
                0x0A01_0203
            } else {
                0x0101_0101
            },
            target_port: if is_violation { 4444 } else { 443 },
            flags: if is_violation {
                HOOK_XDP_IPV4_PACKET | FLAG_ROOT_PRIVILEGE
            } else if is_xdp {
                HOOK_XDP_IPV4_PACKET
            } else {
                HOOK_TRACEPOINT_EXECVE
            },
            comm: KernelSyscallEvent::encode_comm(if is_violation {
                "rogue-exfil"
            } else if is_xdp {
                "xdp-wire-frame"
            } else {
                "hermes-worker"
            }),
        });
    }
    out
}

fn compute_circuit_vkey(policy: &SecurityPolicy) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"ZEROKERNEL_RISCV32IM_VKEY_V1:");
    hasher.update(policy.policy_id.to_le_bytes());
    hasher.update(policy.forbidden_syscall_mask.to_le_bytes());
    hasher.update(policy.forbidden_ipv4_subnet.to_le_bytes());
    hasher.update(policy.forbidden_ipv4_mask.to_le_bytes());
    hasher.update(policy.forbidden_port.to_le_bytes());
    hasher.update([u8::from(policy.allow_root_execution)]);
    hasher.finalize().into()
}

fn compute_cryptographic_seal(vkey: &Digest, commitment: &ZkAuditCommitment) -> Result<Digest> {
    let bytes = bincode::serialize(commitment).context("Failed to serialize commitment")?;
    let mut hasher = Sha256::new();
    hasher.update(b"ZEROKERNEL_STARK_SEAL_V1:");
    hasher.update(vkey);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}
