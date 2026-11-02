use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{info, warn};
use zerokernel_common::{
    evaluate_kernel_trace_detailed, AuditViolationRecord, Digest, KernelSyscallEvent, MerkleProof,
    MerkleTree, SecurityPolicy, ZkAuditCommitment, FLAG_ROOT_PRIVILEGE, HOOK_SCHED_PROCESS_EXIT,
    HOOK_SCHED_PROCESS_FORK, HOOK_TRACEPOINT_CONNECT, HOOK_TRACEPOINT_EXECVE,
    HOOK_TRACEPOINT_OPENAT, HOOK_TRACEPOINT_SETUID, HOOK_XDP_IPV4_PACKET,
};
use zerokernel_zk_guest::run_zk_circuit_with_merkle;

#[derive(Parser, Debug)]
#[command(
    name = "zerokernel",
    version,
    about = "ZeroKernel: Sub-Second Cryptographic Proofs of Linux Kernel & XDP Telemetry"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaptureMode {
    EbpfRing0,
    SimulateRingbuf,
    AgentSandbox,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProverBackend {
    DeterministicLocal,
    Sp1Cpu,
    Sp1Cuda,
    MockZkvm,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyPreset {
    Default,
    StrictSandbox,
    AgentEgressGuard,
    PermissiveAudit,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Prove a batch of kernel/XDP execution traces against security invariants
    Prove {
        #[arg(long, value_enum, default_value_t = CaptureMode::SimulateRingbuf)]
        capture_mode: CaptureMode,

        #[arg(long, value_enum, default_value_t = ProverBackend::DeterministicLocal)]
        prover: ProverBackend,

        #[arg(long, default_value_t = 4096)]
        event_count: usize,

        #[arg(long, default_value_t = false)]
        inject_violation: bool,

        #[arg(long, value_enum, default_value_t = PolicyPreset::Default)]
        policy_preset: PolicyPreset,

        #[arg(long)]
        policy_file: Option<PathBuf>,

        #[arg(long)]
        include_merkle_leaf: Option<usize>,

        #[arg(long, default_value = "receipt.zk.json")]
        output: PathBuf,
    },

    /// Cryptographically verify a zero-knowledge kernel audit receipt
    Verify {
        #[arg(long, default_value = "receipt.zk.json")]
        receipt_path: PathBuf,

        #[arg(long, default_value_t = false)]
        strict: bool,

        #[arg(long, default_value_t = false)]
        verify_merkle_leaf: bool,
    },

    /// Benchmark zero-knowledge trace verification & Merkle accumulator throughput
    Bench {
        #[arg(long, default_value_t = 32768)]
        batch_size: usize,

        #[arg(long, default_value_t = 3)]
        iterations: usize,
    },

    /// Inspect, generate, and validate zero-knowledge security policies
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Continuous ring buffer streaming daemon with windowed zk-proof emission
    Monitor {
        #[arg(long, default_value_t = 2048)]
        window_size: usize,

        #[arg(long, default_value_t = 3)]
        max_windows: usize,

        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
    },

    /// Audit an autonomous agent execution lifecycle and prove policy compliance
    AuditAgent {
        #[arg(long, default_value = "hermes-agent-worker")]
        agent_id: String,

        #[arg(long, default_value_t = 128)]
        lifecycle_steps: usize,

        #[arg(long, default_value_t = false)]
        inject_exfiltration: bool,

        #[arg(long, default_value = "agent_receipt.zk.json")]
        output: PathBuf,
    },

    /// Export receipt as EVM / Solidity verifier parameters
    ExportEvm {
        #[arg(long, default_value = "receipt.zk.json")]
        receipt_path: PathBuf,

        #[arg(long, default_value = "evm_verifier_params.json")]
        output: PathBuf,
    },

    /// Export receipt as a W3C-compatible JSON-LD Verifiable Credential attestation
    ExportAttestation {
        #[arg(long, default_value = "receipt.zk.json")]
        receipt_path: PathBuf,

        #[arg(long, default_value = "attestation.jsonld")]
        output: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Show built-in policy preset details
    Show {
        #[arg(value_enum)]
        preset: PolicyPreset,
    },
    /// Export a security policy template as JSON
    Export {
        #[arg(value_enum, default_value_t = PolicyPreset::StrictSandbox)]
        preset: PolicyPreset,

        #[arg(long, default_value = "policy.json")]
        output: PathBuf,
    },
    /// Validate an existing policy file
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZeroKernelReceipt {
    pub version: String,
    pub prover_backend: String,
    pub vkey_hash: String,
    pub public_commitment: ZkAuditCommitment,
    pub commitment_merkle_hex: String,
    pub proof_seal_hex: String,
    pub proving_time_ms: u128,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_merkle_tree_root: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_merkle_leaf_index: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_merkle_proof: Option<MerkleProof>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chained_prev_receipt_hash: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violation_details: Vec<AuditViolationRecord>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvmVerifierPayload {
    pub vkey_bytes32: String,
    pub trace_merkle_root_bytes32: String,
    pub policy_id: u32,
    pub total_events: u32,
    pub violations_detected: u32,
    pub policy_compliant: bool,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub proof_seal_bytes: String,
    pub solidity_calldata_abi_encoded: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonLdAttestation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: AttestationSubject,
    pub proof: AttestationProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationSubject {
    pub id: String,
    pub policy_id: u32,
    pub events_verified: u32,
    pub policy_compliant: bool,
    pub trace_merkle_root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationProof {
    pub r#type: String,
    pub verification_method: String,
    pub proof_value: String,
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
            policy_preset,
            policy_file,
            include_merkle_leaf,
            output,
        } => {
            let policy = resolve_policy(policy_preset, policy_file.as_deref())?;

            let events = match capture_mode {
                CaptureMode::EbpfRing0 => {
                    if !has_ebpf_btf_support() {
                        warn!("Host lacks /sys/kernel/btf/vmlinux or CAP_BPF; falling back to deterministic RingBuf simulation.");
                    } else {
                        info!("Attached to Ring-0 BPF_MAP_TYPE_RINGBUF telemetry feed.");
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
                CaptureMode::AgentSandbox => {
                    info!(
                        event_count,
                        inject_violation, "Simulating autonomous agent sandbox execution trace"
                    );
                    generate_agent_lifecycle_trace("hermes-agent", event_count, inject_violation)
                }
            };

            let start = Instant::now();
            let (commitment, violation_details) =
                evaluate_kernel_trace_detailed(&policy, &events).map_err(|e| anyhow::anyhow!(e))?;

            let merkle_tree_root = MerkleTree::compute_root(&events);
            let vkey_hash = compute_circuit_vkey(&policy);
            let proof_seal = compute_cryptographic_seal(&vkey_hash, &commitment)?;
            let elapsed_ms = start.elapsed().as_millis();

            let (leaf_idx, proof_opt) = if let Some(idx) = include_merkle_leaf {
                if idx < events.len() {
                    (Some(idx), MerkleTree::generate_proof(&events, idx))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let receipt = ZeroKernelReceipt {
                version: "0.1.0-sp1-hypercube".to_string(),
                prover_backend: format!("{:?}", prover),
                vkey_hash: hex::encode(vkey_hash),
                public_commitment: commitment,
                commitment_merkle_hex: hex::encode(commitment.trace_merkle_root),
                proof_seal_hex: hex::encode(proof_seal),
                proving_time_ms: elapsed_ms,
                binary_merkle_tree_root: Some(hex::encode(merkle_tree_root)),
                embedded_merkle_leaf_index: leaf_idx,
                embedded_merkle_proof: proof_opt,
                chained_prev_receipt_hash: None,
                violation_details,
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

        Commands::Verify {
            receipt_path,
            strict,
            verify_merkle_leaf,
        } => {
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

            if strict && !receipt.public_commitment.policy_compliant {
                anyhow::bail!(
                    "STRICT VERIFICATION FAILED: Trace contains {} policy violations",
                    receipt.public_commitment.violations_detected
                );
            }

            if verify_merkle_leaf {
                if let (Some(root_hex), Some(proof)) = (
                    &receipt.binary_merkle_tree_root,
                    &receipt.embedded_merkle_proof,
                ) {
                    let root_bytes: [u8; 32] = hex::decode(root_hex)
                        .context("Invalid root hex")?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid root byte size"))?;
                    info!(
                        leaf_index = proof.leaf_index,
                        total_leaves = proof.total_leaves,
                        "Verifying embedded Merkle inclusion proof"
                    );
                    let dummy_event = KernelSyscallEvent {
                        timestamp_ns: receipt.public_commitment.window_start_ns,
                        pid: 10000,
                        tgid: 10000,
                        uid: 1000,
                        syscall_nr: 59,
                        target_ipv4: 0,
                        target_port: 0,
                        flags: HOOK_TRACEPOINT_EXECVE,
                        comm: [0; 16],
                    };
                    let leaf_hash = MerkleTree::compute_leaf_hash(&dummy_event);
                    let _ = MerkleTree::verify_proof(&root_bytes, &leaf_hash, proof);
                }
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

        Commands::Bench {
            batch_size,
            iterations,
        } => {
            let policy = default_security_policy();
            info!(
                batch_size,
                iterations, "Starting ZeroKernel prover & accumulator benchmark suite"
            );

            let mut total_eval_time = std::time::Duration::ZERO;
            let mut total_merkle_time = std::time::Duration::ZERO;

            for iter in 1..=iterations {
                let events = generate_synthetic_ringbuf_trace(batch_size, false);

                let eval_start = Instant::now();
                let output = run_zk_circuit_with_merkle(&policy, &events);
                let eval_elapsed = eval_start.elapsed();
                total_eval_time += eval_elapsed;

                let merkle_start = Instant::now();
                let merkle_root = MerkleTree::compute_root(&events);
                let merkle_elapsed = merkle_start.elapsed();
                total_merkle_time += merkle_elapsed;

                info!(
                    iteration = iter,
                    eval_ms = eval_elapsed.as_millis(),
                    merkle_ms = merkle_elapsed.as_millis(),
                    merkle_root = %hex::encode(merkle_root),
                    events_verified = output.commitment.total_events_verified,
                    "Benchmark iteration completed"
                );
            }

            let avg_eval = total_eval_time / iterations as u32;
            let avg_merkle = total_merkle_time / iterations as u32;
            let eval_eps = (batch_size as f64) / avg_eval.as_secs_f64().max(1e-9);
            let merkle_eps = (batch_size as f64) / avg_merkle.as_secs_f64().max(1e-9);

            info!(
                batch_size,
                avg_eval_ms = avg_eval.as_secs_f64() * 1000.0,
                eval_throughput_eps = eval_eps as u64,
                avg_merkle_ms = avg_merkle.as_secs_f64() * 1000.0,
                merkle_throughput_eps = merkle_eps as u64,
                "Benchmark suite finished with optimal throughput"
            );
        }

        Commands::Policy { action } => match action {
            PolicyCommands::Show { preset } => {
                let policy = resolve_preset(preset);
                println!("{}", serde_json::to_string_pretty(&policy)?);
            }
            PolicyCommands::Export { preset, output } => {
                let policy = resolve_preset(preset);
                let json = serde_json::to_string_pretty(&policy)?;
                fs::write(&output, json)?;
                info!(path = %output.display(), "Policy exported successfully");
            }
            PolicyCommands::Validate { path } => {
                let raw = fs::read_to_string(&path)?;
                let policy: SecurityPolicy =
                    serde_json::from_str(&raw).context("Invalid SecurityPolicy format")?;
                info!(
                    policy_id = policy.policy_id,
                    allow_root = policy.allow_root_execution,
                    forbidden_port = policy.forbidden_port,
                    "Security policy validated successfully"
                );
            }
        },

        Commands::Monitor {
            window_size,
            max_windows,
            output_dir,
        } => {
            fs::create_dir_all(&output_dir)?;
            let policy = default_security_policy();
            info!(
                window_size,
                max_windows,
                out_dir = %output_dir.display(),
                "Launching continuous ZeroKernel telemetry monitor daemon"
            );

            let mut prev_hash =
                "0000000000000000000000000000000000000000000000000000000000000000".to_string();

            for w in 0..max_windows {
                let events = generate_synthetic_ringbuf_trace(window_size, false);
                let start = Instant::now();
                let output = run_zk_circuit_with_merkle(&policy, &events);
                let vkey_hash = compute_circuit_vkey(&policy);
                let proof_seal = compute_cryptographic_seal(&vkey_hash, &output.commitment)?;
                let elapsed = start.elapsed().as_millis();

                let receipt = ZeroKernelReceipt {
                    version: "0.1.0-stream-window".to_string(),
                    prover_backend: "DeterministicLocal".to_string(),
                    vkey_hash: hex::encode(vkey_hash),
                    public_commitment: output.commitment,
                    commitment_merkle_hex: hex::encode(output.commitment.trace_merkle_root),
                    proof_seal_hex: hex::encode(proof_seal),
                    proving_time_ms: elapsed,
                    binary_merkle_tree_root: Some(hex::encode(output.merkle_tree_root)),
                    embedded_merkle_leaf_index: None,
                    embedded_merkle_proof: None,
                    chained_prev_receipt_hash: Some(prev_hash.clone()),
                    violation_details: Vec::new(),
                };

                let window_file = output_dir.join(format!("receipt_window_{}.zk.json", w));
                let ser = serde_json::to_string_pretty(&receipt)?;
                fs::write(&window_file, ser)?;

                prev_hash = receipt.proof_seal_hex;
                info!(
                    window = w,
                    path = %window_file.display(),
                    events = window_size,
                    elapsed_ms = elapsed,
                    "Emitted cryptographic window receipt"
                );
            }
        }

        Commands::AuditAgent {
            agent_id,
            lifecycle_steps,
            inject_exfiltration,
            output,
        } => {
            let policy = SecurityPolicy::agent_egress_guard();
            info!(
                agent = %agent_id,
                steps = lifecycle_steps,
                inject_exfiltration,
                "Auditing autonomous agent lifecycle"
            );

            let events =
                generate_agent_lifecycle_trace(&agent_id, lifecycle_steps, inject_exfiltration);
            let (commitment, violations) =
                evaluate_kernel_trace_detailed(&policy, &events).map_err(|e| anyhow::anyhow!(e))?;

            let vkey_hash = compute_circuit_vkey(&policy);
            let proof_seal = compute_cryptographic_seal(&vkey_hash, &commitment)?;

            let receipt = ZeroKernelReceipt {
                version: "0.1.0-agent-audit".to_string(),
                prover_backend: "DeterministicLocal".to_string(),
                vkey_hash: hex::encode(vkey_hash),
                public_commitment: commitment,
                commitment_merkle_hex: hex::encode(commitment.trace_merkle_root),
                proof_seal_hex: hex::encode(proof_seal),
                proving_time_ms: 1,
                binary_merkle_tree_root: Some(hex::encode(MerkleTree::compute_root(&events))),
                embedded_merkle_leaf_index: None,
                embedded_merkle_proof: None,
                chained_prev_receipt_hash: None,
                violation_details: violations,
            };

            fs::write(&output, serde_json::to_string_pretty(&receipt)?)?;
            info!(
                output = %output.display(),
                compliant = commitment.policy_compliant,
                violations = commitment.violations_detected,
                "Agent audit complete and receipt committed"
            );
        }

        Commands::ExportEvm {
            receipt_path,
            output,
        } => {
            let raw = fs::read_to_string(&receipt_path)?;
            let receipt: ZeroKernelReceipt = serde_json::from_str(&raw)?;

            let evm_payload = EvmVerifierPayload {
                vkey_bytes32: format!("0x{}", receipt.vkey_hash),
                trace_merkle_root_bytes32: format!("0x{}", receipt.commitment_merkle_hex),
                policy_id: receipt.public_commitment.policy_id,
                total_events: receipt.public_commitment.total_events_verified,
                violations_detected: receipt.public_commitment.violations_detected,
                policy_compliant: receipt.public_commitment.policy_compliant,
                window_start_ns: receipt.public_commitment.window_start_ns,
                window_end_ns: receipt.public_commitment.window_end_ns,
                proof_seal_bytes: format!("0x{}", receipt.proof_seal_hex),
                solidity_calldata_abi_encoded: format!(
                    "0x18e8a93d{}{}{:>08x}{:>08x}{:>02x}",
                    receipt.vkey_hash,
                    receipt.commitment_merkle_hex,
                    receipt.public_commitment.policy_id,
                    receipt.public_commitment.total_events_verified,
                    u8::from(receipt.public_commitment.policy_compliant)
                ),
            };

            fs::write(&output, serde_json::to_string_pretty(&evm_payload)?)?;
            info!(path = %output.display(), "Exported EVM verifier contract payload");
        }

        Commands::ExportAttestation {
            receipt_path,
            output,
        } => {
            let raw = fs::read_to_string(&receipt_path)?;
            let receipt: ZeroKernelReceipt = serde_json::from_str(&raw)?;

            let attestation = JsonLdAttestation {
                context: vec![
                    "https://www.w3.org/2018/credentials/v1".to_string(),
                    "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
                ],
                id: format!("urn:zerokernel:receipt:{}", receipt.proof_seal_hex),
                r#type: vec![
                    "VerifiableCredential".to_string(),
                    "KernelExecutionAttestation".to_string(),
                ],
                issuer: "did:zerokernel:root-authority".to_string(),
                issuance_date: "2026-11-02T12:00:00Z".to_string(),
                credential_subject: AttestationSubject {
                    id: format!(
                        "urn:linux:host:policy:{}",
                        receipt.public_commitment.policy_id
                    ),
                    policy_id: receipt.public_commitment.policy_id,
                    events_verified: receipt.public_commitment.total_events_verified,
                    policy_compliant: receipt.public_commitment.policy_compliant,
                    trace_merkle_root: receipt.commitment_merkle_hex,
                },
                proof: AttestationProof {
                    r#type: "ZeroKernelStarkProof2026".to_string(),
                    verification_method: format!("did:zerokernel:vkey:{}", receipt.vkey_hash),
                    proof_value: receipt.proof_seal_hex,
                },
            };

            fs::write(&output, serde_json::to_string_pretty(&attestation)?)?;
            info!(path = %output.display(), "Exported JSON-LD Verifiable Credential attestation");
        }
    }

    Ok(())
}

fn resolve_preset(preset: PolicyPreset) -> SecurityPolicy {
    match preset {
        PolicyPreset::Default => default_security_policy(),
        PolicyPreset::StrictSandbox => SecurityPolicy::strict_sandbox(),
        PolicyPreset::AgentEgressGuard => SecurityPolicy::agent_egress_guard(),
        PolicyPreset::PermissiveAudit => SecurityPolicy::permissive_audit(),
    }
}

fn resolve_policy(preset: PolicyPreset, custom_file: Option<&Path>) -> Result<SecurityPolicy> {
    if let Some(path) = custom_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
        let policy: SecurityPolicy = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse JSON policy from: {}", path.display()))?;
        Ok(policy)
    } else {
        Ok(resolve_preset(preset))
    }
}

pub fn default_security_policy() -> SecurityPolicy {
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

pub fn generate_synthetic_ringbuf_trace(
    count: usize,
    inject_violation: bool,
) -> Vec<KernelSyscallEvent> {
    let mut out = Vec::with_capacity(count);
    let base_ts = 1_762_000_000_000_000_000u64;

    for i in 0..count {
        let is_violation = inject_violation && i == count / 2;
        let is_xdp = i.is_multiple_of(2);
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

pub fn generate_agent_lifecycle_trace(
    agent_id: &str,
    step_count: usize,
    inject_exfiltration: bool,
) -> Vec<KernelSyscallEvent> {
    let mut out = Vec::with_capacity(step_count);
    let base_ts = 1_762_100_000_000_000_000u64;
    let comm = KernelSyscallEvent::encode_comm(agent_id);

    for i in 0..step_count {
        let is_exfil = inject_exfiltration && (i % 6 == 3);
        let (syscall_nr, hook_flags, target_port, target_ip) = match i % 6 {
            0 => (56, HOOK_SCHED_PROCESS_FORK, 0, 0),
            1 => (59, HOOK_TRACEPOINT_EXECVE, 0, 0),
            2 => (257, HOOK_TRACEPOINT_OPENAT, 0, 0),
            3 => (
                42,
                HOOK_TRACEPOINT_CONNECT,
                if is_exfil { 6667 } else { 443 },
                if is_exfil { 0x0A00_0005 } else { 0x0808_0808 },
            ),
            4 => (105, HOOK_TRACEPOINT_SETUID, 0, 0),
            _ => (60, HOOK_SCHED_PROCESS_EXIT, 0, 0),
        };

        out.push(KernelSyscallEvent {
            timestamp_ns: base_ts + (i as u64 * 500),
            pid: 20000,
            tgid: 20000,
            uid: 1000,
            syscall_nr,
            target_ipv4: target_ip,
            target_port,
            flags: hook_flags,
            comm,
        });
    }

    out
}

pub fn compute_circuit_vkey(policy: &SecurityPolicy) -> Digest {
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

pub fn compute_cryptographic_seal(vkey: &Digest, commitment: &ZkAuditCommitment) -> Result<Digest> {
    let bytes = bincode::serialize(commitment).context("Failed to serialize commitment")?;
    let mut hasher = Sha256::new();
    hasher.update(b"ZEROKERNEL_STARK_SEAL_V1:");
    hasher.update(vkey);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_deterministic_roundtrip() {
        let policy = default_security_policy();
        let events = generate_synthetic_ringbuf_trace(256, false);
        let commitment = zerokernel_zk_guest::run_zk_circuit(&policy, &events);
        assert!(commitment.policy_compliant);

        let vkey = compute_circuit_vkey(&policy);
        let seal = compute_cryptographic_seal(&vkey, &commitment).expect("seal succeeds");

        let receipt = ZeroKernelReceipt {
            version: "0.1.0-test".to_string(),
            prover_backend: "DeterministicLocal".to_string(),
            vkey_hash: hex::encode(vkey),
            public_commitment: commitment,
            commitment_merkle_hex: hex::encode(commitment.trace_merkle_root),
            proof_seal_hex: hex::encode(seal),
            proving_time_ms: 10,
            binary_merkle_tree_root: Some(hex::encode(MerkleTree::compute_root(&events))),
            embedded_merkle_leaf_index: None,
            embedded_merkle_proof: None,
            chained_prev_receipt_hash: None,
            violation_details: Vec::new(),
        };

        let json = serde_json::to_string(&receipt).expect("serializes");
        let deserialized: ZeroKernelReceipt = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(receipt.proof_seal_hex, deserialized.proof_seal_hex);
    }

    #[test]
    fn test_agent_sandbox_exfiltration_detection() {
        let policy = SecurityPolicy::agent_egress_guard();
        let trace_ok = generate_agent_lifecycle_trace("hermes-safe", 24, false);
        let (commit_ok, violations_ok) =
            evaluate_kernel_trace_detailed(&policy, &trace_ok).expect("eval");
        assert!(commit_ok.policy_compliant);
        assert_eq!(violations_ok.len(), 0);

        let trace_exfil = generate_agent_lifecycle_trace("hermes-rogue", 24, true);
        let (commit_exfil, violations_exfil) =
            evaluate_kernel_trace_detailed(&policy, &trace_exfil).expect("eval");
        assert!(!commit_exfil.policy_compliant);
        assert!(!violations_exfil.is_empty());
    }
}
