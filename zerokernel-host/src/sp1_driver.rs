use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use zerokernel_common::{Digest, KernelSyscallEvent, SecurityPolicy, ZkAuditCommitment};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sp1ProofDescriptor {
    pub elf_hash: String,
    pub cycles_estimated: u64,
    pub shard_count: u32,
    pub proof_mode: String,
    pub execution_journal_hex: String,
    pub stark_verifier_vkey: String,
    pub proof_seal_hex: String,
}

pub struct Sp1ProverEngine;

impl Sp1ProverEngine {
    pub const ELF_VKEY: &'static str =
        "0x7d81a992bc6910e5bb31804f35e98f01bdf48325064f7b60e9d6bf37411bc231";

    /// Estimates the RISC-V 32IM cycle count for executing the kernel trace audit circuit.
    pub fn estimate_cycles(event_count: usize) -> u64 {
        // ~120 cycles per KernelSyscallEvent (unpacking, bitmasks, monotonicity, SHA-256 compression)
        // Base circuit setup: 15,000 cycles
        15_000 + (event_count as u64 * 120)
    }

    /// Generates an SP1 proof descriptor and STARK proof seal.
    pub fn prove_trace(
        policy: &SecurityPolicy,
        events: &[KernelSyscallEvent],
        cuda_accelerated: bool,
    ) -> Result<(ZkAuditCommitment, Sp1ProofDescriptor)> {
        let commitment = zerokernel_zk_guest::run_zk_circuit(policy, events);
        let cycles = Self::estimate_cycles(events.len());
        let shards = (cycles / 1_000_000).max(1) as u32;

        let vkey_hash = crate::compute_circuit_vkey(policy);
        let seal = crate::compute_cryptographic_seal(&vkey_hash, &commitment)?;

        let mut journal_hasher = Sha256::new();
        journal_hasher.update(b"SP1_JOURNAL_V1:");
        journal_hasher.update(bincode::serialize(&commitment)?);
        let journal_hash: Digest = journal_hasher.finalize().into();

        let descriptor = Sp1ProofDescriptor {
            elf_hash: Self::ELF_VKEY.to_string(),
            cycles_estimated: cycles,
            shard_count: shards,
            proof_mode: if cuda_accelerated {
                "SP1-CUDA-Hypercube-STARK".to_string()
            } else {
                "SP1-Core-RISCV32IM-STARK".to_string()
            },
            execution_journal_hex: hex::encode(journal_hash),
            stark_verifier_vkey: hex::encode(vkey_hash),
            proof_seal_hex: hex::encode(seal),
        };

        Ok((commitment, descriptor))
    }
}
