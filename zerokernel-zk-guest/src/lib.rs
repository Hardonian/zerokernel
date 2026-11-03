#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zerokernel_common::{
    aggregate_receipt_commitments, aggregate_receipt_commitments_tree, evaluate_kernel_trace,
    evaluate_kernel_trace_detailed, AuditViolationRecord, CircuitErrorCode, Digest,
    KernelSyscallEvent, MerkleProof, MerkleTree, SecurityPolicy, ZkAggregateCommitment,
    ZkAuditCommitment,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkCircuitInput {
    pub policy: SecurityPolicy,
    pub events: Vec<KernelSyscallEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkCircuitOutput {
    pub commitment: ZkAuditCommitment,
    pub merkle_tree_root: Digest,
    pub violation_count: u32,
}

/// Executes the core RISC-V zero-knowledge circuit for Linux kernel trace audit.
/// Panics if circuit invariants (monotonic clock, batch bounds) are violated.
pub fn run_zk_circuit(policy: &SecurityPolicy, events: &[KernelSyscallEvent]) -> ZkAuditCommitment {
    evaluate_kernel_trace(policy, events)
        .expect("Circuit invariant violated: trace exceeded bounds or non-monotonic clock")
}

/// Runs the circuit and returns both the public commitment and the full binary Merkle tree root.
pub fn run_zk_circuit_with_merkle(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
) -> ZkCircuitOutput {
    let commitment = run_zk_circuit(policy, events);
    let merkle_tree_root = MerkleTree::compute_root(events);
    ZkCircuitOutput {
        commitment,
        merkle_tree_root,
        violation_count: commitment.violations_detected,
    }
}

/// Detailed circuit execution that captures fine-grained violation records.
pub fn run_zk_circuit_detailed(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
) -> (ZkAuditCommitment, Vec<AuditViolationRecord>) {
    evaluate_kernel_trace_detailed(policy, events)
        .expect("Circuit invariant violated: trace exceeded bounds or non-monotonic clock")
}

/// Proves that a specific syscall event is present in the committed trace at leaf_index.
pub fn verify_subtrace_membership(
    merkle_root: &Digest,
    event: &KernelSyscallEvent,
    proof: &MerkleProof,
) -> bool {
    let leaf_hash = MerkleTree::compute_leaf_hash(event);
    MerkleTree::verify_proof(merkle_root, &leaf_hash, proof)
}

/// Executes recursive verification and aggregation over multiple trace window commitments.
pub fn run_recursive_aggregate_circuit(commitments: &[ZkAuditCommitment]) -> ZkAggregateCommitment {
    aggregate_receipt_commitments(commitments).expect(
        "Aggregate circuit invariant violated: mismatched policies or non-monotonic windows",
    )
}

/// Executes hierarchical tree-based recursive aggregation over constituent window commitments.
pub fn run_recursive_aggregate_circuit_tree(
    commitments: &[ZkAuditCommitment],
) -> ZkAggregateCommitment {
    aggregate_receipt_commitments_tree(commitments)
        .expect("Aggregate tree circuit invariant violated")
}

/// Runs the circuit with zero-knowledge sensitive command scrubbing.
pub fn run_zk_circuit_sanitized(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
    scrub_command: bool,
) -> ZkCircuitOutput {
    if !scrub_command {
        return run_zk_circuit_with_merkle(policy, events);
    }

    let sanitized_events: Vec<KernelSyscallEvent> = events
        .iter()
        .map(|e| {
            let mut sanitized = *e;
            sanitized.comm = [0u8; 16]; // scrub command string in zero knowledge
            sanitized
        })
        .collect();

    run_zk_circuit_with_merkle(policy, &sanitized_events)
}

/// Runs the circuit and validates maximum clock drift between consecutive events.
pub fn run_zk_circuit_with_drift_check(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
    max_drift_ns: u64,
) -> Result<ZkCircuitOutput, CircuitErrorCode> {
    if events.is_empty() {
        return Ok(run_zk_circuit_with_merkle(policy, events));
    }

    let mut prev_ts = events[0].timestamp_ns;
    for event in &events[1..] {
        if event.timestamp_ns < prev_ts {
            return Err(CircuitErrorCode::NonMonotonicClock);
        }
        if event.timestamp_ns.saturating_sub(prev_ts) > max_drift_ns {
            return Err(CircuitErrorCode::MaxClockDriftExceeded);
        }
        prev_ts = event.timestamp_ns;
    }

    Ok(run_zk_circuit_with_merkle(policy, events))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_circuit_execution() {
        let policy = SecurityPolicy::strict_sandbox();
        let events = [KernelSyscallEvent {
            timestamp_ns: 1_000_000,
            pid: 4000,
            tgid: 4000,
            uid: 1000,
            syscall_nr: 1, // sys_write
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: KernelSyscallEvent::encode_comm("hermes"),
        }];

        let commitment = run_zk_circuit(&policy, &events);
        assert!(commitment.policy_compliant);
        assert_eq!(commitment.total_events_verified, 1);
        assert_eq!(commitment.violations_detected, 0);

        let output = run_zk_circuit_with_merkle(&policy, &events);
        assert_eq!(output.commitment.policy_id, policy.policy_id);
        assert_ne!(output.merkle_tree_root, [0u8; 32]);
    }

    #[test]
    fn test_guest_subtrace_membership() {
        let policy = SecurityPolicy::permissive_audit();
        let events: Vec<KernelSyscallEvent> = (0..4)
            .map(|i| KernelSyscallEvent {
                timestamp_ns: 2_000_000 + i as u64,
                pid: 5000 + i as u32,
                tgid: 5000,
                uid: 1000,
                syscall_nr: 1,
                target_ipv4: 0,
                target_port: 0,
                flags: 0,
                comm: KernelSyscallEvent::encode_comm("agent"),
            })
            .collect();

        let output = run_zk_circuit_with_merkle(&policy, &events);
        let proof = MerkleTree::generate_proof(&events, 2).expect("proof generated");
        let valid = verify_subtrace_membership(&output.merkle_tree_root, &events[2], &proof);
        assert!(valid);
    }

    #[test]
    fn test_guest_recursive_aggregation() {
        let policy = SecurityPolicy::permissive_audit();
        let events1 = [KernelSyscallEvent {
            timestamp_ns: 100,
            pid: 1,
            tgid: 1,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: [0; 16],
        }];
        let events2 = [KernelSyscallEvent {
            timestamp_ns: 200,
            pid: 1,
            tgid: 1,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: [0; 16],
        }];

        let c1 = run_zk_circuit(&policy, &events1);
        let c2 = run_zk_circuit(&policy, &events2);

        let agg = run_recursive_aggregate_circuit(&[c1, c2]);
        assert_eq!(agg.total_windows, 2);
        assert_eq!(agg.total_events_verified, 2);
        assert!(agg.all_windows_compliant);

        let agg_tree = run_recursive_aggregate_circuit_tree(&[c1, c2]);
        assert_eq!(agg_tree.total_windows, 2);
    }

    #[test]
    fn test_sanitized_and_drift_circuits() {
        let policy = SecurityPolicy::permissive_audit();
        let e1 = KernelSyscallEvent {
            timestamp_ns: 1000,
            pid: 1,
            tgid: 1,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: KernelSyscallEvent::encode_comm("secret-pass"),
        };
        let e2 = KernelSyscallEvent {
            timestamp_ns: 1500,
            pid: 1,
            tgid: 1,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: KernelSyscallEvent::encode_comm("secret-pass"),
        };

        let sanitized = run_zk_circuit_sanitized(&policy, &[e1], true);
        assert!(sanitized.commitment.policy_compliant);

        // Drift check ok
        let drift_ok = run_zk_circuit_with_drift_check(&policy, &[e1, e2], 1000);
        assert!(drift_ok.is_ok());

        // Drift check exceeded
        let drift_fail = run_zk_circuit_with_drift_check(&policy, &[e1, e2], 200);
        assert_eq!(
            drift_fail.unwrap_err(),
            CircuitErrorCode::MaxClockDriftExceeded
        );
    }
}
