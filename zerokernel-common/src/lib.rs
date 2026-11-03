#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

pub type Digest = [u8; 32];
pub const MAX_BATCH_EVENTS: usize = 65_536;

// Ring-0 eBPF tracepoint & probe hook identifiers
pub const HOOK_TRACEPOINT_EXECVE: u16 = 0x0001;
pub const HOOK_XDP_IPV4_PACKET: u16 = 0x0002;
pub const HOOK_TRACEPOINT_OPENAT: u16 = 0x0004;
pub const HOOK_TRACEPOINT_CONNECT: u16 = 0x0008;
pub const HOOK_TRACEPOINT_SETUID: u16 = 0x0010;
pub const HOOK_SCHED_PROCESS_FORK: u16 = 0x0020;
pub const HOOK_SCHED_PROCESS_EXIT: u16 = 0x0040;
pub const HOOK_XDP_IPV6_PACKET: u16 = 0x0100;

// Security invariant audit flags
pub const FLAG_ROOT_PRIVILEGE: u16 = 0x0080;
pub const FLAG_EGRESS_BLOCKED: u16 = 0x0200;
pub const FLAG_ANOMALOUS_BURST: u16 = 0x0400;
pub const FLAG_SENSITIVE_FS_ACCESS: u16 = 0x0800;
pub const FLAG_CONTAINER_ESCAPE: u16 = 0x1000;

// Violation taxonomy codes
pub const VIOLATION_CODE_UNAUTHORIZED_ROOT: u32 = 1;
pub const VIOLATION_CODE_FORBIDDEN_SYSCALL: u32 = 2;
pub const VIOLATION_CODE_FORBIDDEN_IPV4_EGRESS: u32 = 3;
pub const VIOLATION_CODE_FORBIDDEN_PORT: u32 = 4;
pub const VIOLATION_CODE_SENSITIVE_FS: u32 = 5;
pub const VIOLATION_CODE_NON_MONOTONIC_CLOCK: u32 = 6;

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSyscallEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub syscall_nr: u32,
    pub target_ipv4: u32,
    pub target_port: u16,
    pub flags: u16,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub policy_id: u32,
    pub forbidden_syscall_mask: u64,
    pub forbidden_ipv4_subnet: u32,
    pub forbidden_ipv4_mask: u32,
    pub forbidden_port: u16,
    pub allow_root_execution: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedSecurityPolicy {
    pub base: SecurityPolicy,
    pub forbidden_syscall_bitmap: [u64; 8],
    pub allowed_port_min: u16,
    pub allowed_port_max: u16,
    pub max_burst_events_per_sec: u32,
    pub enforce_strict_monotonicity: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAuditCommitment {
    pub policy_id: u32,
    pub total_events_verified: u32,
    pub violations_detected: u32,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub trace_merkle_root: Digest,
    pub policy_compliant: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAggregateCommitment {
    pub policy_id: u32,
    pub total_windows: u32,
    pub total_events_verified: u64,
    pub total_violations_detected: u64,
    pub global_window_start_ns: u64,
    pub global_window_end_ns: u64,
    pub super_merkle_root: Digest,
    pub all_windows_compliant: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditViolationRecord {
    pub event_index: u32,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub syscall_nr: u32,
    pub target_ipv4: u32,
    pub target_port: u16,
    pub violation_code: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub total_leaves: u32,
    pub sibling_hashes: Vec<Digest>,
}

impl KernelSyscallEvent {
    #[inline(always)]
    pub fn to_fixed_bytes(&self) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        buf[8..12].copy_from_slice(&self.pid.to_le_bytes());
        buf[12..16].copy_from_slice(&self.tgid.to_le_bytes());
        buf[16..20].copy_from_slice(&self.uid.to_le_bytes());
        buf[20..24].copy_from_slice(&self.syscall_nr.to_le_bytes());
        buf[24..28].copy_from_slice(&self.target_ipv4.to_le_bytes());
        buf[28..30].copy_from_slice(&self.target_port.to_le_bytes());
        buf[30..32].copy_from_slice(&self.flags.to_le_bytes());
        buf[32..48].copy_from_slice(&self.comm);
        buf
    }

    pub fn encode_comm(name: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let bytes = name.as_bytes();
        let len = if bytes.len() > 15 { 15 } else { bytes.len() };
        out[..len].copy_from_slice(&bytes[..len]);
        out
    }

    pub fn comm_as_str(&self) -> &str {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..len]).unwrap_or("<non-utf8>")
    }

    pub fn is_execve(&self) -> bool {
        (self.flags & HOOK_TRACEPOINT_EXECVE) != 0
    }

    pub fn is_xdp(&self) -> bool {
        (self.flags & HOOK_XDP_IPV4_PACKET) != 0 || (self.flags & HOOK_XDP_IPV6_PACKET) != 0
    }

    pub fn is_openat(&self) -> bool {
        (self.flags & HOOK_TRACEPOINT_OPENAT) != 0
    }

    pub fn is_connect(&self) -> bool {
        (self.flags & HOOK_TRACEPOINT_CONNECT) != 0
    }

    pub fn is_setuid(&self) -> bool {
        (self.flags & HOOK_TRACEPOINT_SETUID) != 0
    }

    pub fn is_sensitive_fs(&self) -> bool {
        (self.flags & FLAG_SENSITIVE_FS_ACCESS) != 0
    }

    pub fn is_container_escape(&self) -> bool {
        (self.flags & FLAG_CONTAINER_ESCAPE) != 0
    }

    pub fn mark_sensitive_fs(&mut self) {
        self.flags |= FLAG_SENSITIVE_FS_ACCESS;
    }

    pub fn mark_container_escape(&mut self) {
        self.flags |= FLAG_CONTAINER_ESCAPE;
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0 || (self.flags & FLAG_ROOT_PRIVILEGE) != 0
    }
}

impl SecurityPolicy {
    pub const fn strict_sandbox() -> Self {
        Self {
            policy_id: 1001,
            forbidden_syscall_mask: (1u64 << 59) | (1u64 << 42), // execve (59), connect (42)
            forbidden_ipv4_subnet: 0x0A00_0000,                  // 10.0.0.0/8
            forbidden_ipv4_mask: 0xFF00_0000,
            forbidden_port: 4444,
            allow_root_execution: false,
        }
    }

    pub const fn agent_egress_guard() -> Self {
        Self {
            policy_id: 2002,
            forbidden_syscall_mask: 0,
            forbidden_ipv4_subnet: 0x0A00_0000, // 10.0.0.0/8
            forbidden_ipv4_mask: 0xFF00_0000,
            forbidden_port: 6667, // IRC/C2 exfiltration
            allow_root_execution: false,
        }
    }

    pub const fn permissive_audit() -> Self {
        Self {
            policy_id: 3003,
            forbidden_syscall_mask: 0,
            forbidden_ipv4_subnet: 0,
            forbidden_ipv4_mask: 0,
            forbidden_port: 0,
            allow_root_execution: true,
        }
    }

    #[inline(always)]
    pub fn is_syscall_forbidden(&self, syscall_nr: u32) -> bool {
        if syscall_nr < 64 {
            let bit = 1u64 << syscall_nr;
            (self.forbidden_syscall_mask & bit) != 0
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn is_ipv4_forbidden(&self, ip: u32) -> bool {
        if self.forbidden_ipv4_mask != 0 && ip != 0 {
            (ip & self.forbidden_ipv4_mask)
                == (self.forbidden_ipv4_subnet & self.forbidden_ipv4_mask)
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn is_port_forbidden(&self, port: u16) -> bool {
        self.forbidden_port != 0 && port == self.forbidden_port
    }

    #[inline(always)]
    pub fn check_event(&self, event: &KernelSyscallEvent) -> (bool, Option<u32>) {
        if !self.allow_root_execution && event.is_root() {
            return (true, Some(VIOLATION_CODE_UNAUTHORIZED_ROOT));
        }

        if self.is_syscall_forbidden(event.syscall_nr) {
            return (true, Some(VIOLATION_CODE_FORBIDDEN_SYSCALL));
        }

        if self.is_ipv4_forbidden(event.target_ipv4) {
            return (true, Some(VIOLATION_CODE_FORBIDDEN_IPV4_EGRESS));
        }

        if self.is_port_forbidden(event.target_port) {
            return (true, Some(VIOLATION_CODE_FORBIDDEN_PORT));
        }

        if (event.flags & FLAG_SENSITIVE_FS_ACCESS) != 0 {
            return (true, Some(VIOLATION_CODE_SENSITIVE_FS));
        }

        (false, None)
    }
}

impl ExtendedSecurityPolicy {
    pub fn from_base(base: SecurityPolicy) -> Self {
        let mut bitmap = [0u64; 8];
        bitmap[0] = base.forbidden_syscall_mask;
        Self {
            base,
            forbidden_syscall_bitmap: bitmap,
            allowed_port_min: 1,
            allowed_port_max: 65535,
            max_burst_events_per_sec: 1_000_000,
            enforce_strict_monotonicity: true,
        }
    }

    pub fn forbid_syscall(&mut self, syscall_nr: u32) {
        let word_idx = (syscall_nr / 64) as usize;
        let bit_idx = syscall_nr % 64;
        if word_idx < 8 {
            self.forbidden_syscall_bitmap[word_idx] |= 1u64 << bit_idx;
            if word_idx == 0 {
                self.base.forbidden_syscall_mask |= 1u64 << bit_idx;
            }
        }
    }

    pub fn is_syscall_forbidden(&self, syscall_nr: u32) -> bool {
        let word_idx = (syscall_nr / 64) as usize;
        let bit_idx = syscall_nr % 64;
        if word_idx < 8 {
            (self.forbidden_syscall_bitmap[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        }
    }
}

pub struct MerkleTree;

impl MerkleTree {
    pub fn compute_leaf_hash(event: &KernelSyscallEvent) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"ZK_LEAF_V1:");
        hasher.update(event.to_fixed_bytes());
        hasher.finalize().into()
    }

    pub fn combine_hashes(left: &Digest, right: &Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"ZK_NODE_V1:");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    pub fn compute_root(events: &[KernelSyscallEvent]) -> Digest {
        if events.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"ZK_EMPTY_TREE_V1");
            return hasher.finalize().into();
        }

        let current_layer: Vec<Digest> = events.iter().map(Self::compute_leaf_hash).collect();
        Self::compute_root_from_hashes(&current_layer)
    }

    pub fn compute_root_from_hashes(hashes: &[Digest]) -> Digest {
        if hashes.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"ZK_EMPTY_TREE_V1");
            return hasher.finalize().into();
        }

        let mut current_layer: Vec<Digest> = hashes.to_vec();

        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity(current_layer.len().div_ceil(2));
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(Self::combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    next_layer.push(Self::combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            current_layer = next_layer;
        }

        current_layer[0]
    }

    pub fn generate_proof(events: &[KernelSyscallEvent], leaf_index: usize) -> Option<MerkleProof> {
        if events.is_empty() || leaf_index >= events.len() {
            return None;
        }

        let total_leaves = events.len() as u32;
        let mut siblings = Vec::new();
        let mut current_layer: Vec<Digest> = events.iter().map(Self::compute_leaf_hash).collect();
        let mut current_idx = leaf_index;

        while current_layer.len() > 1 {
            let sibling_idx = if current_idx.is_multiple_of(2) {
                if current_idx + 1 < current_layer.len() {
                    current_idx + 1
                } else {
                    current_idx
                }
            } else {
                current_idx - 1
            };

            siblings.push(current_layer[sibling_idx]);

            let mut next_layer = Vec::with_capacity(current_layer.len().div_ceil(2));
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(Self::combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    next_layer.push(Self::combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            current_idx /= 2;
            current_layer = next_layer;
        }

        Some(MerkleProof {
            leaf_index: leaf_index as u32,
            total_leaves,
            sibling_hashes: siblings,
        })
    }

    pub fn verify_proof(root: &Digest, leaf_hash: &Digest, proof: &MerkleProof) -> bool {
        let mut current = *leaf_hash;
        let mut idx = proof.leaf_index as usize;

        for sibling in &proof.sibling_hashes {
            if idx.is_multiple_of(2) {
                current = Self::combine_hashes(&current, sibling);
            } else {
                current = Self::combine_hashes(sibling, &current);
            }
            idx /= 2;
        }

        current == *root
    }
}

pub fn evaluate_kernel_trace(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
) -> Result<ZkAuditCommitment, &'static str> {
    let (commitment, _violations) = evaluate_kernel_trace_detailed(policy, events)?;
    Ok(commitment)
}

pub fn evaluate_kernel_trace_detailed(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
) -> Result<(ZkAuditCommitment, Vec<AuditViolationRecord>), &'static str> {
    if events.len() > MAX_BATCH_EVENTS {
        return Err("Kernel trace exceeds MAX_BATCH_EVENTS circuit ceiling");
    }

    let mut rolling_hash: Digest = [0u8; 32];
    let mut violations_count: u32 = 0;
    let mut violation_records = Vec::new();
    let mut window_start = u64::MAX;
    let mut window_end = 0u64;
    let mut prev_ts = 0u64;

    for (idx, event) in events.iter().enumerate() {
        if event.timestamp_ns < prev_ts {
            return Err("Non-monotonic kernel timestamp detected in trace");
        }
        prev_ts = event.timestamp_ns;

        if event.timestamp_ns < window_start {
            window_start = event.timestamp_ns;
        }
        if event.timestamp_ns > window_end {
            window_end = event.timestamp_ns;
        }

        let (violated, code_opt) = policy.check_event(event);

        if violated {
            violations_count = violations_count.saturating_add(1);
            if let Some(code) = code_opt {
                violation_records.push(AuditViolationRecord {
                    event_index: idx as u32,
                    timestamp_ns: event.timestamp_ns,
                    pid: event.pid,
                    syscall_nr: event.syscall_nr,
                    target_ipv4: event.target_ipv4,
                    target_port: event.target_port,
                    violation_code: code,
                });
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(rolling_hash);
        hasher.update(event.to_fixed_bytes());
        rolling_hash = hasher.finalize().into();
    }

    if events.is_empty() {
        window_start = 0;
    }

    let commitment = ZkAuditCommitment {
        policy_id: policy.policy_id,
        total_events_verified: events.len() as u32,
        violations_detected: violations_count,
        window_start_ns: window_start,
        window_end_ns: window_end,
        trace_merkle_root: rolling_hash,
        policy_compliant: violations_count == 0,
    };

    Ok((commitment, violation_records))
}

pub fn aggregate_receipt_commitments(
    commitments: &[ZkAuditCommitment],
) -> Result<ZkAggregateCommitment, &'static str> {
    if commitments.is_empty() {
        return Err("Cannot aggregate empty commitment sequence");
    }

    let policy_id = commitments[0].policy_id;
    let mut total_events: u64 = 0;
    let mut total_violations: u64 = 0;
    let mut all_compliant = true;
    let global_start = commitments[0].window_start_ns;
    let mut global_end = commitments[0].window_end_ns;
    let mut prev_start = commitments[0].window_start_ns;
    let mut roots = Vec::with_capacity(commitments.len());

    for (i, c) in commitments.iter().enumerate() {
        if c.policy_id != policy_id {
            return Err("Mismatched policy_id across aggregated receipt windows");
        }
        if i > 0 && c.window_start_ns < prev_start {
            return Err("Non-monotonic window sequence detected in recursive aggregation");
        }
        prev_start = c.window_start_ns;
        if c.window_end_ns > global_end {
            global_end = c.window_end_ns;
        }

        total_events = total_events.saturating_add(c.total_events_verified as u64);
        total_violations = total_violations.saturating_add(c.violations_detected as u64);
        if !c.policy_compliant {
            all_compliant = false;
        }

        roots.push(c.trace_merkle_root);
    }

    let super_root = MerkleTree::compute_root_from_hashes(&roots);

    Ok(ZkAggregateCommitment {
        policy_id,
        total_windows: commitments.len() as u32,
        total_events_verified: total_events,
        total_violations_detected: total_violations,
        global_window_start_ns: global_start,
        global_window_end_ns: global_end,
        super_merkle_root: super_root,
        all_windows_compliant: all_compliant && total_violations == 0,
    })
}

#[inline(always)]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitErrorCode {
    Success = 0,
    UnauthorizedRoot = 1,
    ForbiddenSyscall = 2,
    ForbiddenIpv4Egress = 3,
    ForbiddenPort = 4,
    SensitiveFsAccess = 5,
    NonMonotonicClock = 6,
    TemporalDiscontinuity = 7,
    PolicyMismatch = 8,
    ProofSealMismatch = 9,
    BatchOverflow = 10,
    MaxClockDriftExceeded = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCombinator {
    All,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSecurityPolicy {
    pub composite_id: u32,
    pub combinator: PolicyCombinator,
    pub policies: Vec<SecurityPolicy>,
}

impl CompositeSecurityPolicy {
    pub fn is_event_compliant(&self, event: &KernelSyscallEvent) -> bool {
        match self.combinator {
            PolicyCombinator::All => self.policies.iter().all(|p| {
                let (c, _) = evaluate_kernel_trace_detailed(p, &[*event]).unwrap_or((
                    ZkAuditCommitment {
                        policy_id: p.policy_id,
                        total_events_verified: 1,
                        violations_detected: 1,
                        window_start_ns: event.timestamp_ns,
                        window_end_ns: event.timestamp_ns,
                        trace_merkle_root: [0; 32],
                        policy_compliant: false,
                    },
                    Vec::new(),
                ));
                c.policy_compliant
            }),
            PolicyCombinator::Any => self.policies.iter().any(|p| {
                let (c, _) = evaluate_kernel_trace_detailed(p, &[*event]).unwrap_or((
                    ZkAuditCommitment {
                        policy_id: p.policy_id,
                        total_events_verified: 1,
                        violations_detected: 1,
                        window_start_ns: event.timestamp_ns,
                        window_end_ns: event.timestamp_ns,
                        trace_merkle_root: [0; 32],
                        policy_compliant: false,
                    },
                    Vec::new(),
                ));
                c.policy_compliant
            }),
        }
    }
}

pub struct SparseMerkleTree;

impl SparseMerkleTree {
    pub const DEPTH: usize = 16;

    pub fn empty_hashes() -> [Digest; Self::DEPTH + 1] {
        let mut empty = [[0u8; 32]; Self::DEPTH + 1];
        let mut hasher = Sha256::new();
        hasher.update(b"SMT_EMPTY_LEAF_V1");
        empty[0] = hasher.finalize().into();

        for d in 1..=Self::DEPTH {
            empty[d] = MerkleTree::combine_hashes(&empty[d - 1], &empty[d - 1]);
        }
        empty
    }

    pub fn compute_leaf_hash(key: u32, value: &Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"SMT_LEAF_V1:");
        hasher.update(key.to_le_bytes());
        hasher.update(value);
        hasher.finalize().into()
    }

    pub fn verify_non_membership(root: &Digest, key: u32, siblings: &[Digest]) -> bool {
        if siblings.len() != Self::DEPTH {
            return false;
        }
        let empty_leaf = Self::empty_hashes()[0];
        let mut current = empty_leaf;
        let mut k = key;

        for sibling in siblings {
            if k.is_multiple_of(2) {
                current = MerkleTree::combine_hashes(&current, sibling);
            } else {
                current = MerkleTree::combine_hashes(sibling, &current);
            }
            k /= 2;
        }

        current == *root
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    pub leaf_indices: Vec<u32>,
    pub total_leaves: u32,
    pub proofs: Vec<MerkleProof>,
}

impl BatchMerkleProof {
    pub fn verify(&self, root: &Digest, leaf_hashes: &[Digest]) -> bool {
        if self.leaf_indices.len() != leaf_hashes.len() || self.proofs.len() != leaf_hashes.len() {
            return false;
        }
        for (i, leaf) in leaf_hashes.iter().enumerate() {
            if !MerkleTree::verify_proof(root, leaf, &self.proofs[i]) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleMountainRange {
    pub peaks: Vec<Digest>,
    pub count: u64,
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        Self {
            peaks: Vec::new(),
            count: 0,
        }
    }

    pub fn append(&mut self, leaf: Digest) {
        let mut current = leaf;
        let mut bit = 1u64;

        while (self.count & bit) != 0 {
            if let Some(prev) = self.peaks.pop() {
                current = MerkleTree::combine_hashes(&prev, &current);
            }
            bit <<= 1;
        }

        self.peaks.push(current);
        self.count = self.count.saturating_add(1);
    }

    pub fn get_bagged_peak(&self) -> Digest {
        if self.peaks.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"MMR_EMPTY_V1");
            return hasher.finalize().into();
        }

        let mut bagged = self.peaks[self.peaks.len() - 1];
        for peak in self.peaks.iter().rev().skip(1) {
            bagged = MerkleTree::combine_hashes(peak, &bagged);
        }
        bagged
    }
}

pub fn aggregate_receipt_commitments_tree(
    commitments: &[ZkAuditCommitment],
) -> Result<ZkAggregateCommitment, &'static str> {
    aggregate_receipt_commitments(commitments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_alignment_and_size() {
        assert_eq!(core::mem::size_of::<KernelSyscallEvent>(), 48);
        assert_eq!(core::mem::align_of::<KernelSyscallEvent>(), 8);
    }

    #[test]
    fn test_comm_encode_decode() {
        let encoded = KernelSyscallEvent::encode_comm("hermes-engine");
        let mut event = KernelSyscallEvent {
            timestamp_ns: 1_000,
            pid: 42,
            tgid: 42,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: HOOK_TRACEPOINT_EXECVE,
            comm: encoded,
        };
        assert_eq!(event.comm_as_str(), "hermes-engine");
        assert!(event.is_execve());
        assert!(!event.is_xdp());
        assert!(!event.is_root());

        event.uid = 0;
        assert!(event.is_root());
    }

    #[test]
    fn test_compliant_and_violating_traces() {
        let policy = SecurityPolicy {
            policy_id: 77,
            forbidden_syscall_mask: 1u64 << 42,
            forbidden_ipv4_subnet: 0x0A00_0000,
            forbidden_ipv4_mask: 0xFF00_0000,
            forbidden_port: 4444,
            allow_root_execution: false,
        };

        let ok_event = KernelSyscallEvent {
            timestamp_ns: 100,
            pid: 1234,
            tgid: 1234,
            uid: 1000,
            syscall_nr: 59,
            target_ipv4: 0x0101_0101,
            target_port: 443,
            flags: HOOK_TRACEPOINT_EXECVE,
            comm: KernelSyscallEvent::encode_comm("hermes-agent"),
        };

        let res = evaluate_kernel_trace(&policy, &[ok_event]).expect("evaluates");
        assert!(res.policy_compliant);
        assert_eq!(res.violations_detected, 0);

        let mut bad_event = ok_event;
        bad_event.timestamp_ns = 200;
        bad_event.target_port = 4444;
        let (res_bad, details) =
            evaluate_kernel_trace_detailed(&policy, &[ok_event, bad_event]).expect("evaluates");
        assert!(!res_bad.policy_compliant);
        assert_eq!(res_bad.violations_detected, 1);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].violation_code, VIOLATION_CODE_FORBIDDEN_PORT);
    }

    #[test]
    fn test_non_monotonic_clock_rejected() {
        let policy = SecurityPolicy {
            policy_id: 1,
            forbidden_syscall_mask: 0,
            forbidden_ipv4_subnet: 0,
            forbidden_ipv4_mask: 0,
            forbidden_port: 0,
            allow_root_execution: true,
        };
        let e1 = KernelSyscallEvent {
            timestamp_ns: 500,
            pid: 1,
            tgid: 1,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: [0; 16],
        };
        let mut e2 = e1;
        e2.timestamp_ns = 499;
        assert!(evaluate_kernel_trace(&policy, &[e1, e2]).is_err());
    }

    #[test]
    fn test_merkle_tree_proof_generation_and_verification() {
        let events: Vec<KernelSyscallEvent> = (0..8)
            .map(|i| KernelSyscallEvent {
                timestamp_ns: 1_000 + i as u64,
                pid: 100 + i as u32,
                tgid: 100,
                uid: 1000,
                syscall_nr: 59,
                target_ipv4: 0,
                target_port: 0,
                flags: HOOK_TRACEPOINT_EXECVE,
                comm: KernelSyscallEvent::encode_comm("proc"),
            })
            .collect();

        let root = MerkleTree::compute_root(&events);
        assert_ne!(root, [0u8; 32]);

        for i in 0..events.len() {
            let proof = MerkleTree::generate_proof(&events, i).expect("proof exists");
            let leaf_hash = MerkleTree::compute_leaf_hash(&events[i]);
            assert!(
                MerkleTree::verify_proof(&root, &leaf_hash, &proof),
                "Proof for leaf {} must verify",
                i
            );

            // Tamper test: wrong leaf hash must fail verification
            let bogus_leaf = [0xabu8; 32];
            assert!(
                !MerkleTree::verify_proof(&root, &bogus_leaf, &proof),
                "Tampered leaf must fail verification"
            );
        }
    }

    #[test]
    fn test_extended_security_policy_bitmaps() {
        let base = SecurityPolicy::strict_sandbox();
        let mut ext = ExtendedSecurityPolicy::from_base(base);

        // System call 257 (openat on x86_64)
        assert!(!ext.is_syscall_forbidden(257));
        ext.forbid_syscall(257);
        assert!(ext.is_syscall_forbidden(257));

        // System call 59 (execve in base)
        assert!(ext.is_syscall_forbidden(59));
    }

    #[test]
    fn test_sensitive_fs_access_violation() {
        let policy = SecurityPolicy::permissive_audit();
        let mut event = KernelSyscallEvent {
            timestamp_ns: 10_000,
            pid: 1234,
            tgid: 1234,
            uid: 1000,
            syscall_nr: 257, // openat
            target_ipv4: 0,
            target_port: 0,
            flags: HOOK_TRACEPOINT_OPENAT,
            comm: KernelSyscallEvent::encode_comm("shadow-stealer"),
        };
        event.mark_sensitive_fs();
        assert!(event.is_sensitive_fs());

        let (commitment, records) =
            evaluate_kernel_trace_detailed(&policy, &[event]).expect("evaluates");
        assert!(!commitment.policy_compliant);
        assert_eq!(commitment.violations_detected, 1);
        assert_eq!(records[0].violation_code, VIOLATION_CODE_SENSITIVE_FS);
    }

    #[test]
    fn test_recursive_commitment_aggregation() {
        let c1 = ZkAuditCommitment {
            policy_id: 100,
            total_events_verified: 1000,
            violations_detected: 0,
            window_start_ns: 10_000,
            window_end_ns: 20_000,
            trace_merkle_root: [1u8; 32],
            policy_compliant: true,
        };
        let c2 = ZkAuditCommitment {
            policy_id: 100,
            total_events_verified: 2000,
            violations_detected: 0,
            window_start_ns: 20_000,
            window_end_ns: 30_000,
            trace_merkle_root: [2u8; 32],
            policy_compliant: true,
        };

        let agg = aggregate_receipt_commitments(&[c1, c2]).expect("aggregates");
        assert_eq!(agg.policy_id, 100);
        assert_eq!(agg.total_windows, 2);
        assert_eq!(agg.total_events_verified, 3000);
        assert_eq!(agg.total_violations_detected, 0);
        assert!(agg.all_windows_compliant);
        assert_eq!(agg.global_window_start_ns, 10_000);
        assert_eq!(agg.global_window_end_ns, 30_000);
        assert_ne!(agg.super_merkle_root, [0u8; 32]);

        // Non-monotonic failure test
        let mut c_bad = c2;
        c_bad.window_start_ns = 5_000;
        assert!(aggregate_receipt_commitments(&[c1, c_bad]).is_err());
    }

    #[test]
    fn test_constant_time_eq_and_error_codes() {
        let a = [42u8; 32];
        let mut b = [42u8; 32];
        assert!(constant_time_eq_32(&a, &b));
        b[15] = 0;
        assert!(!constant_time_eq_32(&a, &b));

        assert_eq!(CircuitErrorCode::Success as u32, 0);
        assert_eq!(CircuitErrorCode::TemporalDiscontinuity as u32, 7);
    }

    #[test]
    fn test_composite_security_policy() {
        let p1 = SecurityPolicy::strict_sandbox();
        let p2 = SecurityPolicy::agent_egress_guard();

        let comp_all = CompositeSecurityPolicy {
            composite_id: 9001,
            combinator: PolicyCombinator::All,
            policies: alloc::vec![p1, p2],
        };

        let comp_any = CompositeSecurityPolicy {
            composite_id: 9002,
            combinator: PolicyCombinator::Any,
            policies: alloc::vec![p1, p2],
        };

        // Benign event (read operation, port 443)
        let benign = KernelSyscallEvent {
            timestamp_ns: 1000,
            pid: 10,
            tgid: 10,
            uid: 1000,
            syscall_nr: 257, // openat
            target_ipv4: 0x01010101,
            target_port: 443,
            flags: HOOK_TRACEPOINT_OPENAT,
            comm: [0; 16],
        };

        assert!(comp_all.is_event_compliant(&benign));
        assert!(comp_any.is_event_compliant(&benign));
    }

    #[test]
    fn test_sparse_merkle_tree_non_membership() {
        let empties = SparseMerkleTree::empty_hashes();
        let root = empties[SparseMerkleTree::DEPTH];
        let mut siblings = Vec::with_capacity(SparseMerkleTree::DEPTH);
        siblings.extend_from_slice(&empties[..SparseMerkleTree::DEPTH]);

        // An empty SMT verifies non-membership for any key
        assert!(SparseMerkleTree::verify_non_membership(
            &root, 42, &siblings
        ));

        // Wrong root fails
        let bogus_root = [99u8; 32];
        assert!(!SparseMerkleTree::verify_non_membership(
            &bogus_root,
            42,
            &siblings
        ));
    }

    #[test]
    fn test_batch_merkle_proof() {
        let events: Vec<KernelSyscallEvent> = (0..4)
            .map(|i| KernelSyscallEvent {
                timestamp_ns: 1_000 + i as u64,
                pid: 100 + i as u32,
                tgid: 100,
                uid: 1000,
                syscall_nr: 1,
                target_ipv4: 0,
                target_port: 0,
                flags: 0,
                comm: [0; 16],
            })
            .collect();

        let root = MerkleTree::compute_root(&events);
        let p0 = MerkleTree::generate_proof(&events, 0).expect("proof 0");
        let p2 = MerkleTree::generate_proof(&events, 2).expect("proof 2");

        let batch = BatchMerkleProof {
            leaf_indices: alloc::vec![0, 2],
            total_leaves: 4,
            proofs: alloc::vec![p0, p2],
        };

        let leaf0 = MerkleTree::compute_leaf_hash(&events[0]);
        let leaf2 = MerkleTree::compute_leaf_hash(&events[2]);

        assert!(batch.verify(&root, &[leaf0, leaf2]));

        // Tampered leaf fails batch
        assert!(!batch.verify(&root, &[leaf0, [0xff; 32]]));
    }

    #[test]
    fn test_merkle_mountain_range_lifecycle() {
        let mut mmr = MerkleMountainRange::new();
        assert_ne!(mmr.get_bagged_peak(), [0u8; 32]);

        for i in 0..10 {
            let mut leaf = [0u8; 32];
            leaf[0] = i as u8;
            mmr.append(leaf);
        }

        assert_eq!(mmr.count, 10);
        assert!(!mmr.peaks.is_empty());
        let peak1 = mmr.get_bagged_peak();
        assert_ne!(peak1, [0u8; 32]);

        mmr.append([0x77u8; 32]);
        assert_eq!(mmr.count, 11);
        let peak2 = mmr.get_bagged_peak();
        assert_ne!(peak1, peak2);
    }

    #[test]
    fn test_adversarial_red_team_suite() {
        // 1. Clock replay / backward jump attack
        let e1 = KernelSyscallEvent {
            timestamp_ns: 2_000_000,
            pid: 100,
            tgid: 100,
            uid: 1000,
            syscall_nr: 1,
            target_ipv4: 0,
            target_port: 0,
            flags: 0,
            comm: [0; 16],
        };
        let e_rewind = KernelSyscallEvent {
            timestamp_ns: 1_000_000, // rewound clock
            ..e1
        };
        assert!(e_rewind.timestamp_ns < e1.timestamp_ns);

        // 2. Merkle leaf forgery attempt with prefix manipulation
        let raw_bytes = [0x55u8; 32];
        let mut forged_input = Vec::new();
        forged_input.extend_from_slice(b"ZK_FAKE_V1:");
        forged_input.extend_from_slice(&raw_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&forged_input);
        let forged_hash: [u8; 32] = hasher.finalize().into();

        let honest_leaf = MerkleTree::compute_leaf_hash(&e1);
        assert!(!constant_time_eq_32(&forged_hash, &honest_leaf));

        // 3. Merkle path sibling corruption attack
        let events = alloc::vec![e1, e1];
        let root = MerkleTree::compute_root(&events);
        let mut proof = MerkleTree::generate_proof(&events, 0).expect("proof");
        assert!(MerkleTree::verify_proof(&root, &honest_leaf, &proof));
        proof.sibling_hashes[0][0] ^= 0x01; // flip 1 bit in sibling
        assert!(!MerkleTree::verify_proof(&root, &honest_leaf, &proof));

        // 4. Aggregate Rollup temporal non-monotonicity violation attack
        let win1 = ZkAuditCommitment {
            policy_id: 202601,
            total_events_verified: 100,
            violations_detected: 0,
            window_start_ns: 2_000,
            window_end_ns: 3_000,
            trace_merkle_root: [1u8; 32],
            policy_compliant: true,
        };
        let win2_rewound = ZkAuditCommitment {
            policy_id: 202601,
            total_events_verified: 100,
            violations_detected: 0,
            window_start_ns: 1_000, // rewound window start
            window_end_ns: 2_000,
            trace_merkle_root: [2u8; 32],
            policy_compliant: true,
        };
        let agg_res = aggregate_receipt_commitments(&[win1, win2_rewound]);
        assert!(agg_res.is_err());
    }
}
