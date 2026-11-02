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

        let mut current_layer: Vec<Digest> = events.iter().map(Self::compute_leaf_hash).collect();

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
}
