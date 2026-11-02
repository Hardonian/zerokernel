#![no_std]
extern crate alloc;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

pub type Digest = [u8; 32];
pub const MAX_BATCH_EVENTS: usize = 65_536;

pub const HOOK_TRACEPOINT_EXECVE: u16 = 0x01;
pub const HOOK_XDP_IPV4_PACKET: u16 = 0x02;
pub const FLAG_ROOT_PRIVILEGE: u16 = 0x80;

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
pub struct ZkAuditCommitment {
    pub policy_id: u32,
    pub total_events_verified: u32,
    pub violations_detected: u32,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub trace_merkle_root: Digest,
    pub policy_compliant: bool,
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
}

pub fn evaluate_kernel_trace(
    policy: &SecurityPolicy,
    events: &[KernelSyscallEvent],
) -> Result<ZkAuditCommitment, &'static str> {
    if events.len() > MAX_BATCH_EVENTS {
        return Err("Kernel trace exceeds MAX_BATCH_EVENTS circuit ceiling");
    }

    let mut rolling_hash: Digest = [0u8; 32];
    let mut violations: u32 = 0;
    let mut window_start = u64::MAX;
    let mut window_end = 0u64;
    let mut prev_ts = 0u64;

    for event in events {
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

        let mut violated = false;

        if !policy.allow_root_execution && event.uid == 0 {
            violated = true;
        }

        if event.syscall_nr < 64 {
            let bit = 1u64 << event.syscall_nr;
            if (policy.forbidden_syscall_mask & bit) != 0 {
                violated = true;
            }
        }

        if event.target_ipv4 != 0
            && policy.forbidden_ipv4_mask != 0
            && (event.target_ipv4 & policy.forbidden_ipv4_mask)
                == (policy.forbidden_ipv4_subnet & policy.forbidden_ipv4_mask)
        {
            violated = true;
        }

        if policy.forbidden_port != 0 && event.target_port == policy.forbidden_port {
            violated = true;
        }

        if violated {
            violations = violations.saturating_add(1);
        }

        let mut hasher = Sha256::new();
        hasher.update(rolling_hash);
        hasher.update(event.to_fixed_bytes());
        rolling_hash = hasher.finalize().into();
    }

    if events.is_empty() {
        window_start = 0;
    }

    Ok(ZkAuditCommitment {
        policy_id: policy.policy_id,
        total_events_verified: events.len() as u32,
        violations_detected: violations,
        window_start_ns: window_start,
        window_end_ns: window_end,
        trace_merkle_root: rolling_hash,
        policy_compliant: violations == 0,
    })
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
        let res_bad = evaluate_kernel_trace(&policy, &[ok_event, bad_event]).expect("evaluates");
        assert!(!res_bad.policy_compliant);
        assert_eq!(res_bad.violations_detected, 1);
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
}
