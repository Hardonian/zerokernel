#![no_std]
extern crate alloc;

use zerokernel_common::{
    evaluate_kernel_trace, KernelSyscallEvent, SecurityPolicy, ZkAuditCommitment,
};

pub fn run_zk_circuit(policy: &SecurityPolicy, events: &[KernelSyscallEvent]) -> ZkAuditCommitment {
    evaluate_kernel_trace(policy, events)
        .expect("Circuit invariant violated: trace exceeded bounds or non-monotonic clock")
}
