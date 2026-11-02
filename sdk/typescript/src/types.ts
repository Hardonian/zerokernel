export interface KernelSyscallEvent {
  timestamp_ns: number;
  pid: number;
  tgid: number;
  uid: number;
  syscall_nr: number;
  target_ipv4?: number;
  target_port?: number;
  flags?: number;
  comm: string;
}

export interface SecurityPolicy {
  policy_id: number;
  forbidden_syscall_mask: string | number;
  forbidden_ipv4_subnet: number;
  forbidden_ipv4_mask: number;
  forbidden_port: number;
  allow_root_execution: boolean;
}

export const SecurityPolicies = {
  strictSandbox(): SecurityPolicy {
    return {
      policy_id: 1001,
      forbidden_syscall_mask: "0x40000000000",
      forbidden_ipv4_subnet: 0x0a000000,
      forbidden_ipv4_mask: 0xff000000,
      forbidden_port: 4444,
      allow_root_execution: false,
    };
  },

  agentEgressGuard(): SecurityPolicy {
    return {
      policy_id: 2002,
      forbidden_syscall_mask: 0,
      forbidden_ipv4_subnet: 0x0a000000,
      forbidden_ipv4_mask: 0xff000000,
      forbidden_port: 6667,
      allow_root_execution: false,
    };
  },

  permissiveAudit(): SecurityPolicy {
    return {
      policy_id: 3003,
      forbidden_syscall_mask: 0,
      forbidden_ipv4_subnet: 0,
      forbidden_ipv4_mask: 0,
      forbidden_port: 0,
      allow_root_execution: true,
    };
  },
};

export interface ZkAuditCommitment {
  policy_id: number;
  total_events_verified: number;
  violations_detected: number;
  window_start_ns: number;
  window_end_ns: number;
  trace_merkle_root: number[];
  policy_compliant: boolean;
}

export interface ZeroKernelReceipt {
  version: string;
  prover_backend: string;
  vkey_hash: string;
  public_commitment: ZkAuditCommitment;
  commitment_merkle_hex: string;
  proof_seal_hex: string;
  proving_time_ms: number;
  binary_merkle_tree_root?: string;
  embedded_merkle_leaf_index?: number;
  embedded_merkle_proof?: any;
  chained_prev_receipt_hash?: string;
  sp1_descriptor?: any;
  violation_details?: any[];
}

export interface ZkAggregateCommitment {
  policy_id: number;
  total_windows: number;
  total_events_verified: number;
  total_violations_detected: number;
  global_window_start_ns: number;
  global_window_end_ns: number;
  super_merkle_root: number[];
  all_windows_compliant: boolean;
}

export interface ZeroKernelAggregateReceipt {
  version: string;
  prover_backend: string;
  vkey_hash: string;
  public_aggregate_commitment: ZkAggregateCommitment;
  super_merkle_hex: string;
  master_proof_seal_hex: string;
  constituent_window_seals: string[];
  total_proving_time_ms: number;
}
