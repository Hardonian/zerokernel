from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class KernelSyscallEvent:
    timestamp_ns: int
    pid: int
    tgid: int
    uid: int
    syscall_nr: int
    target_ipv4: int = 0
    target_port: int = 0
    flags: int = 0
    comm: str = ""


@dataclass
class SecurityPolicy:
    policy_id: int
    forbidden_syscall_mask: int = 0
    forbidden_ipv4_subnet: int = 0
    forbidden_ipv4_mask: int = 0
    forbidden_port: int = 0
    allow_root_execution: bool = False

    @classmethod
    def strict_sandbox(cls) -> "SecurityPolicy":
        return cls(
            policy_id=1001,
            forbidden_syscall_mask=(1 << 59) | (1 << 42),
            forbidden_ipv4_subnet=0x0A000000,
            forbidden_ipv4_mask=0xFF000000,
            forbidden_port=4444,
            allow_root_execution=False,
        )

    @classmethod
    def agent_egress_guard(cls) -> "SecurityPolicy":
        return cls(
            policy_id=2002,
            forbidden_syscall_mask=0,
            forbidden_ipv4_subnet=0x0A000000,
            forbidden_ipv4_mask=0xFF000000,
            forbidden_port=6667,  # C2 / IRC exfiltration
            allow_root_execution=False,
        )

    @classmethod
    def permissive_audit(cls) -> "SecurityPolicy":
        return cls(
            policy_id=3003,
            forbidden_syscall_mask=0,
            forbidden_ipv4_subnet=0,
            forbidden_ipv4_mask=0,
            forbidden_port=0,
            allow_root_execution=True,
        )


@dataclass
class ZkAuditCommitment:
    policy_id: int
    total_events_verified: int
    violations_detected: int
    window_start_ns: int
    window_end_ns: int
    trace_merkle_root: List[int]
    policy_compliant: bool


@dataclass
class ZeroKernelReceipt:
    version: str
    prover_backend: str
    vkey_hash: str
    public_commitment: ZkAuditCommitment
    commitment_merkle_hex: str
    proof_seal_hex: str
    proving_time_ms: int
    binary_merkle_tree_root: Optional[str] = None
    embedded_merkle_leaf_index: Optional[int] = None
    embedded_merkle_proof: Optional[Dict[str, Any]] = None
    chained_prev_receipt_hash: Optional[str] = None
    sp1_descriptor: Optional[Dict[str, Any]] = None
    violation_details: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ZkAggregateCommitment:
    policy_id: int
    total_windows: int
    total_events_verified: int
    total_violations_detected: int
    global_window_start_ns: int
    global_window_end_ns: int
    super_merkle_root: List[int]
    all_windows_compliant: bool


@dataclass
class ZeroKernelAggregateReceipt:
    version: str
    prover_backend: str
    vkey_hash: str
    public_aggregate_commitment: ZkAggregateCommitment
    super_merkle_hex: str
    master_proof_seal_hex: str
    constituent_window_seals: List[str]
    total_proving_time_ms: int
