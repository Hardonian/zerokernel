"""
ZeroKernel Python SDK
Sub-second zero-knowledge proofs of Linux kernel syscalls and AI agent execution invariants.
"""

from .models import (
    KernelSyscallEvent,
    SecurityPolicy,
    ZkAuditCommitment,
    ZeroKernelReceipt,
    ZeroKernelAggregateReceipt,
)
from .client import ZeroKernelClient
from .verifier import ZeroKernelVerifier
from .decorator import audit_agent, async_audit_agent
from .heuristics import (
    detect_c2_exfiltration,
    verify_escrow_receipt,
    ZeroKernelCallbackHandler,
)

__all__ = [
    "KernelSyscallEvent",
    "SecurityPolicy",
    "ZkAuditCommitment",
    "ZeroKernelReceipt",
    "ZeroKernelAggregateReceipt",
    "ZeroKernelClient",
    "ZeroKernelVerifier",
    "audit_agent",
    "async_audit_agent",
    "detect_c2_exfiltration",
    "verify_escrow_receipt",
    "ZeroKernelCallbackHandler",
]

__version__ = "0.1.0"

