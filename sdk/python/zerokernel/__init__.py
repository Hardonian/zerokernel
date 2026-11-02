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
from .decorator import audit_agent

__all__ = [
    "KernelSyscallEvent",
    "SecurityPolicy",
    "ZkAuditCommitment",
    "ZeroKernelReceipt",
    "ZeroKernelAggregateReceipt",
    "ZeroKernelClient",
    "ZeroKernelVerifier",
    "audit_agent",
]

__version__ = "0.1.0"
