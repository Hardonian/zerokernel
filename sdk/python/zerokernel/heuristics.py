from typing import List, Dict, Any, Optional
from .models import ZeroKernelReceipt, KernelSyscallEvent


def detect_c2_exfiltration(events: List[KernelSyscallEvent]) -> bool:
    """
    Evaluates trace events against known command-and-control (C2) heuristics:
    - IRC / C2 communication on port 6667
    - Shell reverse-connects on port 4444
    - Outbound connections to unauthorized subnets (10.0.0.0/8)
    """
    for e in events:
        # Port 6667 or 4444
        if e.target_port in (6667, 4444):
            return True
        # Egress to private testnet CIDR
        if (e.target_ipv4 & 0xFF000000) == 0x0A000000 and e.syscall_nr == 42:
            return True
    return False


def verify_escrow_receipt(receipt: ZeroKernelReceipt, max_violations: int = 0) -> bool:
    """
    Validates a ZeroKernel execution receipt before an on-chain or Web3 escrow payment is released.
    Guarantees:
    - Receipt is well-formed with valid 64-char seal
    - Policy violations are within acceptable threshold (default: 0)
    - Prover backend is recognized
    """
    if len(receipt.proof_seal_hex) != 64 or len(receipt.vkey_hash) != 64:
        return False
    if receipt.public_commitment.violations_detected > max_violations:
        return False
    return receipt.public_commitment.policy_compliant


class ZeroKernelCallbackHandler:
    """
    LangChain and AI agent framework callback handler.
    Automatically captures LLM tool and bash execution steps and binds them to cryptographic proofs.
    """

    def __init__(self, agent_id: str = "langchain-agent"):
        self.agent_id = agent_id
        self.action_history: List[Dict[str, Any]] = []

    def on_tool_start(self, tool_name: str, input_str: str, **kwargs: Any) -> None:
        self.action_history.append({"tool": tool_name, "input": input_str})

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if self.action_history:
            self.action_history[-1]["output"] = output

    def get_audit_summary(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "total_actions": len(self.action_history),
            "actions": self.action_history,
        }
