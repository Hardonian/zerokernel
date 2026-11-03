import functools
from typing import Callable, Any
from .client import ZeroKernelClient
from .models import ZeroKernelReceipt


def audit_agent(
    agent_id: str = "python-agent-task",
    lifecycle_steps: int = 48,
    strict: bool = True,
) -> Callable:
    """
    Decorator for AI agent functions.
    Captures execution invariants, verifies ZeroKernel compliance, and attaches receipt to result.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            client = ZeroKernelClient()
            result = fn(*args, **kwargs)

            receipt = client.audit_agent(
                agent_id=agent_id,
                lifecycle_steps=lifecycle_steps,
                inject_exfiltration=False,
            )

            if strict and not receipt.public_commitment.policy_compliant:
                raise PermissionError(
                    f"Agent execution invariant violated: {receipt.public_commitment.violations_detected} violations detected!"
                )

            if isinstance(result, dict):
                result["__zk_receipt__"] = receipt.proof_seal_hex
                result["__zk_merkle_root__"] = receipt.commitment_merkle_hex

            return result

        return wrapper

    return decorator


def async_audit_agent(
    agent_id: str = "python-async-agent-task",
    lifecycle_steps: int = 48,
    strict: bool = True,
) -> Callable:
    """
    Asynchronous decorator for async def AI agent functions.
    Captures execution invariants, verifies ZeroKernel compliance, and attaches receipt to result.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            client = ZeroKernelClient()
            result = await fn(*args, **kwargs)

            receipt = client.audit_agent(
                agent_id=agent_id,
                lifecycle_steps=lifecycle_steps,
                inject_exfiltration=False,
            )

            if strict and not receipt.public_commitment.policy_compliant:
                raise PermissionError(
                    f"Agent execution invariant violated: {receipt.public_commitment.violations_detected} violations detected!"
                )

            if isinstance(result, dict):
                result["__zk_receipt__"] = receipt.proof_seal_hex
                result["__zk_merkle_root__"] = receipt.commitment_merkle_hex

            return result

        return wrapper

    return decorator

