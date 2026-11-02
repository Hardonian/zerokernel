# ZeroKernel Python SDK

Official Python SDK for **ZeroKernel (`zk-ebpf`)**: Sub-Second Cryptographic Zero-Knowledge Proofs of Linux Kernel Execution & AI Agent Telemetry.

---

## Installation

```bash
pip install zerokernel
# Or from local source:
pip install -e sdk/python
```

---

## Quickstart

### 1. Audit an Autonomous Agent Execution

```python
from zerokernel import ZeroKernelClient, ZeroKernelVerifier

client = ZeroKernelClient()

# Audit an autonomous agent execution lifecycle
receipt = client.audit_agent(
    agent_id="hermes-worker-01",
    lifecycle_steps=64,
    inject_exfiltration=False,
)

print(f"Receipt Seal: {receipt.proof_seal_hex}")
print(f"Compliant: {receipt.public_commitment.policy_compliant}")

# Cryptographically verify the receipt
is_valid = ZeroKernelVerifier.verify_receipt(receipt, strict=True)
assert is_valid
```

---

### 2. Guard Agent Tasks with `@audit_agent` Decorator

```python
from zerokernel import audit_agent

@audit_agent(agent_id="langchain-researcher", lifecycle_steps=32, strict=True)
def run_autonomous_research(prompt: str) -> dict:
    # Simulated agent tool execution
    return {"status": "success", "summary": "Analysis completed safely"}

# Returns the result with cryptographic proof attached
result = run_autonomous_research("Analyze system performance")
print(f"Receipt Seal: {result['__zk_receipt__']}")
```
