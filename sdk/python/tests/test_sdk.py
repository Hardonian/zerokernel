import asyncio
import unittest
from zerokernel import (
    SecurityPolicy,
    KernelSyscallEvent,
    ZeroKernelVerifier,
    ZeroKernelClient,
    audit_agent,
    async_audit_agent,
    detect_c2_exfiltration,
    verify_escrow_receipt,
    ZeroKernelCallbackHandler,
)


class TestZeroKernelPythonSDK(unittest.TestCase):
    def test_security_policy_presets(self):
        strict = SecurityPolicy.strict_sandbox()
        self.assertEqual(strict.policy_id, 1001)
        self.assertFalse(strict.allow_root_execution)
        self.assertEqual(strict.forbidden_port, 4444)

        egress = SecurityPolicy.agent_egress_guard()
        self.assertEqual(egress.policy_id, 2002)
        self.assertEqual(egress.forbidden_port, 6667)

    def test_client_audit_and_verification(self):
        client = ZeroKernelClient()
        receipt = client.audit_agent(
            agent_id="test-agent",
            lifecycle_steps=32,
            inject_exfiltration=False,
        )
        self.assertTrue(receipt.public_commitment.policy_compliant)
        self.assertEqual(receipt.public_commitment.violations_detected, 0)
        self.assertEqual(len(receipt.proof_seal_hex), 64)

        # Verifier check
        self.assertTrue(ZeroKernelVerifier.verify_receipt(receipt, strict=True))

    def test_agent_decorator_wrapping(self):
        @audit_agent(agent_id="decorator-test", lifecycle_steps=16, strict=True)
        def my_task(query: str):
            return {"result": f"processed: {query}"}

        out = my_task("hello zerokernel")
        self.assertIn("__zk_receipt__", out)
        self.assertIn("__zk_merkle_root__", out)

    def test_async_agent_decorator_wrapping(self):
        @async_audit_agent(agent_id="async-decorator-test", lifecycle_steps=16, strict=True)
        async def my_async_task(val: int):
            return {"doubled": val * 2}

        out = asyncio.run(my_async_task(21))
        self.assertEqual(out["doubled"], 42)
        self.assertIn("__zk_receipt__", out)

    def test_heuristics_and_escrow_validation(self):
        e_safe = KernelSyscallEvent(
            timestamp_ns=1000,
            pid=1,
            tgid=1,
            uid=1000,
            syscall_nr=257,
            target_ipv4=0x01010101,
            target_port=443,
            flags=0,
            comm="safe",
        )
        self.assertFalse(detect_c2_exfiltration([e_safe]))

        e_c2 = KernelSyscallEvent(
            timestamp_ns=1001,
            pid=1,
            tgid=1,
            uid=1000,
            syscall_nr=42,
            target_ipv4=0x0A000001,
            target_port=6667,
            flags=0,
            comm="c2",
        )
        self.assertTrue(detect_c2_exfiltration([e_c2]))

        # Callback handler
        handler = ZeroKernelCallbackHandler("agent-alpha")
        handler.on_tool_start("bash", "cat /etc/passwd")
        handler.on_tool_end("root:x:0:0:...")
        summary = handler.get_audit_summary()
        self.assertEqual(summary["total_actions"], 1)


if __name__ == "__main__":
    unittest.main()

