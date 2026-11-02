import unittest
from zerokernel import (
    SecurityPolicy,
    ZeroKernelVerifier,
    ZeroKernelClient,
    audit_agent,
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


if __name__ == "__main__":
    unittest.main()
