import json
import os
import subprocess
import tempfile
from typing import Optional, List, Dict, Any
from .models import SecurityPolicy, ZeroKernelReceipt, ZkAuditCommitment


class ZeroKernelClient:
    """
    Client for interacting with the ZeroKernel binary CLI.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._find_binary()

    def _find_binary(self) -> str:
        # Search path candidates
        candidates = [
            "zerokernel",
            os.path.join(os.getcwd(), "target", "release", "zerokernel.exe"),
            os.path.join(os.getcwd(), "target", "release", "zerokernel"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "target", "release", "zerokernel.exe"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "target", "release", "zerokernel"),
        ]
        for c in candidates:
            if os.path.isfile(c) or (os.name != "nt" and os.path.exists(c)):
                return os.path.abspath(c)
        return "zerokernel"

    def audit_agent(
        self,
        agent_id: str = "python-agent",
        lifecycle_steps: int = 64,
        inject_exfiltration: bool = False,
    ) -> ZeroKernelReceipt:
        with tempfile.NamedTemporaryFile(suffix=".zk.json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                self.binary_path,
                "audit-agent",
                "--agent-id",
                agent_id,
                "--lifecycle-steps",
                str(lifecycle_steps),
                "--output",
                tmp_path,
            ]
            if inject_exfiltration:
                cmd.append("--inject-exfiltration")

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"ZeroKernel audit-agent failed: {res.stderr}")

            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            commit_data = data["public_commitment"]
            commitment = ZkAuditCommitment(**commit_data)
            data["public_commitment"] = commitment
            return ZeroKernelReceipt(**data)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def verify_receipt(self, receipt_path: str, strict: bool = True) -> bool:
        cmd = [self.binary_path, "verify", "--receipt-path", receipt_path]
        if strict:
            cmd.append("--strict")
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode == 0
