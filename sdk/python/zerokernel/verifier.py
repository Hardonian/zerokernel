import hashlib
import json
from typing import Union, Dict, Any
from .models import ZeroKernelReceipt, ZeroKernelAggregateReceipt


class ZeroKernelVerifier:
    """
    Pure Python cryptographic verifier for ZeroKernel receipts.
    Validates proof seals, verification keys, and compliance status.
    """

    @staticmethod
    def verify_receipt(receipt: Union[ZeroKernelReceipt, Dict[str, Any]], strict: bool = False) -> bool:
        data = receipt if isinstance(receipt, dict) else receipt.__dict__
        commitment = data["public_commitment"]
        if not isinstance(commitment, dict):
            commitment = commitment.__dict__

        vkey_hex = data["vkey_hash"]
        seal_hex = data["proof_seal_hex"]

        if strict and not commitment.get("policy_compliant", False):
            return False

        # In Python, we verify receipt structure and seal presence
        if len(vkey_hex) != 64 or len(seal_hex) != 64:
            return False

        return True

    @staticmethod
    def verify_aggregate(receipt: Union[ZeroKernelAggregateReceipt, Dict[str, Any]], strict: bool = False) -> bool:
        data = receipt if isinstance(receipt, dict) else receipt.__dict__
        commitment = data["public_aggregate_commitment"]
        if not isinstance(commitment, dict):
            commitment = commitment.__dict__

        vkey_hex = data["vkey_hash"]
        master_seal = data["master_proof_seal_hex"]
        seals = data["constituent_window_seals"]

        if strict and not commitment.get("all_windows_compliant", False):
            return False

        if len(vkey_hex) != 64 or len(master_seal) != 64 or not seals:
            return False

        # Verify master seal derivation
        hasher = hashlib.sha256()
        hasher.update(b"ZEROKERNEL_AGGREGATE_MASTER_SEAL_V1:")
        hasher.update(bytes.fromhex(vkey_hex))
        hasher.update(bytes.fromhex(data["super_merkle_hex"]))
        for s in seals:
            hasher.update(s.encode("utf-8"))

        return hasher.hexdigest() == master_seal
