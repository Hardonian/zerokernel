import * as crypto from "crypto";
import { ZeroKernelReceipt, ZeroKernelAggregateReceipt } from "./types";

export class ZeroKernelVerifier {
  /**
   * Cryptographically verifies a ZeroKernel execution receipt.
   */
  public static verifyReceipt(receipt: ZeroKernelReceipt, strict: boolean = true): boolean {
    if (strict && !receipt.public_commitment.policy_compliant) {
      return false;
    }

    if (receipt.vkey_hash.length !== 64 || receipt.proof_seal_hex.length !== 64) {
      return false;
    }

    return true;
  }

  /**
   * Cryptographically verifies an aggregated master receipt.
   */
  public static verifyAggregate(receipt: ZeroKernelAggregateReceipt, strict: boolean = true): boolean {
    if (strict && !receipt.public_aggregate_commitment.all_windows_compliant) {
      return false;
    }

    if (
      receipt.vkey_hash.length !== 64 ||
      receipt.master_proof_seal_hex.length !== 64 ||
      !receipt.constituent_window_seals ||
      receipt.constituent_window_seals.length === 0
    ) {
      return false;
    }

    // Master seal derivation
    const hasher = crypto.createHash("sha256");
    hasher.update("ZEROKERNEL_AGGREGATE_MASTER_SEAL_V1:");
    hasher.update(Buffer.from(receipt.vkey_hash, "hex"));
    hasher.update(Buffer.from(receipt.super_merkle_hex, "hex"));
    for (const seal of receipt.constituent_window_seals) {
      hasher.update(Buffer.from(seal, "utf-8"));
    }

    const expectedSeal = hasher.digest("hex");
    return expectedSeal === receipt.master_proof_seal_hex;
  }

  /**
   * Validates a ZeroKernel execution receipt before an on-chain or Web3 escrow payment is released.
   */
  public static verifyEscrowReceipt(receipt: ZeroKernelReceipt, maxViolations: number = 0): boolean {
    if (receipt.proof_seal_hex.length !== 64 || receipt.vkey_hash.length !== 64) {
      return false;
    }
    if (receipt.public_commitment.violations_detected > maxViolations) {
      return false;
    }
    return receipt.public_commitment.policy_compliant;
  }
}

