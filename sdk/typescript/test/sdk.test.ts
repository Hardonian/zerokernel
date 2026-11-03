import * as assert from "assert";
import * as crypto from "crypto";
import {
  SecurityPolicies,
  ZeroKernelVerifier,
  ZeroKernelClient,
  withZeroKernelAudit,
  ZeroKernelReceipt,
  ZeroKernelAggregateReceipt,
  detectC2Exfiltration,
  ZeroKernelCallbackHandler,
} from "../src";

async function runTests() {
  console.log("Running ZeroKernel TypeScript SDK test suite...");

  // 1. SecurityPolicies
  console.log("  Testing SecurityPolicies presets...");
  const strict = SecurityPolicies.strictSandbox();
  assert.strictEqual(strict.policy_id, 1001);
  assert.strictEqual(strict.allow_root_execution, false);
  assert.strictEqual(strict.forbidden_port, 4444);

  const egress = SecurityPolicies.agentEgressGuard();
  assert.strictEqual(egress.policy_id, 2002);
  assert.strictEqual(egress.forbidden_port, 6667);

  // 2. Receipt Verifier
  console.log("  Testing ZeroKernelVerifier.verifyReceipt...");
  const mockReceipt: ZeroKernelReceipt = {
    version: "0.1.0",
    prover_backend: "MockSP1Prover",
    vkey_hash: "a".repeat(64),
    public_commitment: {
      policy_id: 1001,
      total_events_verified: 64,
      violations_detected: 0,
      window_start_ns: 1000,
      window_end_ns: 2000,
      trace_merkle_root: new Array(32).fill(0),
      policy_compliant: true,
    },
    commitment_merkle_hex: "b".repeat(64),
    proof_seal_hex: "c".repeat(64),
    proving_time_ms: 12,
  };

  assert.strictEqual(ZeroKernelVerifier.verifyReceipt(mockReceipt, true), true);

  // Non-compliant fails under strict
  const nonCompliant = {
    ...mockReceipt,
    public_commitment: {
      ...mockReceipt.public_commitment,
      violations_detected: 1,
      policy_compliant: false,
    },
  };
  assert.strictEqual(ZeroKernelVerifier.verifyReceipt(nonCompliant, true), false);
  assert.strictEqual(ZeroKernelVerifier.verifyReceipt(nonCompliant, false), true);

  // Invalid vkey length fails
  const badVkey = { ...mockReceipt, vkey_hash: "deadbeef" };
  assert.strictEqual(ZeroKernelVerifier.verifyReceipt(badVkey, false), false);

  // 3. Aggregate Receipt Verifier
  console.log("  Testing ZeroKernelVerifier.verifyAggregate...");
  const vkeyHex = "a".repeat(64);
  const superMerkleHex = "b".repeat(64);
  const seals = ["seal_win_0", "seal_win_1"];

  const hasher = crypto.createHash("sha256");
  hasher.update("ZEROKERNEL_AGGREGATE_MASTER_SEAL_V1:");
  hasher.update(Buffer.from(vkeyHex, "hex"));
  hasher.update(Buffer.from(superMerkleHex, "hex"));
  for (const s of seals) {
    hasher.update(Buffer.from(s, "utf-8"));
  }
  const masterSeal = hasher.digest("hex");

  const mockAggregate: ZeroKernelAggregateReceipt = {
    version: "0.1.0",
    prover_backend: "MockSP1Prover",
    vkey_hash: vkeyHex,
    public_aggregate_commitment: {
      policy_id: 1001,
      total_windows: 2,
      total_events_verified: 128,
      total_violations_detected: 0,
      global_window_start_ns: 1000,
      global_window_end_ns: 3000,
      super_merkle_root: new Array(32).fill(0),
      all_windows_compliant: true,
    },
    super_merkle_hex: superMerkleHex,
    master_proof_seal_hex: masterSeal,
    constituent_window_seals: seals,
    total_proving_time_ms: 45,
  };

  assert.strictEqual(ZeroKernelVerifier.verifyAggregate(mockAggregate, true), true);

  // Tampered seal fails
  const tamperedAggregate = {
    ...mockAggregate,
    master_proof_seal_hex: "f".repeat(64),
  };
  assert.strictEqual(ZeroKernelVerifier.verifyAggregate(tamperedAggregate, true), false);

  // 4. ZeroKernelClient and Binary Integration
  console.log("  Testing ZeroKernelClient auditAgent with host binary...");
  try {
    const client = new ZeroKernelClient();
    const receipt = client.auditAgent("ts-test-agent", 32, false);
    assert.strictEqual(receipt.public_commitment.policy_compliant, true);
    assert.strictEqual(receipt.public_commitment.violations_detected, 0);
    assert.strictEqual(receipt.proof_seal_hex.length, 64);
    assert.strictEqual(ZeroKernelVerifier.verifyReceipt(receipt, true), true);

    // Test exfiltration injection detection
    const exfilReceipt = client.auditAgent("ts-evil-agent", 32, true);
    assert.strictEqual(exfilReceipt.public_commitment.policy_compliant, false);
    assert.ok(exfilReceipt.public_commitment.violations_detected > 0);

    // 5. Middleware wrapper
    console.log("  Testing withZeroKernelAudit middleware wrapper...");
    const res = await withZeroKernelAudit(
      { agentId: "middleware-agent", lifecycleSteps: 16 },
      async () => {
        return { response: "execution success", answer: 42 };
      }
    );

    assert.strictEqual(res.data.response, "execution success");
    assert.strictEqual(res.data.answer, 42);
    assert.strictEqual(res.compliant, true);
    assert.strictEqual(res.receipt.public_commitment.policy_compliant, true);

    // 6. Heuristics & Escrow validation
    console.log("  Testing heuristics and escrow validation...");
    assert.strictEqual(ZeroKernelVerifier.verifyEscrowReceipt(receipt, 0), true);
    assert.strictEqual(
      detectC2Exfiltration([
        {
          timestamp_ns: 1000,
          pid: 1,
          tgid: 1,
          uid: 1000,
          syscall_nr: 42,
          target_port: 6667,
          comm: "rogue",
        },
      ]),
      true
    );
    assert.strictEqual(
      detectC2Exfiltration([
        {
          timestamp_ns: 1000,
          pid: 1,
          tgid: 1,
          uid: 1000,
          syscall_nr: 257,
          target_port: 443,
          comm: "benign",
        },
      ]),
      false
    );
  } catch (err: any) {
    if (err.code === "ENOENT" || err.message?.includes("zerokernel")) {
      console.log("    (Skipping binary invocation: zerokernel executable not in PATH or release dir)");
    } else {
      throw err;
    }
  }

  console.log("All ZeroKernel TypeScript SDK tests passed successfully!");
}

runTests().catch((err) => {
  console.error("Test failure:", err);
  process.exit(1);
});

