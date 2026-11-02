# ZeroKernel TypeScript SDK (`@zerokernel/sdk`)

Official TypeScript / JavaScript client and verifier SDK for **ZeroKernel**, the Ring-0 eBPF & zkVM Cryptographic Audit Engine for Autonomous AI Agents.

---

## Features

- **Receipt Verification**: Validate SP1 zkVM proofs and Merkle commitments in Node.js or browser runtimes using SHA-256 seal verification.
- **Recursive Aggregate Receipts**: Verify multi-window rollups (`verifyAggregate`) ensuring continuous cryptographic proof across long-running agent trajectories.
- **Client Runner**: Execute deterministic synthetic agent audits or live Ring-0 eBPF telemetry captures via the `zerokernel` CLI.
- **Middleware Task Wrapper**: `withZeroKernelAudit` wraps asynchronous agent routines (e.g. LangChain, ElizaOS, AutoGPT) and attaches immutable cryptographic receipts.
- **Security Policy Presets**: Standard policy configurations (`strictSandbox`, `agentEgressGuard`, `permissiveAudit`).

---

## Installation

```bash
npm install @zerokernel/sdk
```

Or when developing locally:
```bash
cd sdk/typescript
npm install
npm run build
```

---

## Usage Examples

### 1. Cryptographic Receipt Verification

```typescript
import { ZeroKernelVerifier, ZeroKernelReceipt } from "@zerokernel/sdk";

const receipt: ZeroKernelReceipt = JSON.parse(fs.readFileSync("receipt.json", "utf-8"));

// Strict mode: checks seal format, vkey hash, and guarantees 0 policy violations
const isValid = ZeroKernelVerifier.verifyReceipt(receipt, /* strict = */ true);
if (isValid) {
  console.log("Proof verified! Events audited:", receipt.public_commitment.total_events_verified);
} else {
  console.error("Verification failed: receipt is forged or contains policy violations.");
}
```

### 2. Recursive Aggregate Verification

```typescript
import { ZeroKernelVerifier, ZeroKernelAggregateReceipt } from "@zerokernel/sdk";

const aggReceipt: ZeroKernelAggregateReceipt = JSON.parse(fs.readFileSync("master_aggregate.json", "utf-8"));

const isValid = ZeroKernelVerifier.verifyAggregate(aggReceipt, true);
console.log(`Master Aggregate Verified: ${isValid} across ${aggReceipt.public_aggregate_commitment.total_windows} windows`);
```

### 3. Agent Middleware Wrapping

Wrap any agent execution loop (e.g., tool calls, LLM chain steps) in cryptographic proofs:

```typescript
import { withZeroKernelAudit } from "@zerokernel/sdk";

async function runAutonomousWorkflow(prompt: string) {
  return await withZeroKernelAudit(
    { agentId: "financial-analyst-agent", lifecycleSteps: 48 },
    async () => {
      // Execute LLM call or tool orchestration here
      return { output: "Market summary completed" };
    }
  );
}

const { data, receipt, compliant } = await runAutonomousWorkflow("Analyze AAPL");
console.log("Result:", data);
console.log("Compliant:", compliant);
console.log("Proof Seal:", receipt.proof_seal_hex);
```

### 4. Running Agent Audits via Client

```typescript
import { ZeroKernelClient, SecurityPolicies } from "@zerokernel/sdk";

const client = new ZeroKernelClient();

// Run simulated or live agent lifecycle audit
const receipt = client.auditAgent("research-agent", 64, false);
console.log("Events verified:", receipt.public_commitment.total_events_verified);
console.log("Violations:", receipt.public_commitment.violations_detected);
```

---

## License

Dual-licensed under MIT or Apache 2.0.
