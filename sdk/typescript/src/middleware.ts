import { ZeroKernelClient } from "./client";
import { ZeroKernelReceipt } from "./types";

export interface AgentTaskContext {
  agentId: string;
  lifecycleSteps?: number;
}

export interface AgentTaskResult<T> {
  data: T;
  receipt: ZeroKernelReceipt;
  compliant: boolean;
}

/**
 * Wraps an asynchronous agent function, audits its runtime execution,
 * and attaches a cryptographic ZeroKernel receipt.
 */
export async function withZeroKernelAudit<T>(
  ctx: AgentTaskContext,
  task: () => Promise<T>
): Promise<AgentTaskResult<T>> {
  const client = new ZeroKernelClient();
  const data = await task();

  const receipt = client.auditAgent(ctx.agentId, ctx.lifecycleSteps || 48, false);

  if (!receipt.public_commitment.policy_compliant) {
    throw new Error(`ZeroKernel Invariant Violated: ${receipt.public_commitment.violations_detected} violations detected.`);
  }

  return {
    data,
    receipt,
    compliant: receipt.public_commitment.policy_compliant,
  };
}
