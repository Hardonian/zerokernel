import { KernelSyscallEvent } from "./types";

export function detectC2Exfiltration(events: KernelSyscallEvent[]): boolean {
  for (const e of events) {
    if (e.target_port === 6667 || e.target_port === 4444) {
      return true;
    }
    if (e.target_ipv4 && (e.target_ipv4 & 0xff000000) === 0x0a000000 && e.syscall_nr === 42) {
      return true;
    }
  }
  return false;
}

export class ZeroKernelCallbackHandler {
  public agentId: string;
  public actions: Array<{ tool: string; input: string; output?: string }>;

  constructor(agentId: string = "langchain-agent") {
    this.agentId = agentId;
    this.actions = [];
  }

  public onToolStart(toolName: string, inputStr: string): void {
    this.actions.push({ tool: toolName, input: inputStr });
  }

  public onToolEnd(output: string): void {
    if (this.actions.length > 0) {
      this.actions[this.actions.length - 1].output = output;
    }
  }

  public getAuditSummary(): { agentId: string; totalActions: number; actions: any[] } {
    return {
      agentId: this.agentId,
      totalActions: this.actions.length,
      actions: this.actions,
    };
  }
}

