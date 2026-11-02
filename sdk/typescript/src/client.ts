import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { ZeroKernelReceipt } from "./types";

export class ZeroKernelClient {
  private binaryPath: string;

  constructor(binaryPath?: string) {
    this.binaryPath = binaryPath || this.findBinary();
  }

  private findBinary(): string {
    const binName = process.platform === "win32" ? "zerokernel.exe" : "zerokernel";
    const candidates = [
      "zerokernel",
      path.resolve(process.cwd(), "target", "release", binName),
      path.resolve(process.cwd(), "..", "..", "target", "release", binName),
      path.resolve(__dirname, "..", "..", "target", "release", binName),
      path.resolve(__dirname, "..", "..", "..", "target", "release", binName),
      path.resolve(__dirname, "..", "..", "..", "..", "target", "release", binName),
    ];

    for (const c of candidates) {
      if (fs.existsSync(c)) {
        return c;
      }
    }
    return "zerokernel";
  }

  public auditAgent(agentId: string = "ts-agent", lifecycleSteps: number = 64, injectExfiltration: boolean = false): ZeroKernelReceipt {
    const tmpFile = path.join(os.tmpdir(), `zk_agent_${Date.now()}_${Math.random().toString(36).substring(7)}.json`);

    try {
      const args = [
        "audit-agent",
        "--agent-id",
        agentId,
        "--lifecycle-steps",
        lifecycleSteps.toString(),
        "--output",
        tmpFile,
      ];
      if (injectExfiltration) {
        args.push("--inject-exfiltration");
      }

      execFileSync(this.binaryPath, args, { encoding: "utf-8" });

      const raw = fs.readFileSync(tmpFile, "utf-8");
      return JSON.parse(raw) as ZeroKernelReceipt;
    } finally {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    }
  }

  public verifyReceipt(receiptPath: string, strict: boolean = true): boolean {
    const args = ["verify", "--receipt-path", receiptPath];
    if (strict) {
      args.push("--strict");
    }

    try {
      execFileSync(this.binaryPath, args, { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  }
}
