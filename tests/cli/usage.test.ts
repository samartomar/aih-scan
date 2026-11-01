import { describe, expect, it } from "vitest";
import { advisoriesUsage, runAdvisoriesCommand } from "../../src/cli/advisories-v1.js";
import {
  findingsUsage,
  readUsage,
  runFindingsCommand,
  runReadCommand,
  runScanCommandV1,
  scanUsage,
} from "../../src/cli/commands-v1.js";
import {
  runSignCommand,
  runVerifyCommand,
  signUsage,
  verifyUsage,
} from "../../src/cli/sign-verify-v1.js";
import { commandsUsage } from "../../src/cli/usage.js";

const usages = { scanUsage, advisoriesUsage, readUsage, findingsUsage, verifyUsage, signUsage };

describe("command help", () => {
  it("composes the top-level usage from every command's own usage lines", () => {
    const top = commandsUsage(Object.values(usages));
    for (const [name, usage] of Object.entries(usages)) {
      const [first] = usage.split("\n");
      expect(first, name).toMatch(/^Usage: aih-scan [a-z]+ /);
      expect(top, name).toContain(`  ${(first as string).slice(7)}`);
    }
    // Every flag a command documents in its usage lines appears in the top-level usage.
    for (const flag of ["--private", "--include-private", "--ref", "--fail-at", "--signers"])
      expect(top).toContain(flag);
    expect(top).toContain("aih-scan <command> --help");
  });

  it("prints each command's own usage for --help", async () => {
    const out: string[] = [];
    const io = { stdout: (t: string) => void out.push(t), stderr: () => {} };
    const runs: [string, () => unknown][] = [
      [scanUsage, () => runScanCommandV1(["--help"], io as never)],
      [advisoriesUsage, () => runAdvisoriesCommand(["--help"], io as never)],
      [readUsage, () => runReadCommand(["--help"], io)],
      [findingsUsage, () => runFindingsCommand(["--help"], io)],
      [verifyUsage, () => runVerifyCommand(["--help"], io)],
      [signUsage, () => runSignCommand(["--help"], io as never)],
    ];
    for (const [usage, run] of runs) {
      out.length = 0;
      expect(await run()).toBe(0);
      expect(out.join("")).toBe(usage);
    }
  });
});
