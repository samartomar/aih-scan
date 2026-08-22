import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(
  resolve(import.meta.dirname, "../../.github/workflows/disposable-evidence-chain.yml"),
  "utf8",
);

describe("disposable evidence chain workflow", () => {
  it("splits capture, signing, and verification with read-only credentials", () => {
    expect(workflow).toMatch(/jobs:\s+[\s\S]*capture:/);
    expect(workflow).toMatch(/\n {2}sign:\n {4}needs: capture/);
    expect(workflow).toMatch(/\n {2}verify:\n {4}needs: sign/);
    expect(workflow.match(/persist-credentials: false/g)).toHaveLength(3);
    expect(workflow.match(/contents: read/g)?.length).toBeGreaterThanOrEqual(4);
    const signing = workflow.slice(workflow.indexOf("  sign:"), workflow.indexOf("  verify:"));
    expect(signing).not.toMatch(/docker|captureCisco|capture --request/i);
    expect(signing).toContain("--private-key");
    expect(signing).not.toContain("private.pem\n            $");
  });
});
