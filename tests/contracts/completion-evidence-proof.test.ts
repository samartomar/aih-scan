import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  COMPLETION_EXTRACT_SOURCE,
  completionProblem,
  subjectDigest,
  subjectPaths,
} from "../../tools/lib/completion-evidence-proof.mjs";

// S2g: the installed proofs check completion evidence v1 (C2a §1.6) with their own oracle, so
// the oracle itself must agree with the contract's test vector and must catch a bad record.
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-completion-proof-"));
  roots.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, ...path.split("/").slice(0, -1)), { recursive: true });
    writeFileSync(join(root, ...path.split("/")), text, "utf8");
  }
  return root;
}

describe("the installed proofs' completion-evidence oracle", () => {
  it("reproduces the contract's test vector from files on disk", () => {
    const root = fixture({ "SKILL.md": "# alpha\n", "scripts/run.sh": "echo\n" });
    expect(subjectDigest(root, ["scripts/run.sh", "SKILL.md"])).toEqual({
      subjectTreeSha256: "adc6c170f014a8d238d3f18b3cd44e82cbfbe1f7fa9b4bafae6f5aab1cece047",
      analyzedFileCount: 2,
    });
  });

  it("chooses each detector's subject files as the contract's table does", () => {
    const root = fixture({
      ".git/HEAD": "ref\n",
      "README.md": "# readme\n",
      "skills/a/SKILL.md": "# a\n",
      "skills/ab/x.md": "x\n",
      ".mcp.json": "{}\n",
    });
    const pick = (detectorId: string, subjectKind = "source-tree", selected: string[] = []) =>
      subjectPaths({
        detectorId,
        subjectKind,
        root,
        selected,
        detectorOptions: { mcpConfigPaths: [".mcp.json", "missing.json"] },
      });
    expect(pick("detector.semgrep")).toContain(".git/HEAD");
    expect(pick("detector.snyk-agent-scan")).not.toContain(".git/HEAD");
    expect(pick("detector.cisco", "skill-directory")).not.toContain(".git/HEAD");
    expect(pick("detector.cisco", "source-tree", ["skills/a/SKILL.md"])).toEqual([
      "skills/a/SKILL.md",
    ]);
    expect(pick("detector.cisco-mcp-scanner")).toEqual([".mcp.json"]);
    expect(pick("detector.aih-trust-lint", "source-tree", ["README.md"])).toEqual(["README.md"]);
  });

  it("accepts only equal, exact evidence on every successful run", () => {
    const root = fixture({ "SKILL.md": "# alpha\n" });
    const expected = {
      root,
      paths: ["SKILL.md"],
      detectorId: "detector.cisco",
      version: "2.0.14",
      lockSha256: "a".repeat(64),
    };
    const evidence = {
      detectorId: "detector.cisco",
      ...subjectDigest(root, ["SKILL.md"]),
      analyzer: { lockSha256: "a".repeat(64), version: "2.0.14" },
    };
    const good = { executionSuccessful: true, evidence };
    expect(completionProblem([good, good], expected)).toBeUndefined();
    expect(completionProblem([], expected)).toMatch(/no SARIF run/);
    expect(completionProblem([{ executionSuccessful: true, evidence: null }], expected)).toMatch(
      /no aihScanCompletionV1/,
    );
    expect(completionProblem([{ executionSuccessful: false, evidence }], expected)).toMatch(
      /executionSuccessful/,
    );
    expect(
      completionProblem(
        [good, { executionSuccessful: true, evidence: { ...evidence, analyzedFileCount: 2 } }],
        expected,
      ),
    ).toMatch(/different/);
    expect(
      completionProblem(
        [{ executionSuccessful: true, evidence: { ...evidence, extra: 1 } }],
        expected,
      ),
    ).toMatch(/not the expected/);
    expect(completionProblem([good], { ...expected, paths: [] })).toMatch(/not the expected/);
  });

  it("extracts each run's first invocation in the proof child", () => {
    const completionOf = new Function(`${COMPLETION_EXTRACT_SOURCE}; return completionOf;`)() as (
      bytes: Uint8Array,
    ) => unknown;
    const log = {
      runs: [
        {
          invocations: [
            { executionSuccessful: true, properties: { aihScanCompletionV1: { a: 1 } } },
          ],
        },
        {},
      ],
    };
    expect(completionOf(Buffer.from(JSON.stringify(log)))).toEqual([
      { executionSuccessful: true, evidence: { a: 1 } },
      { executionSuccessful: null, evidence: null },
    ]);
    expect(completionOf(Buffer.from("not json"))).toBeNull();
  });
});
