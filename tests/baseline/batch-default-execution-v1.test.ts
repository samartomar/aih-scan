import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../../src/baseline/batch-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const temporaryDirectories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-batch-default-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "rules"), { recursive: true });
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  const request = createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "ecc",
      owner: "affaan-m",
      repository: "everything-claude-code",
      pinnedCommit: "a".repeat(40),
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components: [
      {
        id: "rules-core",
        content: "general",
        paths: ["rules"],
        treeSha256: hashComponentTreeV1(root, ["rules"]).treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep"],
      },
    ],
  });
  return { root, request };
}

describe("executeBaselineVetBatchV1 default execution", () => {
  it("uses Scan's own hardened analyzer execution when no callback is supplied", async () => {
    // The host is declared as win32 so Scan's own process runner refuses the analyzer
    // spawn by its documented platform rule. Reaching that refusal is the proof that
    // the default execution really is Scan's hardened stack, and no process is started.
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    const { root, request } = fixture();

    await expect(executeBaselineVetBatchV1(request, { sourceRoot: root })).rejects.toThrow(
      /process-group execution requires a Linux analyzer host/,
    );
  });

  it("still accepts an injected execution, which stays the seam tests use", async () => {
    const { root, request } = fixture();
    const analyzers: string[] = [];

    await expect(
      executeBaselineVetBatchV1(request, {
        sourceRoot: root,
        execute: async ({ analyzer }) => {
          analyzers.push(analyzer);
          throw new TypeError("injected execution reached");
        },
      }),
    ).rejects.toThrow(/injected execution reached/);
    expect(analyzers).toEqual(["aih-native"]);
  });
});
