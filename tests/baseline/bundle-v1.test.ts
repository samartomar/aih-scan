import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../../src/baseline/batch-v1.js";
import {
  readBaselineVetBundleForSigningV1,
  readBaselineVetBundleV1,
  writeBaselineVetBundleV1,
} from "../../src/baseline/bundle-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("BaselineVetBundleV1", () => {
  it("round-trips one canonical receipt and exact annex set, refusing extras and overwrite", async () => {
    const parent = mkdtempSync(join(tmpdir(), "aih-scan-baseline-bundle-"));
    temporaryDirectories.push(parent);
    const sourceRoot = join(parent, "source");
    mkdirSync(join(sourceRoot, "rules"), { recursive: true });
    writeFileSync(join(sourceRoot, "rules", "base.md"), "# Rule\n", "utf8");
    const request = createBaselineVetRequestV1({
      protocol: "BaselineVetRequestV1",
      profile: "aih-baseline-v1",
      source: {
        id: "ecc",
        owner: "affaan-m",
        repository: "everything-claude-code",
        pinnedCommit: "a".repeat(40),
        treeSha256: hashSourceTreeV1(sourceRoot).treeSha256,
      },
      components: [
        {
          id: "rules-core",
          content: "general",
          paths: ["rules"],
          treeSha256: hashComponentTreeV1(sourceRoot, ["rules"]).treeSha256,
          analyzers: ["aih-native", "skillspector", "semgrep"],
        },
      ],
    });
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot,
      execute: async ({ analyzer }) =>
        analyzer === "aih-native"
          ? {
              mediaType: "application/vnd.aih.baseline-native+json",
              bytes: canonicalStrictJsonBytesV1({
                protocol: "BaselineNativeObservationV1",
                files: [],
              }),
              analyzerVersion: "native.0123456789ab",
            }
          : {
              mediaType: "application/sarif+json",
              bytes: canonicalStrictJsonBytesV1({
                version: "2.1.0",
                runs: [{ tool: { driver: { name: analyzer } }, results: [] }],
              }),
              analyzerVersion: `${analyzer}.0123456789ab`,
            },
    });
    const output = join(parent, "bundle");
    writeBaselineVetBundleV1({ outputDirectory: output, result });

    expect(readBaselineVetBundleV1({ bundleDirectory: output })).toEqual(result);
    if (process.platform === "linux")
      expect(readBaselineVetBundleForSigningV1({ bundleDirectory: output })).toEqual(result);
    else
      expect(() => readBaselineVetBundleForSigningV1({ bundleDirectory: output })).toThrow(
        /requires Linux/,
      );
    expect(() => writeBaselineVetBundleV1({ outputDirectory: output, result })).toThrow();
    writeFileSync(join(output, "unexpected"), "extra", "utf8");
    expect(() => readBaselineVetBundleV1({ bundleDirectory: output })).toThrow(/bundle members/);
  });
});
