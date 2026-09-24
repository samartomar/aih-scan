import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ANALYZER_OUTPUT_MAX_BYTES_V1,
  AnalyzerOutputReadErrorV1,
  readBoundedAnalyzerOutputV1,
} from "../../src/baseline/bounded-output-read-v1.js";
import { failureStage } from "../../src/runner/run-detector-v1.js";

// U1j: every JSON or SARIF report Scan reads from an analyzer's output (Cisco jobs, the OCI
// capture, the host and namespace scan-all runs) is read as one regular, unlinked file of at
// most the analyzer-output cap, through an open descriptor that must still be the file that
// was checked, and never through an unbounded read. Every refusal is typed and classified
// `output`.

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
const directory = () => {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-bounded-read-"));
  roots.push(root);
  return root;
};
const refusal = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    if (error instanceof AnalyzerOutputReadErrorV1)
      return { reason: error.reason, message: error.message, stage: failureStage(error.message) };
    throw error;
  }
  return undefined;
};

describe("readBoundedAnalyzerOutputV1 (U1j)", () => {
  it("uses the one 16 MiB analyzer-output cap and returns the file's exact bytes", () => {
    expect(ANALYZER_OUTPUT_MAX_BYTES_V1).toBe(16 * 1024 * 1024);
    const path = join(directory(), "results.json");
    writeFileSync(path, '{"a":1}\n');
    expect(readBoundedAnalyzerOutputV1(path, "Cisco JSON report")).toEqual(readFileSync(path));
    const exact = join(directory(), "exact.json");
    writeFileSync(exact, "x".repeat(8));
    expect(readBoundedAnalyzerOutputV1(exact, "Cisco JSON report", 8).byteLength).toBe(8);
  });

  it("refuses a missing, empty, oversized or non-regular output, typed at output", () => {
    const root = directory();
    writeFileSync(join(root, "empty.json"), "");
    writeFileSync(join(root, "big.json"), "x".repeat(9));
    mkdirSync(join(root, "dir.json"));
    for (const [name, reason, text] of [
      ["missing.json", "missing", /Cisco JSON report is missing$/],
      ["empty.json", "size", /Cisco JSON report is empty$/],
      ["big.json", "size", /Cisco JSON report exceeds 8 bytes$/],
      ["dir.json", "shape", /Cisco JSON report is not one regular file$/],
    ] as const)
      expect(
        refusal(() => readBoundedAnalyzerOutputV1(join(root, name), "Cisco JSON report", 8)),
        name,
      ).toEqual({
        reason,
        message: expect.stringMatching(new RegExp(`^aih-scan analyzer output: ${text.source}`)),
        stage: "output",
      });
  });

  it("refuses a hard-linked output (two names for one file)", () => {
    const root = directory();
    writeFileSync(join(root, "results.sarif"), "{}");
    linkSync(join(root, "results.sarif"), join(root, "alias.sarif"));
    expect(
      refusal(() => readBoundedAnalyzerOutputV1(join(root, "results.sarif"), "Cisco SARIF")),
    ).toMatchObject({ reason: "shape", stage: "output" });
  });

  it("refuses a symbolic link, even to a regular file", (context) => {
    const root = directory();
    writeFileSync(join(root, "real.sarif"), "{}");
    try {
      symlinkSync(join(root, "real.sarif"), join(root, "results.sarif"));
    } catch {
      context.skip();
    }
    expect(
      refusal(() => readBoundedAnalyzerOutputV1(join(root, "results.sarif"), "Cisco SARIF")),
    ).toMatchObject({ reason: "shape", stage: "output" });
  });
});

describe("no unbounded analyzer-output read remains (U1j)", () => {
  const source = (path: string) =>
    readFileSync(new URL(`../../src/${path}`, import.meta.url), "utf8");

  it("reads Cisco job, OCI and probe output only through the bounded reader", () => {
    for (const path of [
      "detectors/cisco-multi-skill/scan-v1.ts",
      "cisco/oci-broker-v1.ts",
      "cisco/linux-amd64-probe-v1.ts",
    ]) {
      const text = source(path);
      expect(text, path).not.toMatch(/readFileSync/);
      expect(text, path).toMatch(/readBoundedAnalyzerOutputV1\(/);
    }
  });

  it("reads the host and namespace scan-all reports through the bounded reader", () => {
    const text = source("baseline/runtime-v1.ts");
    const at = text.indexOf("function readBoundedAnalyzerOutput(");
    expect(at).toBeGreaterThan(0);
    expect(text.slice(at, text.indexOf("\n}\n", at))).toMatch(
      /return readBoundedAnalyzerOutputV1\(path, label\);/,
    );
  });
});
