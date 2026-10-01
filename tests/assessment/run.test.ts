import * as fsBoundary from "node:fs";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { canonicalBytes } from "../../src/assessment/json.js";
import { SEMGREP_VERSION_V1 } from "../../src/baseline/runtime-v1.js";
import * as processBoundary from "../../src/cli/process-runner.js";
import { runScan } from "../../src/public/host.js";
import { readReport } from "../../src/public/read.js";

vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
}));
const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function rootFixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-assessment-test-"));
  roots.push(root);
  return root;
}
function request(root: string) {
  return {
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: root },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
  };
}
function semgrepTransport(stdout: string, malformed = false) {
  const nativeStat = fsBoundary.statSync(process.execPath),
    actualStat = fsBoundary.statSync;
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  vi.spyOn(process, "arch", "get").mockReturnValue("x64");
  vi.spyOn(fsBoundary, "statSync").mockImplementation(((
    path: Parameters<typeof fsBoundary.statSync>[0],
    ...args: unknown[]
  ) =>
    String(path) === "/usr/bin/bwrap" || String(path) === "/usr/local/bin/uv"
      ? nativeStat
      : Reflect.apply(actualStat, fsBoundary, [path, ...args])) as typeof fsBoundary.statSync);
  vi.spyOn(processBoundary, "processRunner").mockImplementation(async (argv) => ({
    code: 0,
    stderr: "",
    truncated: false,
    stdout: argv.includes("--sarif")
      ? stdout
      : argv.at(-1) === "--version"
        ? SEMGREP_VERSION_V1
        : "",
    ...(argv.includes("--sarif") && malformed ? { stdoutMalformedUtf8: true as const } : {}),
  }));
}
function sarif(path: string, message = "fixture finding", extra = "") {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "semgrep" } },
        invocations: [{ executionSuccessful: true }],
        results: [
          {
            ruleId: "fixture.rule",
            level: "warning",
            message: { text: message },
            locations: [
              { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 1 } } },
            ],
          },
        ],
        properties: { extra },
      },
    ],
  });
}
function nativeAndSemgrep(root: string) {
  return {
    ...request(root),
    selection: { paths: ["SKILL.md"], excludedPaths: [] },
    detectors: [
      { detectorId: "detector.aih-native", configuration: {} },
      { detectorId: "detector.semgrep", configuration: {} },
    ],
  };
}
test.each([
  ["unselected location", "outside.txt", "fixture finding", false],
  ["unbound finding", "absent.txt", "fixture finding", false],
  ["malformed annex bytes", "SKILL.md", "fixture finding", true],
])("%s fails only that detector and preserves a reliable sibling and Scan ID", async (_kind, path, message, malformed) => {
  const root = rootFixture();
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  writeFileSync(join(root, "outside.txt"), "other captured bytes\n");
  semgrepTransport(sarif(path, message), malformed);
  const result = await runScan(nativeAndSemgrep(root));
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      completion: "partial",
      results: [
        {
          outcome: "succeeded",
          observations: [{ origin: "fresh" }],
          coverage: { coveredPaths: ["SKILL.md"] },
        },
        {
          outcome: "failed",
          observations: [],
          coverage: { coveredPaths: [], uncoveredPaths: ["SKILL.md"] },
        },
      ],
    },
  });
  if (result.status === "assessment") {
    expect(result.scanId).toMatch(/^scan:sha256:[0-9a-f]{64}$/);
    expect(result.annexes).toHaveLength(1);
    expect((await readReport(canonicalBytes(result.report))).status).toBe("read");
    expect(JSON.stringify(result.report.results[1]!.diagnostics)).not.toContain(message);
  }
});
test.each([
  "per-annex",
  "decoded-budget",
  "artifact-budget",
])("oversized later output respects %s and preserves native work", async (kind) => {
  const root = rootFixture();
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  semgrepTransport(sarif("SKILL.md", "fixture finding", "x".repeat(24000)));
  const result = await runScan({
    ...nativeAndSemgrep(root),
    limits:
      kind === "per-annex"
        ? { maxAnnexBytes: 16000 }
        : kind === "decoded-budget"
          ? { maxDecodedArtifactBytes: 24000 }
          : { maxArtifactBytes: 24000 },
  });
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      results: [
        { outcome: "succeeded", observations: [{ origin: "fresh" }] },
        { outcome: "failed", observations: [], diagnostics: [{ code: "resource-limit" }] },
      ],
    },
  });
  if (result.status === "assessment") expect(result.annexes).toHaveLength(1);
});
test("a reliable native observation survives a refused sibling in one source-bound assessment", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-assessment-test-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Example\n");
  const result = await runScan({
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: root },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [
      { detectorId: "detector.aih-native", configuration: {} },
      { detectorId: "detector.unavailable", configuration: {} },
    ],
  });
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      completion: "partial",
      results: [
        {
          detectorId: "detector.aih-native",
          outcome: "succeeded",
          coverage: { coveredPaths: ["SKILL.md"], complete: true },
        },
        {
          detectorId: "detector.unavailable",
          outcome: "refused",
          coverage: { uncoveredPaths: ["SKILL.md"], complete: false },
        },
      ],
    },
  });
  if (result.status === "assessment") {
    expect(result.annexes.length).toBeGreaterThan(0);
    expect(JSON.stringify(result)).not.toContain(root);
  }
});
test("a native annex byte-binding mismatch fails only its detector", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  semgrepTransport(sarif("SKILL.md"));
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  // Fault at the system digest boundary after native output creation, before annex admission.
  vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, data) =>
    new TextDecoder().decode(data).includes('"version":"2.1.0"')
      ? new Uint8Array(32).buffer
      : digest(algorithm, data),
  );
  const result = await runScan(nativeAndSemgrep(root));
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      results: [
        { outcome: "succeeded", observations: [{ origin: "fresh" }] },
        { outcome: "failed", observations: [], diagnostics: [{ code: "detector-output-invalid" }] },
      ],
    },
  });
  if (result.status === "assessment") expect(result.annexes).toHaveLength(1);
});
test("root Git metadata is omitted while other dot files remain source-bound", async () => {
  const root = rootFixture();
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "secret"), "private metadata");
  writeFileSync(join(root, ".visible"), "ordinary content");
  const result = await runScan(request(root));
  expect(result.status).toBe("assessment");
  if (result.status === "assessment") {
    expect(result.report.source.capture.entries.map((entry) => entry.path)).toEqual([".visible"]);
    expect((await readReport(canonicalBytes(result.report))).status).toBe("read");
  }
});
test("an empty captured source has a real identity and an honest native refusal", async () => {
  expect(await runScan(request(rootFixture()))).toMatchObject({
    status: "assessment",
    report: {
      completion: "partial",
      source: { capture: { entries: [] } },
      results: [{ outcome: "refused", coverage: { complete: true } }],
    },
  });
});
test.each([
  [
    "duplicate detector",
    (r: ReturnType<typeof request>) => {
      r.detectors.push({ ...r.detectors[0]! });
    },
  ],
  [
    "unknown request field",
    (r: ReturnType<typeof request>) => {
      Object.assign(r, { unexpected: true });
    },
  ],
  [
    "invalid detector configuration",
    (r: ReturnType<typeof request>) => {
      r.detectors[0]!.configuration = { unexpected: true };
    },
  ],
])("%s fails before capture or detector effects", async (_name, modify) => {
  const r = request(join(rootFixture(), "absent"));
  modify(r);
  expect(await runScan(r)).toMatchObject({ status: "diagnostic", phase: "request" });
});
test("absent selection or capture byte overflow never receives a Scan ID", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "file"), "0123456789");
  const result = await runScan({ ...request(root), limits: { maxSourceBytes: 1 } });
  expect(result).toMatchObject({ status: "diagnostic", phase: "capture" });
  expect(result).not.toHaveProperty("scanId");
  expect(
    await runScan({ ...request(root), selection: { paths: ["absent"], excludedPaths: [] } }),
  ).toMatchObject({ status: "diagnostic", phase: "capture" });
});
test("unsupported selected profiles remain refused detector slots", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "file"), "x");
  const result = await runScan({
    ...request(root),
    detectors: [{ detectorId: "detector.aih-native", profileId: "unknown", configuration: {} }],
  });
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      requestedDetectors: [{ profileId: null }],
      results: [{ outcome: "refused", coverage: { uncoveredPaths: ["file"] } }],
    },
  });
});
test("cancellation before capture is diagnostic and contains no assessment identity", async () => {
  const signal = AbortSignal.abort();
  expect(await runScan(request(rootFixture()), { signal })).toMatchObject({
    status: "diagnostic",
    phase: "capture",
  });
});
test("explicit exclusions stay excluded when the detector cannot honour them", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "file"), "x");
  expect(
    await runScan({ ...request(root), selection: { paths: "all", excludedPaths: ["file"] } }),
  ).toMatchObject({
    status: "assessment",
    report: {
      completion: "partial",
      results: [
        {
          outcome: "refused",
          coverage: { coveredPaths: [], excludedPaths: ["file"], uncoveredPaths: [] },
        },
      ],
    },
  });
});
test("prior artifacts produce an explained miss and fresh work", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "file"), "x");
  expect(
    await runScan({
      ...request(root),
      priorArtifacts: [
        {
          scanId: `scan:sha256:${"0".repeat(64)}`,
          location: { kind: "file", path: join(root, "missing-artifact") },
        },
      ],
    }),
  ).toMatchObject({
    status: "assessment",
    diagnostics: [{ code: "reuse-miss" }],
    report: { results: [{ observations: [{ origin: "fresh" }] }] },
  });
});
test("contained source links retain identity and escaping links fail capture", async ({ skip }) => {
  const root = rootFixture();
  writeFileSync(join(root, "file"), "x");
  try {
    symlinkSync("file", join(root, "linked"), "file");
  } catch {
    skip();
    return;
  }
  const result = await runScan({
    ...request(root),
    detectors: [{ detectorId: "detector.unavailable", configuration: {} }],
  });
  expect(result.status).toBe("assessment");
  if (result.status === "assessment")
    expect(result.report.source.capture.entries).toContainEqual(
      expect.objectContaining({ kind: "file-link", path: "linked", target: "file" }),
    );
  symlinkSync(rootFixture(), join(root, "outside"), "dir");
  expect(await runScan(request(root))).toMatchObject({ status: "diagnostic", phase: "capture" });
});
test.each([
  false,
  true,
])("a successful sibling survives a later external detector %s cancellation", async (cancel) => {
  const root = rootFixture();
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  const controller = new AbortController(),
    nativeStat = fsBoundary.statSync(process.execPath),
    actualStat = fsBoundary.statSync;
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  vi.spyOn(process, "arch", "get").mockReturnValue("x64");
  vi.spyOn(fsBoundary, "statSync").mockImplementation(((
    path: Parameters<typeof fsBoundary.statSync>[0],
    ...args: unknown[]
  ) =>
    String(path) === "/usr/bin/bwrap" || String(path) === "/usr/local/bin/uv"
      ? nativeStat
      : Reflect.apply(actualStat, fsBoundary, [path, ...args])) as typeof fsBoundary.statSync);
  vi.spyOn(processBoundary, "processRunner").mockImplementation(async () => {
    if (cancel) controller.abort();
    return {
      code: 1,
      stdout: "",
      stderr: "external detector unavailable",
      truncated: cancel,
      ...(cancel ? { termination: "abort" as const } : {}),
    };
  });
  const result = await runScan(
    {
      ...request(root),
      detectors: [
        { detectorId: "detector.aih-native", configuration: {} },
        { detectorId: "detector.semgrep", configuration: {} },
        { detectorId: "detector.skillspector", configuration: {} },
      ],
    },
    { signal: controller.signal },
  );
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      completion: "partial",
      results: [
        {
          outcome: "succeeded",
          observations: [{ origin: "fresh" }],
          coverage: { coveredPaths: ["SKILL.md"] },
        },
        {
          outcome: cancel ? "cancelled" : "failed",
          coverage: { coveredPaths: [], uncoveredPaths: ["SKILL.md"] },
        },
        { outcome: cancel ? "cancelled" : "refused" },
      ],
    },
  });
});
test("lost detector snapshot identity cannot become a partial assessment", async () => {
  const root = rootFixture();
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  const actualTemp = fsBoundary.mkdtempSync;
  let capturedRoot = "";
  vi.spyOn(fsBoundary, "mkdtempSync").mockImplementation(((
    prefix: Parameters<typeof fsBoundary.mkdtempSync>[0],
    ...args: unknown[]
  ) => {
    const directory = Reflect.apply(actualTemp, fsBoundary, [prefix, ...args]);
    if (typeof prefix === "string" && prefix.includes("aih-scan-assessment-"))
      capturedRoot = join(directory, "snapshot");
    return directory;
  }) as typeof fsBoundary.mkdtempSync);
  // The explicit artifact transport runs after source capture. Corrupt the
  // snapshot at that public IO boundary, independently of how native analysis
  // reads its files (descriptor reads and in-memory projection are both valid).
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
    expect(capturedRoot).not.toBe("");
    writeFileSync(join(capturedRoot, "SKILL.md"), "changed source snapshot\n");
    return new Response("{}");
  });
  const result = await runScan(
    {
      ...request(root),
      priorArtifacts: [
        {
          scanId: `scan:sha256:${"0".repeat(64)}`,
          location: { kind: "https", url: "https://evidence.example.test/prior.json" },
        },
      ],
    },
    { reuseTrust: { keys: [], publishers: [] } },
  );
  expect(result).toMatchObject({ status: "diagnostic", phase: "assembly" });
  expect(result).not.toHaveProperty("scanId");
});
