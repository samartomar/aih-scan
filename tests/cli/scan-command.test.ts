import * as fsBoundary from "node:fs";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { readArtifact } from "../../src/artifact/read.js";
import { canonicalBytes } from "../../src/assessment/json.js";
import { runScan } from "../../src/assessment/run.js";
import type { ScanRunResult } from "../../src/assessment/types.js";
import * as processBoundary from "../../src/cli/process-runner.js";
import {
  runScanCommand,
  type ScanCommandIo,
  scanExitCodes,
  scanUsage,
} from "../../src/cli/scan-command.js";

vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
}));

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
/** A disposable directory. The real path keeps expectations independent of tmpdir links. */
function fixture(files: Record<string, string> = {}): string {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "aih-scan-command-test-")));
  roots.push(root);
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), text);
  }
  return root;
}
function harness(extra: Partial<ScanCommandIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: ScanCommandIo = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    ...extra,
  };
  return { io, stdout: () => out.join(""), stderr: () => err.join("") };
}

test("assesses a directory with the native and trust-lint detectors by default", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(await runScanCommand([root], run.io)).toBe(0);
  expect(run.stdout()).toMatch(/Scan ID: scan:sha256:[0-9a-f]{64}/);
  expect(run.stdout()).toContain("Completion: complete");
  expect(run.stdout()).toContain("detector.aih-native");
  expect(run.stdout()).toContain("detector.aih-trust-lint");
});

test("sends the documented request for the real path of a target relative to io.cwd", async () => {
  const parent = fixture({ "real/child/SKILL.md": "# Fixture\n" });
  // The working directory is reached through a link; the request names the real directory.
  symlinkSync(join(parent, "real"), join(parent, "alias"), "junction");
  const requests: unknown[] = [];
  const run = harness({
    cwd: join(parent, "alias"),
    runScan: (request, options) => {
      requests.push(request);
      return runScan(request, options);
    },
  });
  expect(await runScanCommand(["child"], run.io)).toBe(0);
  expect(requests).toEqual([
    {
      schema: "urn:aihq:scan:request:1.0.0",
      source: { kind: "local", path: join(parent, "real", "child") },
      selection: { paths: "all", excludedPaths: [] },
      detectors: [
        { detectorId: "detector.aih-native", configuration: {} },
        {
          detectorId: "detector.aih-trust-lint",
          configuration: { internalScopes: [], mcpConfigPaths: [] },
        },
      ],
    },
  ]);
});

const invalidCommands: [string, (root: string) => string[]][] = [
  ["no target", () => []],
  ["a missing directory", (root) => [join(root, "missing")]],
  ["a regular file", (root) => [join(root, "file.txt")]],
  ["a directory link", (root) => [join(root, "link")]],
  ["more than one target", (root) => [root, root]],
  ["an unknown detector", (root) => [root, "--detector", "detector.not-registered"]],
  [
    "a duplicated detector",
    (root) => [root, "--detector", "detector.aih-native", "--detector", "detector.aih-native"],
  ],
  ["an unknown option", (root) => [root, "--no-such-option"]],
  ["a duplicated --fail-on-findings", (root) => [root, "--fail-on-findings", "--fail-on-findings"]],
  ["a duplicated --json", (root) => [root, "--json", "--json"]],
  [
    "a duplicated --artifact",
    (root) => [root, "--artifact", join(root, "a.json"), "--artifact", join(root, "b.json")],
  ],
  ["--artifact without a value", (root) => [root, "--artifact"]],
  ["--artifact followed by another option", (root) => [root, "--artifact", "--json"]],
  ["a detector option without a value", (root) => [root, "--detector"]],
  ["a detector option followed by another option", (root) => [root, "--detector", "--detector"]],
];
test.each(invalidCommands)("refuses %s before running anything", async (_name, args) => {
  const root = fixture({ "file.txt": "text\n", "dir/SKILL.md": "# Fixture\n" });
  symlinkSync(join(root, "dir"), join(root, "link"), "junction");
  const calls: unknown[] = [];
  const run = harness({
    cwd: root,
    runScan: async (request) => {
      calls.push(request);
      throw new Error("an invalid command must not run a scan");
    },
  });
  expect(await runScanCommand(args(root), run.io)).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(run.stdout()).toBe("");
  expect(calls).toEqual([]);
});

test("--detector selects exactly the named detectors, before or after the target", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const requests: { detectors: unknown }[] = [];
  const run = harness({
    runScan: (request, options) => {
      requests.push(request as { detectors: unknown });
      return runScan(request, options);
    },
  });
  expect(
    await runScanCommand(
      ["--detector", "detector.aih-trust-lint", root, "--detector", "detector.aih-binding-gate"],
      run.io,
    ),
  ).toBe(0);
  expect(requests.map((request) => request.detectors)).toEqual([
    [
      {
        detectorId: "detector.aih-trust-lint",
        configuration: { internalScopes: [], mcpConfigPaths: [] },
      },
      { detectorId: "detector.aih-binding-gate", configuration: {} },
    ],
  ]);
  expect(run.stdout()).not.toContain("detector.aih-native");
});

test("summarizes the target and one line per detector result", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n", "docs/notes.md": "notes\n" });
  const run = harness();
  expect(await runScanCommand([root], run.io)).toBe(0);
  const lines = run.stdout().split("\n");
  expect(lines).toContain(`Target: ${root} (2 files, 3 entries)`);
  expect(lines).toContain(
    "  detector.aih-native: succeeded; origin fresh; 0 findings; coverage 2/2 complete",
  );
  expect(lines).toContain(
    "  detector.aih-trust-lint: succeeded; origin fresh; 0 findings; coverage 2/2 complete",
  );
});

const unlockedPackage = `${JSON.stringify({
  name: "fixture",
  version: "1.0.0",
  dependencies: { "left-pad": "1.3.0" },
})}\n`;
type Assessment = Extract<ScanRunResult, { status: "assessment" }>;
function assessedResult(result: ScanRunResult): Assessment {
  if (result.status !== "assessment") throw new Error("expected an assessment");
  return result;
}
function assessed(seen: { result?: ScanRunResult }): Assessment {
  if (seen.result === undefined) throw new Error("expected a result");
  return assessedResult(seen.result);
}
function recording(into: { result?: ScanRunResult }): Partial<ScanCommandIo> {
  return {
    runScan: async (request, options) => {
      into.result = await runScan(request, options);
      return into.result;
    },
  };
}
test("lists each finding with its severity, rule, location, detector and message", async () => {
  const root = fixture({ "package.json": unlockedPackage });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  // Findings alone do not fail a scan unless --fail-on-findings asks for it.
  expect(await runScanCommand([root], run.io)).toBe(0);
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  const trustLint = seen.result.report.results.find(
    (result) => result.detectorId === "detector.aih-trust-lint",
  );
  const finding = trustLint?.observations[0]?.body.findings[0];
  if (finding?.severity.state !== "present" || finding.message.state !== "present")
    throw new Error("expected a described finding");
  const lines = run.stdout().split("\n");
  expect(lines).toContain("Findings (1):");
  expect(lines).toContain(
    `  [${finding.severity.value.level}] trust.unpinned-dependency package.json:1 ` +
      `(detector.aih-trust-lint) ${finding.message.value}`,
  );
  expect(lines).toContain(
    "  detector.aih-trust-lint: succeeded; origin fresh; 1 finding; coverage 1/1 complete",
  );
});

test("caps the findings list and points to the complete outputs", async () => {
  const dependencies = Object.fromEntries(
    Array.from({ length: 30 }, (_unused, index) => [`fixture-dependency-${index}`, "*"]),
  );
  const root = fixture({
    "package.json": `${JSON.stringify({ name: "fixture", version: "1.0.0", dependencies })}\n`,
  });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(await runScanCommand([root], run.io)).toBe(0);
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  const total = seen.result.report.results
    .flatMap((result) => result.observations)
    .reduce((sum, observation) => sum + observation.body.findings.length, 0);
  expect(total).toBeGreaterThan(20);
  const lines = run.stdout().split("\n");
  expect(lines).toContain(`Findings (${total}):`);
  expect(lines.filter((line) => line.startsWith("  ["))).toHaveLength(20);
  expect(lines).toContain(
    `  ... ${total - 20} more findings not shown; use --json or --artifact for the complete list`,
  );
});

test("lists each annex with the detector that produced it and states they are not combined", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(await runScanCommand([root], run.io)).toBe(0);
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  const { report } = seen.result;
  expect(report.annexes).toHaveLength(2);
  const lines = run.stdout().split("\n");
  expect(lines).toContain("Annexes (2): per-detector evidence, never combined");
  for (const annex of report.annexes) {
    const producer = report.results.find((result) =>
      result.observations.some((observation) => observation.body.annexIds.includes(annex.id)),
    );
    expect(lines).toContain(
      `  ${annex.id} ${annex.mediaType} ${annex.byteLength} bytes, from ${producer?.detectorId}`,
    );
  }
});

test("an unavailable detector leaves a partial assessment that exits 1 and says so", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(
    await runScanCommand(
      ["--detector", "detector.aih-native", "--detector", "detector.skillspector", root],
      run.io,
    ),
  ).toBe(1);
  const lines = run.stdout().split("\n");
  expect(lines).toContain("Completion: partial");
  expect(lines).toContain(
    "  detector.aih-native: succeeded; origin fresh; 0 findings; coverage 1/1 complete",
  );
  expect(lines).toContain(
    "  detector.skillspector: refused; origin none; 0 findings; coverage 0/1 incomplete",
  );
});

test("shows the diagnostics of an unavailable detector under its result", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  await runScanCommand(
    ["--detector", "detector.aih-native", "--detector", "detector.skillspector", root],
    run.io,
  );
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  const refused = seen.result.report.results.find(
    (result) => result.detectorId === "detector.skillspector",
  );
  expect(refused?.diagnostics.map((diagnostic) => diagnostic.code)).toEqual([
    "rules-material-unavailable",
  ]);
  const lines = run.stdout().split("\n");
  const at = lines.indexOf(
    "  detector.skillspector: refused; origin none; 0 findings; coverage 0/1 incomplete",
  );
  expect(at).toBeGreaterThan(-1);
  expect(lines[at + 1]).toBe(`    rules-material-unavailable: ${refused?.diagnostics[0]?.detail}`);
});

test.each([
  ["with a finding exits 1", { "package.json": unlockedPackage }, 1],
  ["without findings exits 0", { "SKILL.md": "# Fixture\n" }, 0],
])("--fail-on-findings %s", async (_name, files, expected) => {
  const root = fixture(files);
  const run = harness();
  expect(await runScanCommand(["--fail-on-findings", root], run.io)).toBe(expected);
});

test("a diagnostic result is no assessment: it prints its diagnostics and exits 2", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness({
    runScan: async () => ({
      schema: "urn:aihq:scan:run-result:1.0.0",
      status: "diagnostic",
      phase: "capture",
      diagnostics: [{ code: "invalid-input", detail: "The source could not be captured." }],
    }),
  });
  expect(await runScanCommand([root], run.io)).toBe(2);
  const lines = run.stdout().split("\n");
  expect(lines).toContain("No assessment (capture diagnostic)");
  expect(lines).toContain("  invalid-input: The source could not be captured.");
  expect(run.stdout()).not.toContain("Scan ID");
});

test("--json writes exactly the complete canonical run result and a newline to stdout", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(await runScanCommand(["--json", root], run.io)).toBe(0);
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  expect(run.stdout()).toBe(`${new TextDecoder().decode(canonicalBytes(seen.result))}\n`);
  const written = JSON.parse(run.stdout());
  expect(Object.keys(written).sort()).toEqual([
    "annexes",
    "diagnostics",
    "report",
    "scanId",
    "schema",
    "status",
  ]);
  expect(written.schema).toBe("urn:aihq:scan:run-result:1.0.0");
  expect(written.annexes).toHaveLength(2);
});

test("writes aih-scan: assessing <target> to stderr just before running the scan", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const events: string[] = [];
  const run = harness({
    stderr: (text) => events.push(`stderr: ${text}`),
    runScan: async (request, options) => {
      events.push("runScan");
      return runScan(request, options);
    },
  });
  expect(await runScanCommand([root], run.io)).toBe(0);
  expect(events).toEqual([`stderr: aih-scan: assessing ${root}\n`, "runScan"]);
});

test("--json keeps stdout to the result and puts the status of a diagnostic on stderr", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const diagnostic: ScanRunResult = {
    schema: "urn:aihq:scan:run-result:1.0.0",
    status: "diagnostic",
    phase: "assembly",
    diagnostics: [{ code: "invalid-input", detail: "The source changed during capture." }],
  };
  const run = harness({ runScan: async () => diagnostic });
  expect(await runScanCommand(["--json", root], run.io)).toBe(2);
  expect(run.stdout()).toBe(`${new TextDecoder().decode(canonicalBytes(diagnostic))}\n`);
  expect(run.stderr()).toContain("aih-scan: no assessment (assembly diagnostic)\n");
});

test("--json keeps stdout to the result and puts the completion of a partial scan on stderr", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(
    await runScanCommand(
      ["--json", "--detector", "detector.aih-native", "--detector", "detector.skillspector", root],
      run.io,
    ),
  ).toBe(1);
  if (seen.result?.status !== "assessment") throw new Error("expected an assessment");
  expect(run.stdout()).toBe(`${new TextDecoder().decode(canonicalBytes(seen.result))}\n`);
  expect(run.stderr()).toContain(`aih-scan: ${seen.result.scanId} is partial\n`);
});

test("--artifact saves an unsigned artifact that reads back through the portable reader", async () => {
  const root = fixture({ "package.json": unlockedPackage });
  const outputs = fixture();
  const path = join(outputs, "scan.artifact.json");
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(await runScanCommand(["--artifact", path, root], run.io)).toBe(0);
  const assessment = assessed(seen);
  const bytes = readFileSync(path);
  const read = await readArtifact(new Uint8Array(bytes));
  expect(read).toMatchObject({
    status: "read",
    scanId: assessment.scanId,
    authenticity: "unchecked",
    annexBytes: "checked",
  });
  const artifact = JSON.parse(bytes.toString("utf8"));
  expect(artifact).not.toHaveProperty("attestation");
  // Every detector annex is preserved individually; none is merged into another.
  expect(artifact.annexes).toEqual(
    assessment.report.annexes.map((descriptor) => ({
      ...descriptor,
      bytesBase64: assessment.annexes.find((annex) => annex.id === descriptor.id)?.bytesBase64,
    })),
  );
  if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
  const lines = run.stdout().split("\n");
  expect(lines).toContain(`Artifact: ${path}`);
  expect(lines).toContain(
    `  unsigned; authenticity unchecked; read back through the portable reader as ${assessment.scanId}`,
  );
});

const unusableArtifactPaths: [string, (outputs: string) => string][] = [
  ["an existing file", (outputs) => join(outputs, "existing.json")],
  ["an existing directory", (outputs) => join(outputs, "dir")],
  ["an existing link", (outputs) => join(outputs, "dir-link")],
  ["a path below a linked directory", (outputs) => join(outputs, "linked", "new.json")],
  ["a path in a missing directory", (outputs) => join(outputs, "missing", "new.json")],
];
test.each(unusableArtifactPaths)("--artifact refuses %s before running", async (_name, pick) => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const outputs = fixture({ "existing.json": "keep\n", "dir/.keep": "", "real/.keep": "" });
  symlinkSync(join(outputs, "dir"), join(outputs, "dir-link"), "junction");
  symlinkSync(join(outputs, "real"), join(outputs, "linked"), "junction");
  const calls: unknown[] = [];
  const run = harness({
    runScan: async (request) => {
      calls.push(request);
      throw new Error("an unusable artifact path must be refused before the scan");
    },
  });
  expect(await runScanCommand(["--artifact", pick(outputs), root], run.io)).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(calls).toEqual([]);
  expect(readFileSync(join(outputs, "existing.json"), "utf8")).toBe("keep\n");
  expect(readdirSync(join(outputs, "real"))).toEqual([".keep"]);
});

test("--artifact tells the user to use a real path when a parent directory is a link", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const outputs = fixture({ "real/.keep": "" });
  symlinkSync(join(outputs, "real"), join(outputs, "linked"), "junction");
  const run = harness();
  expect(
    await runScanCommand(["--artifact", join(outputs, "linked", "new.json"), root], run.io),
  ).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: .*linked or non-directory parent; use a real path/);
});

test("--artifact is not saved when the file read back differs from the bytes written", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const path = join(fixture(), "scan.artifact.json");
  const actualRead = fsBoundary.readFileSync;
  vi.spyOn(fsBoundary, "readFileSync").mockImplementation(((
    target: Parameters<typeof fsBoundary.readFileSync>[0],
    ...args: unknown[]
  ) =>
    String(target) === path
      ? Buffer.from("replaced after it was written\n")
      : Reflect.apply(actualRead, fsBoundary, [
          target,
          ...args,
        ])) as typeof fsBoundary.readFileSync);
  const run = harness();
  expect(await runScanCommand(["--artifact", path, root], run.io)).toBe(2);
  expect(run.stderr()).toContain(
    "aih-scan: artifact not saved: the saved artifact differs from the bytes that were written\n",
  );
  expect(run.stdout()).not.toContain("Artifact:");
});

test("--artifact never replaces a file that appears while the scan runs", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const outputs = fixture();
  const path = join(outputs, "scan.artifact.json");
  const seen: { result?: ScanRunResult } = {};
  const run = harness({
    runScan: async (request, options) => {
      writeFileSync(path, "created by someone else\n");
      return recording(seen).runScan?.(request, options) as Promise<ScanRunResult>;
    },
  });
  expect(await runScanCommand(["--artifact", path, root], run.io)).toBe(2);
  expect(readFileSync(path, "utf8")).toBe("created by someone else\n");
  expect(run.stderr()).toMatch(/aih-scan: artifact not saved: /);
  // The assessment itself is still reported.
  expect(run.stdout()).toContain(`Scan ID: ${assessed(seen).scanId}`);
});

test("--artifact refuses a parent directory that becomes a link while the scan runs", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const outputs = fixture({ "sub/.keep": "" });
  const run = harness({
    runScan: async (request, options) => {
      renameSync(join(outputs, "sub"), join(outputs, "moved"));
      symlinkSync(join(outputs, "moved"), join(outputs, "sub"), "junction");
      return runScan(request, options);
    },
  });
  expect(
    await runScanCommand(["--artifact", join(outputs, "sub", "scan.artifact.json"), root], run.io),
  ).toBe(2);
  expect(readdirSync(join(outputs, "moved"))).toEqual([".keep"]);
  expect(run.stderr()).toMatch(/aih-scan: artifact not saved: /);
});

test("--artifact preserves a partial assessment and exits 1", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const path = join(fixture(), "partial.artifact.json");
  const seen: { result?: ScanRunResult } = {};
  const run = harness(recording(seen));
  expect(
    await runScanCommand(
      [
        "--artifact",
        path,
        "--detector",
        "detector.aih-native",
        "--detector",
        "detector.skillspector",
        root,
      ],
      run.io,
    ),
  ).toBe(1);
  const read = await readArtifact(new Uint8Array(readFileSync(path)));
  expect(read).toMatchObject({ status: "read", scanId: assessed(seen).scanId });
  if (read.status !== "read") throw new Error("expected a readable artifact");
  expect(read.report.completion).toBe("partial");
  expect(read.report.results.map((result) => [result.detectorId, result.outcome])).toEqual([
    ["detector.aih-native", "succeeded"],
    ["detector.skillspector", "refused"],
  ]);
});

test("--artifact writes nothing for a diagnostic result", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const path = join(fixture(), "none.artifact.json");
  const run = harness({
    runScan: async () => ({
      schema: "urn:aihq:scan:run-result:1.0.0",
      status: "diagnostic",
      phase: "capture",
      diagnostics: [{ code: "invalid-input", detail: "The source could not be captured." }],
    }),
  });
  expect(await runScanCommand(["--artifact", path, root], run.io)).toBe(2);
  expect(existsSync(path)).toBe(false);
});

test("a cancellation requested before the scan exits 130 and yields no Scan ID", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const cancellation = new AbortController();
  cancellation.abort();
  const run = harness({ cancellation: cancellation.signal });
  expect(await runScanCommand(["--json", root], run.io)).toBe(130);
  const written = JSON.parse(run.stdout());
  expect(written).toMatchObject({ status: "diagnostic", phase: "capture" });
  expect(written).not.toHaveProperty("scanId");
  expect(run.stderr()).toContain("aih-scan: cancelled; no assessment was produced\n");
});

test("a cancellation during an external detector exits 130 and keeps the finished work", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const path = join(fixture(), "cancelled.artifact.json");
  const cancellation = new AbortController();
  // The external detector's process boundary is simulated, as in the assessment host tests.
  const nativeStat = fsBoundary.statSync(process.execPath);
  const actualStat = fsBoundary.statSync;
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  vi.spyOn(process, "arch", "get").mockReturnValue("x64");
  vi.spyOn(fsBoundary, "statSync").mockImplementation(((
    target: Parameters<typeof fsBoundary.statSync>[0],
    ...args: unknown[]
  ) =>
    String(target) === "/usr/bin/bwrap" || String(target) === "/usr/local/bin/uv"
      ? nativeStat
      : Reflect.apply(actualStat, fsBoundary, [target, ...args])) as typeof fsBoundary.statSync);
  vi.spyOn(processBoundary, "processRunner").mockImplementation(async () => {
    cancellation.abort();
    return {
      code: 1,
      stdout: "",
      stderr: "external detector unavailable",
      truncated: true,
      termination: "abort" as const,
    };
  });
  const seen: { result?: ScanRunResult } = {};
  const run = harness({ ...recording(seen), cancellation: cancellation.signal });
  expect(
    await runScanCommand(
      [
        "--artifact",
        path,
        "--detector",
        "detector.aih-native",
        "--detector",
        "detector.semgrep",
        // Reached only after the abort: it is cancelled, not refused, if the signal arrived.
        "--detector",
        "detector.skillspector",
        root,
      ],
      run.io,
    ),
  ).toBe(130);
  const assessment = assessed(seen);
  expect(assessment.report.results.map((result) => [result.detectorId, result.outcome])).toEqual([
    ["detector.aih-native", "succeeded"],
    ["detector.semgrep", "cancelled"],
    ["detector.skillspector", "cancelled"],
  ]);
  const lines = run.stdout().split("\n");
  expect(lines).toContain(
    "  detector.aih-native: succeeded; origin fresh; 0 findings; coverage 1/1 complete",
  );
  expect(lines).toContain(
    "  detector.semgrep: cancelled; origin none; 0 findings; coverage 0/1 incomplete",
  );
  expect(run.stderr()).toContain("aih-scan: cancelled; finished results are preserved\n");
  const read = await readArtifact(new Uint8Array(readFileSync(path)));
  expect(read).toMatchObject({ status: "read", scanId: assessment.scanId });
});

test("prints report and run diagnostics, and says when there are none", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const quiet = harness();
  await runScanCommand([root], quiet.io);
  expect(quiet.stdout().split("\n")).toContain("Diagnostics: none");

  const noisy = harness({
    runScan: async (request, options) => {
      const result = assessedResult(await runScan(request, options));
      result.report.diagnostics.push({ code: "reuse-miss", detail: "Prior work was not reused." });
      result.diagnostics.push({ code: "run-note", detail: "Run-level note." });
      return result;
    },
  });
  await runScanCommand([root], noisy.io);
  const lines = noisy.stdout().split("\n");
  const at = lines.indexOf("Diagnostics (2):");
  expect(at).toBeGreaterThan(-1);
  expect(lines.slice(at + 1, at + 3)).toEqual([
    "  reuse-miss: Prior work was not reused.",
    "  run-note: Run-level note.",
  ]);
});

/** Everything the terminal could interpret: any control or format character except the line end. */
function terminalControls(text: string): string[] {
  return [...text].filter((character) => character !== "\n" && /\p{C}/u.test(character));
}
// Built from code points so the source itself holds no control or bidirectional character.
const esc = String.fromCharCode(0x1b);
const bell = String.fromCharCode(0x07);
const bidiOverride = String.fromCodePoint(0x202e);
const replacement = String.fromCodePoint(0xfffd);
test("detector and report text cannot drive the terminal or forge output lines", async () => {
  const root = fixture({ "package.json": unlockedPackage });
  const run = harness({
    runScan: async (request, options) => {
      const result = assessedResult(await runScan(request, options));
      const trustLint = result.report.results.find(
        (detector) => detector.detectorId === "detector.aih-trust-lint",
      );
      const observation = trustLint?.observations[0];
      const finding = observation?.body.findings[0];
      if (!trustLint || !observation || !finding) throw new Error("expected a finding");
      trustLint.diagnostics.push({
        code: "crafted",
        detail: `${esc}[31mred${bell}${esc}]0;title${bell}`,
      });
      finding.rule = { state: "present", value: { nativeRuleId: `rule${esc}[2J` } };
      finding.severity = { state: "present", value: { level: `high${bell}` } };
      finding.message = {
        state: "present",
        value: `first\nScan ID: scan:sha256:forged\r${bidiOverride}last\t${esc}`,
      };
      result.report.diagnostics.push({ code: "report-note", detail: `report${esc}[0m` });
      result.diagnostics.push({ code: "run-note", detail: `run${bell}` });
      result.report.annexes[0] = {
        ...(result.report.annexes[0] as (typeof result.report.annexes)[number]),
        id: `annex.x${esc}[1m`,
        mediaType: `application/x${esc}[1m`,
      };
      if (finding.location.state === "present")
        finding.location.value.path = `dir${bell}/package.json`;
      trustLint.detectorId = `detector.x${bidiOverride}`;
      return result;
    },
  });
  await runScanCommand([root], run.io);
  const out = run.stdout();
  expect(terminalControls(out)).toEqual([]);
  // Newlines inside detector text cannot start a forged line of their own.
  expect(out.split("\n").filter((line) => line.startsWith("Scan ID:"))).toHaveLength(1);
  expect(out).toContain(`${replacement}[31mred${replacement}${replacement}]0;title${replacement}`);
  expect(out).toContain(`first Scan ID: scan:sha256:forged ${replacement}last ${replacement}`);
});

test.each([
  ["a detector name", (root: string) => [root, "--detector", `detector.${esc}[2J${bell}`]],
  ["an option name", (root: string) => [root, `--${esc}[2J${bell}`]],
  ["a target name", (root: string) => [join(root, `missing${esc}[2J${bell}`)]],
])("an argument error echoing %s cannot drive the terminal", async (_name, args) => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness({ cwd: root });
  expect(await runScanCommand(args(root), run.io)).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: .*\n$/);
  expect(terminalControls(run.stderr())).toEqual([]);
});

test.each([
  ["--help"],
  ["-h"],
])("%s prints the usage with every option and exit code", async (flag) => {
  const run = harness();
  expect(await runScanCommand([flag], run.io)).toBe(0);
  expect(run.stdout()).toBe(scanUsage);
  expect(scanUsage.startsWith("Usage: aih-scan scan <directory>")).toBe(true);
  for (const documented of [
    "--detector <id>",
    "--json",
    "--artifact <new-file>",
    "--fail-on-findings",
    "detector.aih-native",
    "detector.aih-trust-lint",
    "0  ",
    "1  ",
    "2  ",
    "130  ",
  ])
    expect(scanUsage).toContain(documented);
  expect(scanExitCodes).toEqual({
    complete: 0,
    incomplete: 1,
    findings: 1,
    invalid: 2,
    cancelled: 130,
  });
  expect(run.stderr()).toBe("");
});

test("an artifact that cannot be saved outranks an incomplete assessment: exit 2, not 1", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const path = join(fixture(), "scan.artifact.json");
  const run = harness({
    runScan: async (request, options) => {
      writeFileSync(path, "created by someone else\n");
      return runScan(request, options);
    },
  });
  expect(
    await runScanCommand(
      [
        "--artifact",
        path,
        "--detector",
        "detector.aih-native",
        "--detector",
        "detector.skillspector",
        root,
      ],
      run.io,
    ),
  ).toBe(2);
  expect(run.stdout()).toContain("Completion: partial");
});

test("an incomplete assessment with findings and --fail-on-findings still exits 1", async () => {
  const root = fixture({ "package.json": unlockedPackage });
  const run = harness();
  expect(
    await runScanCommand(
      [
        "--fail-on-findings",
        "--detector",
        "detector.aih-trust-lint",
        "--detector",
        "detector.skillspector",
        root,
      ],
      run.io,
    ),
  ).toBe(1);
  expect(run.stdout()).toContain("Completion: partial");
});

test("--json with --artifact keeps stdout to the result and reports the artifact on stderr", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const outputs = fixture();
  const seen: { result?: ScanRunResult } = {};
  const run = harness({ ...recording(seen), cwd: outputs });
  // A relative artifact path resolves against io.cwd, like a relative target.
  expect(await runScanCommand(["--json", "--artifact", "scan.artifact.json", root], run.io)).toBe(
    0,
  );
  expect(run.stdout()).toBe(`${new TextDecoder().decode(canonicalBytes(assessed(seen)))}\n`);
  expect(run.stderr()).toContain(`Artifact: ${join(outputs, "scan.artifact.json")}\n`);
  const read = await readArtifact(
    new Uint8Array(readFileSync(join(outputs, "scan.artifact.json"))),
  );
  expect(read).toMatchObject({ status: "read", scanId: assessed(seen).scanId });
});
