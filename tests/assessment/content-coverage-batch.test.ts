import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, expectTypeOf, test } from "vitest";
import { canonicalBytes, observationIdFor, sha256 } from "../../src/assessment/json.js";
import type {
  ContentDescriptor,
  ReadContentCoverageBatchResult,
  ReadContentCoverageResult,
  ReportBody,
} from "../../src/assessment/types.js";
import { runScan } from "../../src/public/host.js";
import {
  coverageBatchLimits,
  maxContentDescriptors,
  readContentCoverage,
  readContentCoverageBatch,
  readReport,
} from "../../src/public/read.js";

const report: ReportBody = JSON.parse(
  readFileSync("schemas/examples/1.0.0.json", "utf8"),
).examples.find((entry: { format: string }) => entry.format === "urn:aihq:scan:report:1.0.0").valid;
const skill = {
  path: "SKILL.md",
  sha256: "f8185998ec464c5c9d5fe35c2157e0ad2593c5d5224797b24060a016df079d77",
  byteLength: 138,
};

test("independent coverage rows preserve singleton results and share one observation payload", async () => {
  const read = await readReport(canonicalBytes(report));
  const queries = [
    { descriptors: [skill] },
    { descriptors: [{ ...skill, sha256: "0".repeat(64) }] },
    { descriptors: [skill] },
  ];
  const batch = await readContentCoverageBatch({ read, queries });
  expect(batch.status).toBe("complete");
  if (batch.status !== "complete") throw new Error("batch refused");
  expect(batch.observations).toHaveLength(1);
  expectTypeOf(batch.observations[0]!.coverage.coveredPaths).toEqualTypeOf<readonly string[]>();
  const first = batch.results[0]!;
  if (first.status === "matched")
    expectTypeOf(first.observationIndexes).toEqualTypeOf<readonly number[]>();
  for (const [index, query] of queries.entries()) {
    const row = batch.results[index]!;
    const expanded =
      row.status === "matched"
        ? (({ observationIndexes, ...rest }) => ({
            ...rest,
            observations: observationIndexes.map((at) => batch.observations[at]),
          }))(row)
        : row;
    expect(expanded).toEqual(await readContentCoverage({ read, ...query }));
  }
});

test("invalid individual query shapes do not discard valid rows", async () => {
  const read = await readReport(canonicalBytes(report));
  const batch = await readContentCoverageBatch({
    read,
    queries: [
      null,
      { descriptors: [skill] },
      { descriptors: [] },
      { descriptors: [skill], trusted: true },
    ],
  } as never);
  expect(batch.status).toBe("complete");
  if (batch.status !== "complete") throw new Error("batch refused");
  expect(batch.results.map((row) => row.status)).toEqual([
    "invalid",
    "matched",
    "invalid",
    "invalid",
  ]);
});

test("snapshots all input before yielding and freezes shared output against cross-query mutation", async () => {
  const read = await readReport(canonicalBytes(report));
  if (read.status !== "read") throw new Error("fixture invalid");
  const queries = [{ descriptors: [{ ...skill }] }, { descriptors: [{ ...skill }] }];
  const pending = readContentCoverageBatch({ read, queries });
  queries[0]!.descriptors[0]!.path = "MUTATED.md";
  read.scanId = `scan:sha256:${"0".repeat(64)}`;
  read.report.results[0]!.observations[0]!.body.input.detectorVersion = "mutated";
  const batch = await pending;
  expect(batch.status).toBe("complete");
  if (batch.status !== "complete") throw new Error("batch refused");
  expect(batch.results.map((row) => row.status)).toEqual(["matched", "matched"]);
  expect(Object.isFrozen(batch.observations[0]!.detector.platform)).toBe(true);
  expect(() => {
    Array.prototype.push.call(batch.observations[0]!.coverage.coveredPaths, "MUTATED.md");
  }).toThrow(TypeError);
  expect(() => {
    if (batch.results[0]!.status === "matched")
      Object.defineProperty(batch.results[0]!.observationIndexes, "0", { value: 100 });
  }).toThrow(TypeError);
  expect(batch.results[1]).toMatchObject({ observationIndexes: [0] });
  const future = await readContentCoverageBatch({ read, queries: [{ descriptors: [skill] }] });
  expect(future).toMatchObject({
    status: "complete",
    results: [{ status: "unavailable", reason: "invalid-read" }],
  });
});

test("unsupported and invalid reads retain per-query descriptor error precedence", async () => {
  for (const read of [
    await readReport(new TextEncoder().encode("{}")),
    await readReport(new TextEncoder().encode('{"schema":"urn:aihq:scan:report:99.0.0"}')),
  ]) {
    const batch = await readContentCoverageBatch({
      read,
      queries: [{ descriptors: [] }, { descriptors: [skill] }],
    });
    expect(batch.status).toBe("complete");
    if (batch.status !== "complete") throw new Error("batch refused");
    expect(batch.results[0]).toEqual(await readContentCoverage({ read, descriptors: [] }));
    expect(batch.results[1]).toEqual(await readContentCoverage({ read, descriptors: [skill] }));
  }
});

function expand(batch: ReadContentCoverageBatchResult, at: number): ReadContentCoverageResult {
  if (batch.status !== "complete") throw new Error("batch refused");
  const row = batch.results[at]!;
  if (row.status !== "matched") return structuredClone(row) as ReadContentCoverageResult;
  const { observationIndexes, ...rest } = row;
  return structuredClone({
    ...rest,
    observations: observationIndexes.map((index) => batch.observations[index]!),
  }) as ReadContentCoverageResult;
}

async function assembled(value: ReportBody) {
  value.source.capture.entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  value.source.capture.captureSha256 = await sha256(
    canonicalBytes({
      domain: "aih.scan.capture.v1",
      profile: value.source.capture.profile,
      entries: value.source.capture.entries,
    }),
  );
  for (const result of value.results) {
    for (const observation of result.observations)
      observation.observationId = await observationIdFor(observation.body);
    result.observations.sort((a, b) => (a.observationId < b.observationId ? -1 : 1));
  }
  const read = await readReport(canonicalBytes(value));
  expect(read.status).toBe("read");
  return read;
}

test("independent groups preserve closure omissions, incomplete coverage and refused/failed detector gaps", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-batch-groups-"));
  try {
    writeFileSync(join(root, "A.md"), "# A\n");
    writeFileSync(join(root, "B.md"), "# B\n");
    const run = await runScan({
      schema: "urn:aihq:scan:request:1.0.0",
      source: { kind: "local", path: root },
      selection: { paths: ["A.md"], excludedPaths: [] },
      detectors: [
        { detectorId: "detector.aih-native", configuration: {} },
        { detectorId: "detector.aih-binding-gate", configuration: {} },
        { detectorId: "detector.unavailable", configuration: {} },
      ],
    });
    if (run.status !== "assessment") throw new Error("fixture assessment failed");
    const descriptors: ContentDescriptor[] = run.report.source.capture.entries.flatMap((entry) =>
      "sha256" in entry
        ? [{ path: entry.path, sha256: entry.sha256, byteLength: entry.byteLength }]
        : [],
    );
    const queries = [
      [descriptors[0]!],
      [descriptors[1]!],
      descriptors,
      [{ ...descriptors[0]!, byteLength: 999 }],
    ];
    for (const failed of [false, true]) {
      const value = structuredClone(run.report);
      if (failed) {
        const native = value.results.find((result) => result.detectorId === "detector.aih-native")!;
        native.outcome = "failed";
        native.diagnostics = [
          { code: "detector-failed", detail: "Retained observation before failure" },
        ];
      }
      const read = await assembled(value);
      const batch = await readContentCoverageBatch({
        read,
        queries: queries.map((descriptors) => ({ descriptors })),
      });
      for (const [at, descriptors] of queries.entries())
        expect(expand(batch, at)).toEqual(await readContentCoverage({ read, descriptors }));
      expect(expand(batch, 0)).toMatchObject({
        status: "matched",
        detectorsWithoutCoverage: failed
          ? ["detector.aih-native", "detector.unavailable"]
          : ["detector.unavailable"],
      });
      expect(expand(batch, 2)).toMatchObject({
        status: "matched",
        observations: [],
        excluded: {
          "input-missing-descriptor": 1,
          "coverage-incomplete": failed ? 0 : 1,
          "detector-not-succeeded": failed ? 1 : 0,
        },
      });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("file links match exact bytes, directories mismatch and findings outside queries keep supporting annexes", async () => {
  const value = structuredClone(report);
  const entries = value.source.capture.entries;
  const file = entries.find((entry) => entry.path === skill.path)!;
  if (file.kind !== "file") throw new Error("fixture missing file");
  entries.push(
    { ...file, path: "OTHER.md" },
    { ...file, kind: "file-link", path: "ALIAS.md", target: skill.path },
    { kind: "directory", path: "folder" },
  );
  const observation = value.results[0]!.observations[0]!;
  observation.body.input.entries = entries;
  value.selection.paths = ["ALIAS.md", "OTHER.md", "SKILL.md"];
  observation.body.input.targetPaths = [...value.selection.paths];
  observation.body.coverage.coveredPaths = [...value.selection.paths];
  value.results[0]!.coverage.coveredPaths = [...value.selection.paths];
  observation.body.findings = [
    {
      rawOccurrenceFingerprint: `raw-occurrence-v1:${"f".repeat(64)}`,
      multiplicity: 1,
      rule: { state: "present", value: { nativeRuleId: "fixture.rule" } },
      severity: { state: "unavailable", reason: "not-declared", detail: "fixture" },
      message: { state: "present", value: "Outside query" },
      location: {
        state: "present",
        value: { path: "OTHER.md", fileSha256: skill.sha256, startLine: 1 },
      },
      supportingEvidence: {
        state: "present",
        value: { annexId: value.annexes[0]!.id, ordinal: 0 },
      },
    },
  ];
  const read = await assembled(value);
  const queries = [
    [skill],
    [{ ...skill, path: "ALIAS.md" }],
    [{ ...skill, path: "folder" }],
    [skill, { ...skill, path: "OTHER.md" }],
    [{ ...skill, path: "ALIAS.md", sha256: "0".repeat(64) }],
  ];
  const batch = await readContentCoverageBatch({
    read,
    queries: queries.map((descriptors) => ({ descriptors })),
  });
  for (const [at, descriptors] of queries.entries())
    expect(expand(batch, at)).toEqual(await readContentCoverage({ read, descriptors }));
  expect(expand(batch, 1)).toMatchObject({
    status: "matched",
    observations: [
      { findings: [{ location: { value: { path: "OTHER.md" } } }], annexes: value.annexes },
    ],
  });
  expect(expand(batch, 2)).toMatchObject({ status: "mismatched", unmatchedPaths: ["folder"] });
});

test("aggregate request limits refuse globally before inspecting the read", async () => {
  let touched = false;
  const read = {
    get status() {
      touched = true;
      throw new Error("must not admit");
    },
  };
  const cases = [
    Array.from({ length: coverageBatchLimits.maxQueries + 1 }, () => ({ descriptors: [skill] })),
    Array.from({ length: 6 }, () => ({
      descriptors: Array.from({ length: maxContentDescriptors }, (_, at) => ({
        ...skill,
        path: `f${at}`,
      })),
    })),
    [{ descriptors: [{ ...skill, path: "x".repeat(coverageBatchLimits.maxRequestBytes + 1) }] }],
    [{ descriptors: [skill], nested: [[[[[[[[[{}]]]]]]]]] }],
  ];
  for (const queries of cases) {
    expect(await readContentCoverageBatch({ read, queries } as never)).toMatchObject({
      status: "invalid",
      diagnostics: [{ code: "resource-limit" }],
    });
  }
  expect(touched).toBe(false);
});

test("malformed batch envelopes and accessor/sparse/cyclic queries fail closed without invoking getters", async () => {
  let invoked = false;
  const accessor = {
    get descriptors() {
      invoked = true;
      return [skill];
    },
  };
  const cycle: unknown[] = [];
  cycle.push(cycle);
  const read = await readReport(canonicalBytes(report));
  for (const input of [
    null,
    { read, queries: [] },
    { read, queries: [{ descriptors: [skill] }], trusted: true },
    { read, queries: [accessor] },
    { read, queries: Array(1) },
    { read, queries: cycle },
  ]) {
    expect((await readContentCoverageBatch(input as never)).status).toBe("invalid");
  }
  expect(invoked).toBe(false);
});

test("retains the ten-thousand descriptor single-query boundary", async () => {
  const read = await readReport(canonicalBytes(report));
  const descriptors = Array.from({ length: maxContentDescriptors }, (_, at) => ({
    ...skill,
    path: `f${at}`,
  }));
  const batch = await readContentCoverageBatch({ read, queries: [{ descriptors }] });
  expect(expand(batch, 0)).toEqual(await readContentCoverage({ read, descriptors }));
  expect(expand(batch, 0)).toMatchObject({
    status: "mismatched",
    unmatchedPaths: expect.arrayContaining(["f0", "f9999"]),
  });
});

test("bounds shared-path classification work and repeated detector-gap output without returning partial rows", async () => {
  const value = structuredClone(report);
  const prototype = value.requestedDetectors[0]!;
  const count = 240;
  for (let at = 0; at < count; at++) {
    const detectorId = `z${String(at).padStart(4, "0")}${"x".repeat(240)}`;
    value.requestedDetectors.push({ ...prototype, detectorId });
    value.results.push({
      detectorId,
      outcome: "refused",
      observations: [],
      coverage: {
        coveredPaths: [],
        excludedPaths: [],
        uncoveredPaths: [skill.path],
        complete: false,
      },
      diagnostics: [{ code: "fixture-refused", detail: "fixture" }],
    });
  }
  value.completion = "partial";
  const read = await assembled(value);
  const response = await readContentCoverageBatch({
    read,
    queries: Array.from({ length: 1000 }, () => ({ descriptors: [skill] })),
  });
  expect(response).toMatchObject({
    status: "invalid",
    diagnostics: [{ code: "resource-limit", detail: expect.stringContaining("response bytes") }],
  });
  expect(response).not.toHaveProperty("results");
  const descriptors = Array.from({ length: 1000 }, (_, at) => ({ ...skill, path: `f${at}` }));
  const work = await readContentCoverageBatch({
    read,
    queries: Array.from({ length: 50 }, () => ({ descriptors })),
  });
  // Report result units alone exceed the bounded cumulative classification budget.
  expect(work).toMatchObject({
    status: "invalid",
    diagnostics: [
      { code: "resource-limit", detail: expect.stringContaining("classification work") },
    ],
  });
});

test("bounds association amplification even when observation payloads are shared", async () => {
  const value = structuredClone(report);
  const request = structuredClone(value.requestedDetectors[0]!);
  const result = structuredClone(value.results[0]!);
  value.requestedDetectors = [];
  value.results = [];
  for (let at = 0; at < 26; at++) {
    const detectorId = `fixture.detector${String(at).padStart(2, "0")}`;
    value.requestedDetectors.push({ ...request, detectorId });
    const next = structuredClone(result);
    next.detectorId = detectorId;
    next.observations[0]!.body.input.detectorId = detectorId;
    value.results.push(next);
  }
  const read = await assembled(value);
  const accepted = await readContentCoverageBatch({
    read,
    queries: Array.from({ length: 3846 }, () => ({ descriptors: [skill] })),
  });
  expect(accepted.status).toBe("complete");
  if (accepted.status !== "complete") throw new Error("batch refused");
  expect(accepted.observations).toHaveLength(26);
  expect(accepted.results).toHaveLength(3846);
  const refused = await readContentCoverageBatch({
    read,
    queries: Array.from({ length: 4096 }, () => ({ descriptors: [skill] })),
  });
  expect(refused).toMatchObject({
    status: "invalid",
    diagnostics: [
      { code: "resource-limit", detail: expect.stringContaining("observation associations") },
    ],
  });
  expect(refused).not.toHaveProperty("results");
});

test("closed batch envelopes reject hidden/symbol fields and read accessors", async () => {
  const read = await readReport(canonicalBytes(report));
  let invoked = false;
  const inputs = [
    Object.defineProperty({ read, queries: [{ descriptors: [skill] }] }, "trusted", {
      value: true,
    }),
    { read, queries: [{ descriptors: [skill] }], [Symbol("trusted")]: true },
    {
      queries: [{ descriptors: [skill] }],
      get read() {
        invoked = true;
        return read;
      },
    },
  ];
  for (const input of inputs)
    expect((await readContentCoverageBatch(input)).status).toBe("invalid");
  expect(invoked).toBe(false);
});
