import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import {
  admitDetectorDefinitionsV1,
  isAdmittedSemgrepDefinitionV1,
  type SuppliedDetectorDefinitionV1,
} from "../../src/assessment/detector-definition.js";
import { sha256 } from "../../src/assessment/json.js";
import { createRetainedObservationsV1, runScan } from "../../src/public/host.js";
import * as runner from "../../src/runner/run-detector-v1.js";

vi.mock("../../src/runner/run-detector-v1.js", async (original) => ({
  ...(await original<typeof import("../../src/runner/run-detector-v1.js")>()),
}));
const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
async function bundle(
  id = "organization.review",
  revision = "one",
  text = "rules: []\n",
): Promise<SuppliedDetectorDefinitionV1> {
  const rules = new TextEncoder().encode(text);
  return {
    definition: {
      schema: "urn:aihq:scan:detector-definition:1.0.0",
      detectorId: id,
      version: revision,
      adapter: "semgrep-sarif-v1",
      profileId: "host-process-uv-v1",
      rules: { sha256: await sha256(rules), byteLength: rules.length },
    },
    rules,
  };
}
test("admission snapshots exact bytes and mints immutable custody", async () => {
  const supplied = await bundle();
  const pending = admitDetectorDefinitionsV1([supplied]);
  supplied.rules.fill(0);
  const admitted = (await pending).get(supplied.definition.detectorId);
  if (!admitted) throw new Error("Missing admitted definition");
  expect(admitted.rules.utf8).toBe("rules: []\n");
  expect(isAdmittedSemgrepDefinitionV1(admitted)).toBe(true);
  expect(isAdmittedSemgrepDefinitionV1({ ...admitted })).toBe(false);
  expect(Object.isFrozen(admitted.rules)).toBe(true);
});
test("invalid bundles are rejected before source capture", async () => {
  const valid = await bundle();
  const invalid = [
    [valid, valid],
    [await bundle("detector.aih-native")],
    [{ ...valid, rules: new Uint8Array([0]) }],
    [{ ...valid, definition: { ...valid.definition, command: "anything" } }],
    [{ ...valid, definition: { ...valid.definition, adapter: "arbitrary" } }],
    [{ ...valid, definition: { ...valid.definition, profileId: "arbitrary" } }],
    [
      {
        ...valid,
        definition: { ...valid.definition, rules: { ...valid.definition.rules, byteLength: 1 } },
      },
    ],
  ];
  for (const detectorDefinitions of invalid) {
    const result = await runScan(
      {
        schema: "urn:aihq:scan:request:1.0.0",
        source: { kind: "local", path: "/missing-source" },
        selection: { paths: "all", excludedPaths: [] },
        detectors: [{ detectorId: "organization.review", configuration: {} }],
      },
      { detectorDefinitions: detectorDefinitions as SuppliedDetectorDefinitionV1[] },
    );
    expect(result).toMatchObject({ status: "diagnostic", phase: "request" });
  }
  const invalidUtf8 = new Uint8Array([0xff]);
  await expect(
    admitDetectorDefinitionsV1([
      {
        ...valid,
        rules: invalidUtf8,
        definition: {
          ...valid.definition,
          rules: { sha256: await sha256(invalidUtf8), byteLength: 1 },
        },
      },
    ]),
  ).rejects.toThrow("UTF-8");
});
test("custom definitions bind revisions and retain eligible built-in siblings", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-definition-"));
  roots.push(root);
  writeFileSync(join(root, "a.js"), "eval('x')\n");
  const supplied = await bundle();
  const request = {
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: root },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [
      { detectorId: "detector.aih-binding-gate", configuration: {} },
      { detectorId: supplied.definition.detectorId, configuration: {} },
    ],
  };
  const run = vi.spyOn(runner, "runDefinedDetectorV1").mockImplementation(async () => ({
    outcome: "refused",
    reason: "execution-profile-unavailable",
    detail: "fixture unavailable",
    host: { os: process.platform, architecture: process.arch },
  }));
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { detectorDefinitions: [supplied], retained });
  const next = await runScan(request, {
    detectorDefinitions: [await bundle(undefined, "two", "rules: []\n# revision\n")],
    retained,
  });
  expect(run).toHaveBeenCalledTimes(2);
  expect(first.status).toBe("assessment");
  expect(next.status).toBe("assessment");
  if (next.status !== "assessment") return;
  expect(next.report.completion).toBe("partial");
  expect(
    next.report.results.find((unit) => unit.detectorId === "detector.aih-binding-gate")
      ?.observations[0]?.origin,
  ).toBe("reused");
  expect(
    next.report.results.find((unit) => unit.detectorId === supplied.definition.detectorId)?.outcome,
  ).toBe("refused");
  expect(run.mock.calls[0]?.[1].definitionSha256).not.toBe(run.mock.calls[1]?.[1].definitionSha256);
});
test("new IDs produce portable observations with distinct definition and native versions", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-definition-success-"));
  roots.push(root);
  writeFileSync(join(root, "a.js"), "const a = 1;\n");
  const first = await bundle("organization.first", "author-revision-one");
  const second = await bundle(
    "organization.second",
    "author-revision-two",
    "rules: []\n# second\n",
  );
  const nativeVersions: string[] = [];
  vi.spyOn(runner, "runDefinedDetectorV1").mockImplementation(async (request) => {
    const native = await runner.runDetectorV1({
      detectorId: "detector.aih-native",
      subject: request.subject,
    });
    if (
      native.outcome === "succeeded" &&
      native.evidence.kind === "baseline-analyzer-observation-v1"
    )
      nativeVersions.push(native.evidence.observation.analyzerVersion);
    return native;
  });
  const request = {
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: root },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [first, second].map(({ definition }) => ({
      detectorId: definition.detectorId,
      configuration: {},
    })),
  };
  const result = await runScan(request, { detectorDefinitions: [first, second] });
  expect(result.status).toBe("assessment");
  if (result.status !== "assessment") return;
  expect(result.report.completion).toBe("complete");
  expect(nativeVersions).toHaveLength(2);
  expect(nativeVersions).not.toContain(first.definition.version);
  expect(nativeVersions).not.toContain(second.definition.version);
  for (const supplied of [first, second]) {
    const input = result.report.results.find(
      (unit) => unit.detectorId === supplied.definition.detectorId,
    )?.observations[0]?.body.input;
    expect(input).toMatchObject({
      detectorId: supplied.definition.detectorId,
      detectorVersion: supplied.definition.version,
      rulesSha256: supplied.definition.rules.sha256,
      scopeKind: "source-tree",
    });
  }
  const updated = await bundle(
    "organization.first",
    "author-revision-three",
    "rules: []\n# changed\n",
  );
  const changed = await runScan(request, { detectorDefinitions: [updated, second] });
  expect(changed.status).toBe("assessment");
  if (changed.status !== "assessment") return;
  expect(changed.report.results[0]?.observations[0]?.body.input.adapterSha256).not.toBe(
    result.report.results[0]?.observations[0]?.body.input.adapterSha256,
  );
  expect(changed.report.results[1]?.observations[0]?.body.input.adapterSha256).toBe(
    result.report.results[1]?.observations[0]?.body.input.adapterSha256,
  );
});
