import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "vitest";
import { createRetainedObservationsV1, runScan } from "../../src/public/host.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test("an unrelated source change preserves binding's complete selected closure while whole-tree work reruns", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-selected-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Selected skill\n");
  writeFileSync(join(root, "unselected.txt"), "before\n");
  const request = {
    schema: "urn:aihq:scan:request:1.0.0" as const,
    source: { kind: "local" as const, path: root },
    selection: { paths: ["SKILL.md"], excludedPaths: [] },
    detectors: [
      { detectorId: "detector.aih-binding-gate", configuration: {} },
      { detectorId: "detector.aih-native", configuration: {} },
      { detectorId: "detector.unavailable", configuration: {} },
    ],
  };
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { retained });
  expect(first.status).toBe("assessment");
  if (first.status !== "assessment") return;
  expect(first.report.results.map((result) => result.outcome)).toEqual([
    "succeeded",
    "succeeded",
    "refused",
  ]);
  const original = structuredClone(first.report.results[0]!.observations[0]!);

  writeFileSync(join(root, "unselected.txt"), "after\n");
  const second = await runScan(request, { retained });
  expect(second.status).toBe("assessment");
  if (second.status !== "assessment") return;
  const [binding, native, unavailable] = second.report.results;
  expect(binding!.observations[0]!.origin).toBe("reused");
  expect(binding!.observations[0]!.body.input.scopeKind).toBe("selected-closure");
  expect(binding!.observations[0]!.body.input.entries.map((entry) => entry.path)).toEqual([
    "SKILL.md",
  ]);
  expect(binding!.observations[0]!.observationId).toBe(original.observationId);
  expect(binding!.observations[0]!.body).toEqual(original.body);
  expect(binding!.coverage).toEqual({
    coveredPaths: ["SKILL.md"],
    excludedPaths: [],
    uncoveredPaths: [],
    complete: true,
  });
  expect(native!.observations[0]!.origin).toBe("fresh");
  expect(native!.observations[0]!.body.input.scopeKind).toBe("source-tree");
  expect(unavailable!.outcome).toBe("refused");
  expect(second.report.completion).toBe("partial");
  expect(second.scanId).not.toBe(first.scanId);
});

test("changed selected bytes, removed membership and wider scope each rerun the complete binding unit", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-membership-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Initial\n");
  writeFileSync(join(root, "extra.md"), "# Selected dependency\n");
  const request = {
    schema: "urn:aihq:scan:request:1.0.0" as const,
    source: { kind: "local" as const, path: root },
    selection: { paths: ["SKILL.md", "extra.md"], excludedPaths: [] },
    detectors: [{ detectorId: "detector.aih-binding-gate", configuration: {} }],
  };
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { retained });
  expect(first.status).toBe("assessment");
  if (first.status !== "assessment") return;
  const firstObservation = first.report.results[0]?.observations[0];
  expect(firstObservation?.origin).toBe("fresh");

  writeFileSync(join(root, "extra.md"), "# Changed dependency\n");
  const changed = await runScan(request, { retained });
  expect(changed.status).toBe("assessment");
  if (changed.status !== "assessment") return;
  expect(changed.report.results[0]?.observations).toHaveLength(1);
  expect(changed.report.results[0]?.observations[0]?.origin).toBe("fresh");
  expect(changed.report.results[0]?.coverage.coveredPaths).toEqual(["SKILL.md", "extra.md"]);
  expect(changed.report.results[0]?.observations[0]?.observationId).not.toBe(
    firstObservation?.observationId,
  );

  rmSync(join(root, "extra.md"));
  const reduced = await runScan(
    { ...request, selection: { paths: ["SKILL.md"], excludedPaths: [] } },
    { retained },
  );
  expect(reduced.status).toBe("assessment");
  if (reduced.status !== "assessment") return;
  const reducedObservation = reduced.report.results[0]?.observations[0];
  expect(reducedObservation?.origin).toBe("fresh");
  expect(reducedObservation?.body.input.targetPaths).toEqual(["SKILL.md"]);
  expect(reducedObservation?.body.input.entries.map((entry) => entry.path)).toEqual(["SKILL.md"]);
  expect(reduced.report.results[0]?.coverage.coveredPaths).toEqual(["SKILL.md"]);

  writeFileSync(join(root, "new.md"), "# Newly selected\n");
  const wider = await runScan(
    { ...request, selection: { paths: "all", excludedPaths: [] } },
    { retained },
  );
  expect(wider.status).toBe("assessment");
  if (wider.status !== "assessment") return;
  expect(wider.report.results[0]?.observations[0]?.origin).toBe("fresh");
  expect(wider.report.results[0]?.coverage).toEqual({
    coveredPaths: ["SKILL.md", "new.md"],
    excludedPaths: [],
    uncoveredPaths: [],
    complete: true,
  });
  expect(wider.report.results[0]?.observations[0]?.body.coverage.coveredPaths).toEqual([
    "SKILL.md",
    "new.md",
  ]);
});

test("selected file links retain directory ancestry and their shared target dependency", async (context) => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-links-"));
  roots.push(root);
  mkdirSync(join(root, "selected"));
  mkdirSync(join(root, "shared"));
  writeFileSync(join(root, "shared", "dependency.md"), "# Shared input\n");
  writeFileSync(join(root, "shared", "unrelated.md"), "# Unselected sibling\n");
  try {
    symlinkSync("../shared/dependency.md", join(root, "selected", "linked.md"), "file");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes((error as NodeJS.ErrnoException).code ?? "")) {
      context.skip();
      return;
    }
    throw error;
  }
  const request = {
    schema: "urn:aihq:scan:request:1.0.0" as const,
    source: { kind: "local" as const, path: root },
    selection: { paths: ["selected/linked.md"], excludedPaths: [] },
    detectors: [{ detectorId: "detector.aih-binding-gate", configuration: {} }],
  };
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { retained });
  expect(first.status).toBe("assessment");
  if (first.status !== "assessment") return;
  const original = first.report.results[0]?.observations[0];
  expect(original?.body.input.entries.map((entry) => entry.path)).toEqual([
    "selected",
    "selected/linked.md",
    "shared",
    "shared/dependency.md",
  ]);
  writeFileSync(join(root, "shared", "unrelated.md"), "# Changed sibling\n");
  const unrelated = await runScan(request, { retained });
  expect(unrelated.status).toBe("assessment");
  if (unrelated.status !== "assessment") return;
  expect(unrelated.report.results[0]?.observations[0]?.origin).toBe("reused");
  expect(unrelated.report.results[0]?.observations[0]?.body).toEqual(original?.body);

  writeFileSync(join(root, "shared", "dependency.md"), "# Changed shared input\n");
  const changed = await runScan(request, { retained });
  expect(changed.status).toBe("assessment");
  if (changed.status !== "assessment") return;
  expect(changed.report.results[0]?.observations[0]?.origin).toBe("fresh");
  expect(changed.report.results[0]?.coverage.coveredPaths).toEqual(["selected/linked.md"]);
});

test("trust-lint keeps its whole-tree dependency even for an explicit smaller selection", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-trust-scope-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Selected content\n");
  writeFileSync(join(root, "notes.txt"), "first repository fact\n");
  const request = {
    schema: "urn:aihq:scan:request:1.0.0" as const,
    source: { kind: "local" as const, path: root },
    selection: { paths: ["SKILL.md"], excludedPaths: [] },
    detectors: [
      {
        detectorId: "detector.aih-trust-lint",
        configuration: { internalScopes: [], mcpConfigPaths: [] },
      },
    ],
  };
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { retained });
  expect(first.status).toBe("assessment");
  if (first.status !== "assessment") return;
  expect(first.report.results[0]?.outcome).toBe("succeeded");
  expect(first.report.results[0]?.observations[0]?.body.input.scopeKind).toBe("source-tree");
  const repeated = await runScan(request, { retained });
  expect(repeated.status).toBe("assessment");
  if (repeated.status !== "assessment") return;
  expect(repeated.report.results[0]?.observations[0]?.origin).toBe("reused");
  writeFileSync(join(root, "notes.txt"), "changed repository fact\n");
  const changed = await runScan(request, { retained });
  expect(changed.status).toBe("assessment");
  if (changed.status !== "assessment") return;
  expect(changed.report.results[0]?.observations[0]?.origin).toBe("fresh");
  expect(
    changed.report.results[0]?.observations[0]?.body.input.entries.map((entry) => entry.path),
  ).toEqual(["SKILL.md", "notes.txt"]);
});
