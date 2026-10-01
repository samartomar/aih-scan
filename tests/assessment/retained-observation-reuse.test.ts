import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "vitest";
import {
  createRetainedObservationsV1,
  type RetainedObservationsV1,
  runScan,
} from "../../src/public/host.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function rootFixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-assessment-retained-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Example\n");
  return root;
}
function request(root: string) {
  return {
    schema: "urn:aihq:scan:request:1.0.0" as const,
    source: { kind: "local" as const, path: root },
    selection: { paths: "all" as const, excludedPaths: [] },
    detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
  };
}
test("Scan-managed retained observations keep identity and times when unchanged", async () => {
  const root = rootFixture();
  const retained: RetainedObservationsV1 = createRetainedObservationsV1();

  const first = await runScan(request(root), { retained });
  expect(first.status).toBe("assessment");
  if (first.status !== "assessment") return;
  const observation = first.report.results[0]!.observations[0]!;
  expect(observation.origin).toBe("fresh");
  expect(first.report.results[0]!.outcome).toBe("succeeded");
  const firstObservationSnapshot = structuredClone(observation);

  const second = await runScan(request(root), { retained });
  expect(second.status).toBe("assessment");
  if (second.status !== "assessment") return;

  // A reused unit is assembled into a genuinely current assessment, not a copied report.
  expect(second.scanId).not.toBe(first.scanId);
  expect(second.report.createdAt >= first.report.createdAt).toBe(true);
  expect(second.report.requestedDetectors).toEqual(first.report.requestedDetectors);

  const reused = second.report.results[0]!.observations[0]!;
  expect(second.report.results[0]!.outcome).toBe("succeeded");
  expect(reused.origin).toBe("reused");
  expect(reused.fromScanId).toBe(first.scanId);
  // The original observation identity, body and observed times survive reuse unchanged;
  // reuse never mints a new observed timestamp or trims the retained unit.
  expect(reused.observationId).toBe(observation.observationId);
  expect(reused.body).toEqual(observation.body);
  expect(reused.body.startedAt).toBe(observation.body.startedAt);
  expect(reused.body.completedAt).toBe(observation.body.completedAt);

  // The reused unit still ships its original annex bytes so the new report can be packed.
  expect(second.annexes.map((annex) => annex.id)).toEqual(first.annexes.map((annex) => annex.id));
  expect(second.annexes.map((annex) => annex.bytesBase64)).toEqual(
    first.annexes.map((annex) => annex.bytesBase64),
  );

  // The first assessment's own observation is untouched by the second run.
  expect(first.report.results[0]!.observations[0]).toEqual(firstObservationSnapshot);
});
