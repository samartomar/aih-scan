import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { createRetainedObservationsV1, runScan } from "../../src/public/host.js";

test("returned report mutation cannot change retained bytes and a cloned handle cannot claim custody", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-custody-"));
  try {
    writeFileSync(join(root, "SKILL.md"), "# Example\n");
    const request = {
      schema: "urn:aihq:scan:request:1.0.0" as const,
      source: { kind: "local" as const, path: root },
      selection: { paths: "all" as const, excludedPaths: [] },
      detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
    };
    const retained = createRetainedObservationsV1();
    const first = await runScan(request, { retained });
    expect(first.status).toBe("assessment");
    if (first.status !== "assessment") return;
    const body = structuredClone(first.report.results[0]!.observations[0]!.body);
    const annexes = structuredClone(first.annexes);
    first.report.results[0]!.observations[0]!.body.completedAt = "2000-01-01T00:00:00.000Z";
    first.report.results[0]!.observations[0]!.body.coverage.coveredPaths.length = 0;
    first.annexes[0]!.bytesBase64 = "";

    const reused = await runScan(request, { retained });
    expect(reused.status).toBe("assessment");
    if (reused.status !== "assessment") return;
    expect(reused.report.results[0]!.observations[0]!.origin).toBe("reused");
    expect(reused.report.results[0]!.observations[0]!.body).toEqual(body);
    expect(reused.annexes).toEqual(annexes);

    const forged = await runScan(request, { retained: structuredClone(retained) });
    expect(forged.status).toBe("assessment");
    if (forged.status !== "assessment") return;
    expect(forged.report.results[0]!.observations[0]!.origin).toBe("fresh");
    expect(forged.report.results[0]!.diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "reuse-miss" })]),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a retained hit cannot bypass current annex limits or turn failed work into complete coverage", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-reuse-budget-"));
  try {
    writeFileSync(join(root, "SKILL.md"), "# Bounded evidence\n");
    const request = {
      schema: "urn:aihq:scan:request:1.0.0" as const,
      source: { kind: "local" as const, path: root },
      selection: { paths: "all" as const, excludedPaths: [] },
      detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
    };
    const retained = createRetainedObservationsV1();
    const first = await runScan(request, { retained });
    expect(first.status).toBe("assessment");
    if (first.status !== "assessment") return;
    expect(first.report.results[0]?.outcome).toBe("succeeded");
    const lowered = await runScan({ ...request, limits: { maxAnnexBytes: 1 } }, { retained });
    expect(lowered).toMatchObject({
      status: "assessment",
      report: {
        completion: "partial",
        results: [
          {
            outcome: "failed",
            observations: [],
            coverage: { complete: false, uncoveredPaths: ["SKILL.md"] },
            diagnostics: [expect.objectContaining({ code: "resource-limit" })],
          },
        ],
      },
      annexes: [],
    });
    const restored = await runScan(request, { retained });
    expect(restored.status).toBe("assessment");
    if (restored.status !== "assessment") return;
    expect(restored.report.results[0]?.observations[0]?.origin).toBe("reused");
    expect(restored.report.results[0]?.observations[0]?.body).toEqual(
      first.report.results[0]?.observations[0]?.body,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
