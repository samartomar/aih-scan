import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { createRetainedObservationsV1, runScan } from "../dist/public/host.js";

// A reproducible detector-work delta, measured only against an owned temporary source.
// Build first. This is deliberately not a customer-scale or cold-filesystem benchmark.
const root = mkdtempSync(join(tmpdir(), "aih-observation-reuse-timing-"));
const rounds = 7;
const timed = async (request, options) => {
  const started = performance.now();
  const result = await runScan(request, options);
  const milliseconds = performance.now() - started;
  assert.equal(result.status, "assessment");
  assert.equal(result.report.completion, "partial");
  return { result, milliseconds };
};
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
try {
  writeFileSync(join(root, "SKILL.md"), "# Selected fixture\n\nA fixed, local binding input.\n");
  for (let index = 0; index < 128; index++) {
    writeFileSync(join(root, `unselected-${String(index).padStart(3, "0")}.txt`), "x".repeat(1024));
  }
  const request = {
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: root },
    selection: { paths: ["SKILL.md"], excludedPaths: [] },
    detectors: [
      { detectorId: "detector.aih-binding-gate", configuration: {} },
      { detectorId: "detector.aih-native", configuration: {} },
      { detectorId: "detector.unavailable", configuration: {} },
    ],
  };
  const retained = createRetainedObservationsV1();
  const cold = await timed(request, { retained });
  const original = cold.result.report.results[0].observations[0];
  const deltaTimes = [], freshTimes = [];
  let last;
  for (let round = 0; round < rounds; round++) {
    writeFileSync(join(root, "unselected-000.txt"), `${round}:` + "y".repeat(1022));
    let delta, fresh;
    if (round % 2 === 0) {
      delta = await timed(request, { retained });
      fresh = await timed(request);
    } else {
      fresh = await timed(request);
      delta = await timed(request, { retained });
    }
    const [binding, native, unavailable] = delta.result.report.results;
    assert.equal(binding.observations[0].origin, "reused");
    assert.equal(binding.observations[0].observationId, original.observationId);
    assert.deepEqual(binding.observations[0].body, original.body);
    assert.equal(native.observations[0].origin, "fresh");
    assert.equal(unavailable.outcome, "refused");
    assert.equal(delta.result.report.selection.paths.length, 1);
    assert(fresh.result.report.results.filter(result => result.outcome === "succeeded")
      .every(result => result.observations[0].origin === "fresh"));
    deltaTimes.push(delta.milliseconds);
    freshTimes.push(fresh.milliseconds);
    last = delta.result;
  }
  process.stdout.write(JSON.stringify({
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    workload: { files: 129, unselectedFileBytes: 131072, selectedFiles: 1, rounds },
    cacheState: "First run has an empty retained handle; delta runs retain its binding observation. OS filesystem cache is not cleared. Fresh/delta order alternates within one process.",
    granularity: "One complete selected binding inventory; one complete source-tree native unit; one unavailable detector.",
    coldRetainedMilliseconds: cold.milliseconds,
    deltaMilliseconds: deltaTimes,
    forcedFreshMilliseconds: freshTimes,
    deltaMedianMilliseconds: median(deltaTimes),
    forcedFreshMedianMilliseconds: median(freshTimes),
    finalAccounting: last.report.results.map(result => ({
      detectorId: result.detectorId,
      outcome: result.outcome,
      origins: result.observations.map(observation => observation.origin),
      completeCoverage: result.coverage.complete,
    })),
  }, null, 2) + "\n");
} finally {
  rmSync(root, { recursive: true, force: true });
}
