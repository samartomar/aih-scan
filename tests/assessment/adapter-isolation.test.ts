import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "vitest";
import { runDetectorV1 } from "../../src/index.js";
import { runScan } from "../../src/public/host.js";

test("the assessment native adapter preserves the public runner's original annex, including supported file links", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-adapter-parity-test-"));
  try {
    writeFileSync(join(root, "SKILL.md"), "# Native parity fixture\n");
    const paths = ["SKILL.md"];
    try {
      symlinkSync("SKILL.md", join(root, "linked.md"), "file");
      paths.push("linked.md");
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          ["EPERM", "EACCES", "ENOTSUP"].includes(String(error.code))
        )
      )
        throw error;
    }
    const direct = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: { kind: "source-tree", sourceRoot: root, selectedClosurePaths: paths },
      timeoutMs: 10000,
    });
    expect(direct.outcome).toBe("succeeded");
    if (
      direct.outcome !== "succeeded" ||
      direct.evidence.kind !== "baseline-analyzer-observation-v1"
    )
      throw new Error("Native fixture output required");
    const assessment = await runScan({
      schema: "urn:aihq:scan:request:1.0.0",
      source: { kind: "local", path: root },
      selection: { paths, excludedPaths: [] },
      detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
    });
    expect(assessment).toMatchObject({
      status: "assessment",
      report: { results: [{ outcome: "succeeded" }] },
    });
    if (assessment.status !== "assessment") throw new Error("Native fixture assessment required");
    const annex = assessment.annexes[0];
    if (!annex) throw new Error("Native fixture annex required");
    expect(Buffer.from(annex.bytesBase64, "base64")).toEqual(direct.evidence.observation.bytes);
    expect(assessment.report.annexes[0]).toMatchObject({
      mediaType: direct.evidence.observation.mediaType,
      byteLength: direct.evidence.observation.annex.byteLength,
      sha256: direct.evidence.observation.annex.sha256,
    });
    expect(assessment.report.results[0]?.observations[0]?.body.input.detectorVersion).toBe(
      direct.evidence.observation.analyzerVersion,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("changing unrelated installed trust rules preserves native and binding observation reuse", () => {
  const root = mkdtempSync(join(tmpdir(), "aih-adapter-isolation-test-"));
  try {
    const built = join(root, "built");
    execFileSync(
      process.execPath,
      [resolve("node_modules/typescript/bin/tsc"), "-p", "tsconfig.build.json", "--outDir", built],
      { cwd: resolve("."), stdio: "pipe" },
    );
    const installed = join(root, "installed");
    mkdirSync(installed);
    cpSync(built, join(installed, "dist"), { recursive: true });
    cpSync(resolve("package.json"), join(installed, "package.json"));
    cpSync(resolve("tools/baseline-analyzers"), join(installed, "tools/baseline-analyzers"), {
      recursive: true,
    });
    symlinkSync(resolve("node_modules"), join(installed, "node_modules"), "junction");
    const source = join(root, "source");
    mkdirSync(source);
    writeFileSync(join(source, "SKILL.md"), "# Independent adapter fixture\n");
    const script = join(root, "exercise.mjs");
    writeFileSync(
      script,
      `
import { appendFileSync } from 'node:fs';
import { runScan, createRetainedObservationsV1 } from ${JSON.stringify(pathToFileURL(join(installed, "dist/public/host.js")).href)};
const retained = createRetainedObservationsV1();
const request = {
  schema: 'urn:aihq:scan:request:1.0.0', source: {kind: 'local', path: ${JSON.stringify(source)}},
  selection: {paths: ['SKILL.md'], excludedPaths: []},
  detectors: [{detectorId: 'detector.aih-native', configuration: {}}, {detectorId: 'detector.aih-binding-gate', configuration: {}}],
};
const original = await runScan(request, {retained});
appendFileSync(${JSON.stringify(join(installed, "dist/detectors/trust-lint/depnames.js"))}, '\\n// unrelated trust dependency rule material changed\\n');
const current = await runScan(request, {retained});
appendFileSync(${JSON.stringify(join(installed, "dist/detectors/trust-lint/lint.js"))}, '\\n// shared binding and trust rule material changed\\n');
const sharedChanged = await runScan(request, {retained});
appendFileSync(${JSON.stringify(join(installed, "dist/assessment/in-process-adapter.js"))}, '\\n// common adapter implementation changed\\n');
const commonChanged = await runScan(request, {retained});
appendFileSync(${JSON.stringify(join(installed, "dist/assessment/native-implementation.js"))}, '\\n// native implementation changed\\n');
const nativeChanged = await runScan(request, {retained});
process.stdout.write(JSON.stringify({original, current, sharedChanged, commonChanged, nativeChanged}));
`,
    );
    const { original, current, sharedChanged, commonChanged, nativeChanged } = JSON.parse(
      execFileSync(process.execPath, [script], { encoding: "utf8", maxBuffer: 1024 * 1024 }),
    );
    expect(original).toMatchObject({
      status: "assessment",
      report: { results: [{ outcome: "succeeded" }, { outcome: "succeeded" }] },
    });
    expect(current).toMatchObject({
      status: "assessment",
      report: {
        results: [
          { observations: [{ origin: "reused" }] },
          { observations: [{ origin: "reused" }] },
        ],
      },
    });
    for (let index = 0; index < 2; index++) {
      expect(current.report.results[index].observations[0].body).toEqual(
        original.report.results[index].observations[0].body,
      );
      expect(current.report.results[index].observations[0].observationId).toBe(
        original.report.results[index].observations[0].observationId,
      );
    }
    expect(current.annexes).toEqual(original.annexes);
    expect(sharedChanged).toMatchObject({
      status: "assessment",
      report: {
        results: [
          { detectorId: "detector.aih-binding-gate", observations: [{ origin: "fresh" }] },
          { detectorId: "detector.aih-native", observations: [{ origin: "reused" }] },
        ],
      },
    });
    expect(commonChanged).toMatchObject({
      status: "assessment",
      report: {
        results: [{ observations: [{ origin: "fresh" }] }, { observations: [{ origin: "fresh" }] }],
      },
    });
    expect(nativeChanged).toMatchObject({
      status: "assessment",
      report: {
        results: [
          { detectorId: "detector.aih-binding-gate", observations: [{ origin: "reused" }] },
          { detectorId: "detector.aih-native", observations: [{ origin: "fresh" }] },
        ],
      },
    });
    expect(nativeChanged.report.results[0].observations[0].body).toEqual(
      commonChanged.report.results[0].observations[0].body,
    );
    expect(nativeChanged.report.results[0].observations[0].observationId).toBe(
      commonChanged.report.results[0].observations[0].observationId,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 30000);
