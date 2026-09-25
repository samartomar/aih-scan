/**
 * Capture for `tools/capture-catalog-item.mjs`: prepare the request from the staged
 * closure and the operator's detector inputs, pass the gates in their fixed order,
 * and invoke the packaged `aih-scan capture` command. A capture that yields no
 * verified bundle is recorded as a failure, never as an empty scan.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalBytes, reasonOf, refuse, regularBytes } from "./common.mjs";
import { importReader, installConsumer, installedPackage } from "./catalog.mjs";
import { readDetectorInputs } from "./detector-inputs.mjs";
import { assertSkillSourceRoot, dockerPreflight } from "./preflight.mjs";
import {
  appendProcessLog,
  currentLogPath,
  log,
  recordFailure,
  writeCaptureFailure,
  writePreflight,
} from "./report.mjs";
import { readCatalogSourceClosure } from "./staging.mjs";

const CAPTURE_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * Runs the packaged capture command and returns its outcome instead of throwing: a
 * capture that produced no verified bundle must still be recorded with the exit
 * status and the streams the command actually wrote. Every failed attempt is
 * written to the run directory before it is returned.
 */
export function attemptCapture(prepared, runRoot) {
  const bundlePath = join(runRoot, "bundle");
  const captureCommand = [
    process.execPath,
    prepared.cliEntry,
    "capture",
    "--request",
    prepared.requestPath,
    "--output",
    bundlePath,
  ];
  const failed = (phase, reason, result, captureProcessExisted) => {
    const failure = {
      outcome: "failed",
      phase,
      reason,
      captureCommand,
      /*
       * Whether a capture process existed decides what this run may claim about
       * findings: with a process, its output was not inspected and stays unknown.
       */
      captureProcessExisted,
      exitCode: result === undefined || typeof result.status !== "number" ? null : result.status,
      signal: result === undefined ? null : (result.signal ?? null),
      spawnError: result === undefined || result.error === undefined ? null : result.error.message,
      stdout: result === undefined ? null : result.stdout,
      stderr: result === undefined ? null : result.stderr,
    };
    writeCaptureFailure(runRoot, prepared, failure);
    return failure;
  };
  if (existsSync(bundlePath))
    return failed(
      "capture",
      `capture bundle directory already exists: ${bundlePath}`,
      undefined,
      false,
    );
  const result = spawnSync(process.execPath, captureCommand.slice(1), {
    encoding: "utf8",
    env: process.env,
    timeout: CAPTURE_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  appendProcessLog("aih-scan capture", result);
  if (result.error !== undefined)
    return failed("capture", `capture could not run: ${result.error.message}`, result, true);
  if (result.status !== 0)
    return failed(
      "capture",
      `capture exited ${result.status}: ${
        (result.stderr ?? "").trim().slice(0, 2000) || "no diagnostic output"
      }; full output is in execution.log`,
      result,
      true,
    );
  let bundle;
  try {
    bundle = prepared.reader.readScanCaptureBundleV2({ bundleDirectory: bundlePath });
  } catch (error) {
    return failed(
      "bundle",
      `the produced bundle failed its own reader: ${reasonOf(error)}`,
      result,
      true,
    );
  }
  const manifest = JSON.parse(readFileSync(join(bundlePath, "bundle.json"), "utf8"));
  log(`bundle          ${bundlePath}`);
  log(`candidate       sha256:${manifest.candidate.candidateSha256}`);
  log(
    `annexes         ${bundle.annexArtifacts
      .map((entry) => `${entry.descriptorId}:${entry.sha256}`)
      .join(" ")}`,
  );
  return { outcome: "captured", bundlePath, candidateSha256: manifest.candidate.candidateSha256 };
}

/**
 * Everything the command does after preparation, in this order: refuse a subject the
 * registered route cannot load, refuse a host or daemon the broker cannot reach,
 * record the preflight, then either stop (`--prepare-only`) or capture.
 *
 * The order is the point. A subject the scanner cannot load is refused before the
 * Docker gate and before any container exists, and this function is separate from
 * `main` so that order is observable on a host whose platform gate would otherwise
 * refuse first. Every failure from here on leaves capture-failure.json behind.
 */
export async function runPreparedCapture(options, runRoot, platform, prepared) {
  const skill = await recordFailure("subject", runRoot, prepared, () =>
    assertSkillSourceRoot(prepared.item),
  );
  log(`skill root      ${prepared.item.sourceRoot} (${skill.path} sha256:${skill.sha256})`);
  const docker = await recordFailure("host", runRoot, prepared, () =>
    dockerPreflight(prepared.detector.layout),
  );
  writePreflight(runRoot, platform, docker, prepared, skill);
  if (options.prepareOnly === true) {
    log("prepare-only    capture not attempted; this is preparation, not detector output");
    return {
      outcome: "prepared",
      requestPath: prepared.requestPath,
      captureCommand: `aih-scan capture --request ${prepared.requestPath} --output ${join(runRoot, "bundle")}`,
    };
  }
  const attempt = attemptCapture(prepared, runRoot);
  if (attempt.outcome !== "captured") refuse(attempt.reason);
  return {
    outcome: "captured",
    bundlePath: attempt.bundlePath,
    candidateSha256: attempt.candidateSha256,
    executionLog: currentLogPath(),
  };
}

/**
 * Steps 2 to 6 of the fixed order: the whole platform-independent preparation,
 * exactly as the command runs it. It stops before the subject gate, before the host
 * gate's Docker check and before capture, so it is also the surface a test can drive
 * against supplied tarballs without pretending a detector ran.
 *
 * Preparation stages the published source closure under its own paths, selects the
 * skill material root Catalog declares and writes the request. `runPreparedCapture`
 * then refuses a subject the registered route cannot load, using the staged material
 * this function wrote and the digests it verified.
 */
export async function prepareCapture(options, runRoot) {
  const consumer = installConsumer(options);
  const catalog = installedPackage(consumer.consumerRoot, "@aihq/catalog");
  const scan = installedPackage(consumer.consumerRoot, "@aihq/scan");
  const reader = await importReader(consumer.consumerRoot);
  const cliEntry = join(consumer.consumerRoot, "node_modules", "@aihq", "scan", "dist", "cli.js");
  regularBytes(cliEntry, "packaged aih-scan CLI", 1, 16 * 1024 * 1024);
  const catalogTarball = consumer.tarballs.find((entry) => entry.flag === "--catalog-tarball");
  if (catalogTarball === undefined)
    refuse("the installed catalog tarball is missing from the consumer's own record");

  const source = readCatalogSourceClosure(reader, options, runRoot, {
    name: "@aihq/catalog",
    version: catalog.version,
    tarball: catalogTarball,
  });
  const item = source.item;
  const detector = readDetectorInputs(reader, options, runRoot);

  const request = {
    registration: detector.registrationInput,
    detectorId: detector.detectorId,
    layout: detector.layout,
    sourceRoot: item.sourceRoot,
    selectedClosurePaths: item.selectedClosurePaths,
    annexFiles: detector.annexFiles.map((entry) => ({
      descriptorId: entry.descriptorId,
      path: entry.path,
    })),
  };
  const requestPath = join(runRoot, "capture-request.json");
  writeFileSync(requestPath, canonicalBytes(request), { flag: "wx" });
  log(`request         ${requestPath}`);
  return {
    consumerRoot: consumer.consumerRoot,
    tarballs: consumer.tarballs,
    packages: [
      { name: "@aihq/catalog", version: catalog.version },
      { name: "@aihq/scan", version: scan.version },
    ],
    reader,
    cliEntry,
    item,
    sourceClosurePath: source.recordPath,
    detector,
    request,
    requestPath,
  };
}
