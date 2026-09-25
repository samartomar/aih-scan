/**
 * Reporting for `tools/capture-catalog-item.mjs`: the run directory and its
 * `execution.log`, the process log blocks, `capture-failure.json` and
 * `preflight.json`. These are the helper's own diagnostic records, never evidence.
 */
import { existsSync, lstatSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  assertOutsideGitRepository,
  canonicalBytes,
  reasonOf,
  refuse,
  SOURCE_CLOSURE_RECORD_PROTOCOL,
} from "./common.mjs";

/** Bound on each stream kept in capture-failure.json; the full text stays in execution.log. */
const MAX_FAILURE_STREAM_CHARACTERS = 64 * 1024;

/* ---------- run log ---------- */

let logPath;
export const log = (message) => {
  const line = `${message}\n`;
  process.stdout.write(line);
  if (logPath !== undefined) writeFileSync(logPath, line, { flag: "a" });
};

export function appendProcessLog(label, result) {
  const body =
    `\n===== ${label} =====\n` +
    `finished ${new Date().toISOString()}\n` +
    `exit     ${result.status}\n` +
    (result.error === undefined ? "" : `error    ${result.error.message}\n`) +
    (result.signal === null || result.signal === undefined ? "" : `signal   ${result.signal}\n`) +
    (result.stdout ? `--- stdout ---\n${result.stdout}\n` : "") +
    (result.stderr ? `--- stderr ---\n${result.stderr}\n` : "");
  if (logPath === undefined) process.stdout.write(body);
  else writeFileSync(logPath, body, { flag: "a" });
}

/** The run's `execution.log`, once `createRunDirectory` has made it. */
export const currentLogPath = () => logPath;

export function createRunDirectory(output) {
  const runRoot = resolve(output);
  assertOutsideGitRepository(runRoot, "--output");
  if (existsSync(runRoot)) {
    const stat = lstatSync(runRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      refuse(`--output must be a real directory: ${runRoot}`);
    if (readdirSync(runRoot).length > 0) refuse(`--output must be new or empty: ${runRoot}`);
  } else {
    mkdirSync(runRoot, { recursive: true, mode: 0o700 });
  }
  logPath = join(runRoot, "execution.log");
  writeFileSync(logPath, "", { flag: "w" });
  return runRoot;
}

/**
 * The run directory's record of a stop that produced no verified bundle. It keeps
 * only what the phase actually made available: the reason, the capture command when
 * one was built, the exit status and the streams the command really wrote, the
 * selected source root and the file paths this capture was asked to cover. A field
 * the phase never produced stays null — no output is reconstructed, a failed run is
 * never recorded as an empty successful scan, and the full streams remain in
 * execution.log rather than being truncated away here.
 *
 * `findingsProduced` answers only what this helper can establish. A capture that ran
 * and failed, and a bundle that failed its own reader, may have written detector
 * output this helper never inspects: there the answer is null and the basis says so.
 * Only a run in which no capture process existed at all records false.
 */
export function writeCaptureFailure(runRoot, prepared, failure) {
  const excerpt = (text) => {
    if (typeof text !== "string") return { characters: 0, text: null, truncated: false };
    return text.length <= MAX_FAILURE_STREAM_CHARACTERS
      ? { characters: text.length, text, truncated: false }
      : {
          characters: text.length,
          text: text.slice(-MAX_FAILURE_STREAM_CHARACTERS),
          truncated: true,
        };
  };
  const stdout = excerpt(failure.stdout);
  const stderr = excerpt(failure.stderr);
  const bundlePath = join(runRoot, "bundle");
  const executionLog = join(runRoot, "execution.log");
  writeFileSync(
    join(runRoot, "capture-failure.json"),
    canonicalBytes({
      protocol: "CatalogItemCaptureFailureV1",
      outcome: "failed",
      phase: failure.phase,
      reason: failure.reason,
      captureCommand: failure.captureCommand ?? null,
      exitCode: failure.exitCode ?? null,
      signal: failure.signal ?? null,
      spawnError: failure.spawnError ?? null,
      stdout: stdout.text,
      stdoutCharacters: stdout.characters,
      stdoutTruncated: stdout.truncated,
      stderr: stderr.text,
      stderrCharacters: stderr.characters,
      stderrTruncated: stderr.truncated,
      bundleDirectory: bundlePath,
      bundlePresent: existsSync(bundlePath),
      /* This record exists only because no verified bundle was produced. */
      bundleVerified: false,
      /*
       * Whether a capture process existed at all, and then whether it is known to
       * have produced no findings. Unknown, not false, once a capture process has
       * existed: a failed command and a bundle that fails validation may each have
       * written detector output, and this helper does not read detector output to
       * find out.
       */
      captureProcessExisted: failure.captureProcessExisted === true,
      findingsProduced: failure.captureProcessExisted === true ? null : false,
      findingsProducedBasis:
        failure.captureProcessExisted === true
          ? "capture-output-not-inspected"
          : "no-capture-process-existed",
      sourceRoot: prepared === undefined ? null : prepared.item.sourceRoot,
      coveredFilePaths: prepared === undefined ? null : [...prepared.item.selectedClosurePaths],
      sourceClosureRecord: prepared === undefined ? null : prepared.sourceClosurePath,
      captureRequestPath: prepared === undefined ? null : prepared.requestPath,
      executionLog,
    }),
  );
  if (existsSync(executionLog))
    writeFileSync(executionLog, `\n${failure.phase} failure: ${failure.reason}\n`, { flag: "a" });
}

/**
 * Runs one step and, if it refuses, records the refusal in the run directory before
 * it propagates. These phases all run before any capture command exists, so a
 * failure during preparation has no staged root to name yet and no capture process
 * to have produced findings: those fields are recorded as null and false rather
 * than guessed.
 */
export async function recordFailure(phase, runRoot, prepared, step) {
  try {
    return await step();
  } catch (error) {
    writeCaptureFailure(runRoot, prepared, {
      captureCommand: null,
      captureProcessExisted: false,
      exitCode: null,
      phase,
      reason: reasonOf(error),
      signal: null,
      spawnError: null,
      stderr: null,
      stdout: null,
    });
    throw error;
  }
}

export function writePreflight(runRoot, platform, docker, prepared, skill) {
  const { item } = prepared;
  writeFileSync(
    join(runRoot, "preflight.json"),
    canonicalBytes({
      protocol: "CatalogItemCapturePreflightV1",
      /* Node's vocabulary and OCI's, labelled separately rather than merged. */
      platform,
      docker,
      tarballs: prepared.tarballs,
      packages: prepared.packages,
      detectorId: prepared.detector.detectorId,
      registrationSha256: prepared.detector.registrationRecord.registrationSha256,
      manifestDigestSha256: prepared.detector.layout.manifestDigestSha256,
      configDigestSha256: prepared.detector.layout.configDigestSha256,
      logicalReference: prepared.detector.layout.logicalReference,
      /* The closure this capture was staged from, as the public reader returned it. */
      sourceClosure: {
        record: prepared.sourceClosurePath,
        protocol: SOURCE_CLOSURE_RECORD_PROTOCOL,
        collection: item.closure.collection,
        entryId: item.entry.entryId,
        entrySubject: item.entry.subject,
        source: item.closure.source,
        declaredTreeDigest: item.closure.declaredTreeDigest,
        declaredSkillRoot: item.skillRoot.declaredPath,
        declaredMarker: item.skillRoot.marker,
      },
      sourceRoot: item.sourceRoot,
      selectedClosurePaths: item.selectedClosurePaths,
      coveredPublishedPaths: item.skillRoot.files,
      uncoveredPublishedPaths: item.uncoveredPublishedPaths,
      /* Which staged file the scanner loads as the skill, beside what the mount covers. */
      skill,
    }),
  );
}
