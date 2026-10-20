#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  batchId,
  canonicalBytes,
  commit,
  detectorsFor,
  matchesTargetSource,
  parseJson,
  profile,
  readRegular,
  schemas,
  sha256,
  targetDirectory,
  targetIdentity,
  targetKey,
  unavailableCoverage,
  validateInput,
  validateManifest,
} from "./contracts.mjs";
import { acquireCatalogCapture, materializeCatalogCapture } from "./catalog-capture.mjs";
import { batchBudget } from "./batch-budget.mjs";
import { ghApi } from "../artifact/gh-api.mjs";
import { loadScanner } from "./scanner.mjs";

const runtime = () => ({
  node: process.version,
  platform: process.platform,
  architecture: process.arch,
});
async function githubJson(path, options = {}) {
  const response = await fetch(`https://api.github.com/${path}`, {
    redirect: "error",
    signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(Math.min(30000,options.timeout ?? 30000))]) : AbortSignal.timeout(30000),
    headers: { Accept: "application/vnd.github+json", "User-Agent": "aih-scan-refresh" },
  });
  if (!response.ok) throw new Error("Repository identity lookup failed");
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > 1024 * 1024) throw new Error("GitHub response exceeds bound");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
async function repositoryIdentity(repository, options) {
  const body = await githubJson(`repos/${repository}`, options);
  if (body.full_name !== repository || body.clone_url !== `https://github.com/${repository}.git`)
    throw new Error("Repository identity or redirect mismatch");
  return { repository, repositoryUrl: body.clone_url };
}
async function resolveRef(repositoryUrl, ref) {
  if (/^[0-9a-f]{40}$/.test(ref)) return ref;
  const repository = repositoryUrl.slice("https://github.com/".length, -4);
  const body = await githubJson(
    `repos/${repository}/git/ref/heads/${encodeURIComponent(ref.slice("refs/heads/".length))}`,
  );
  if (body.ref !== ref || body.object?.type !== "commit")
    throw new Error("Ref resolution ambiguous or mismatch");
  return commit(body.object.sha);
}
export async function freezeBatch({
  input,
  scannerTarball,
  scannerInstall,
  resolveRepository = repositoryIdentity,
  resolveRef: resolveTargetRef = resolveRef,
  captureTransport,
}) {
  const snapshot = validateInput(parseJson(canonicalBytes(input)));
  const budget = batchBudget(snapshot.batchLimits?.maxDurationMs);
  try {
  const scanner = await loadScanner(scannerTarball, scannerInstall, snapshot.scannerSourceCommit);
  const targets = [];
  for (const target of snapshot.targets) {
    budget.checkpoint();
    const identity = await resolveRepository(target.repository, {signal:budget.signal,timeout:budget.checkpoint()});
    if (
      identity.repository !== target.repository ||
      identity.repositoryUrl !== `https://github.com/${target.repository}.git`
    )
      throw new Error("Resolved repository mismatch");
    const oid = /^[0-9a-f]{40}$/.test(target.ref)
      ? target.ref
      : commit(await resolveTargetRef(identity.repositoryUrl, target.ref));
    targets.push({
      repository: target.repository,
      ...targetIdentity(target),
      repositoryUrl: identity.repositoryUrl,
      reviewedRef: target.ref,
      commit: oid,
      selection: target.selection,
      detectors: detectorsFor(target.trustLint),
      ...(target.capture ? { capture: await acquireCatalogCapture({commit: oid, capture: target.capture}, snapshot.limits, budget.transport(captureTransport ?? ghApi())) } : {}),
    });
  }
  scanner.verifyUnchanged();
  const manifest = {
    schema: snapshot.schema === schemas.captureBatchInput ? schemas.captureBatchManifest : snapshot.schema === schemas.captureInput ? schemas.captureManifest : schemas.manifest,
    createdAt: new Date().toISOString(),
    scanner: scanner.identity,
    runtime: snapshot.runtime,
    profile,
    limits: snapshot.limits,
    ...(snapshot.batchLimits ? {batchLimits:snapshot.batchLimits} : {}),
    unavailableCoverage: [...unavailableCoverage],
    targets,
  };
  manifest.batchId = batchId(manifest);
  budget.checkpoint();
  return validateManifest(manifest);
  } finally { budget.dispose(); }
}
function createExclusiveDirectory(output) {
  mkdirSync(output, { mode: 0o700 });
}
function writeJson(path, value) {
  const bytes = canonicalBytes(value);
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  return sha256(bytes);
}
function noOutputInsideSource(output) {
  const root = resolve(import.meta.dirname, "../..");
  if (output === root || output.startsWith(`${root}/`) || output.startsWith(`${root}\\`))
    throw new Error("Producer outputs must be outside scanner source checkout");
}
export async function runBatch({ manifest, scannerTarball, scannerInstall, output, signal, captureTransport }) {
  const frozen = validateManifest(parseJson(canonicalBytes(manifest)));
  const independent = frozen.schema === schemas.captureBatchManifest;
  const budget = batchBudget(frozen.batchLimits?.maxDurationMs, signal);
  const acquired = new Map();
  try {
  if (!canonicalBytes(runtime()).equals(canonicalBytes(frozen.runtime)))
    throw new Error("Execution runtime differs from frozen runtime");
  const scanner = await loadScanner(scannerTarball, scannerInstall, frozen.scanner.sourceCommit);
  if (!canonicalBytes(scanner.identity).equals(canonicalBytes(frozen.scanner)))
    throw new Error("Installed scanner differs from frozen identity");
  // Refuse missing/tampered capture input before any detector or candidate output.
  for (const target of frozen.targets.filter(target => target.capture)) {
    if (budget.termination() !== "completed") break;
    try {
      budget.checkpoint();
      const root = await materializeCatalogCapture(target, frozen.limits, budget.transport(captureTransport ?? ghApi()));
      acquired.set(targetKey(target), root);
      budget.checkpoint();
    } catch (error) {
      if (budget.termination() === "completed") throw error;
      break;
    }
  }
  const destination = resolve(output);
  noOutputInsideSource(destination);
  createExclusiveDirectory(destination);
  const manifestSha256 = writeJson(join(destination, "manifest.json"), frozen);
  mkdirSync(join(destination, "targets"), { mode: 0o700 });
  const inventory = {
    schema: independent ? schemas.captureBatchInventory : schemas.inventory,
    batchId: frozen.batchId,
    manifestSha256,
    createdAt: new Date().toISOString(),
    scanner: frozen.scanner,
    runtime: runtime(),
    profile: frozen.profile,
    unavailableCoverage: frozen.unavailableCoverage,
    targets: [],
    ...(independent ? {termination:"completed",durationMs:0} : {}),
  };
  for (const target of frozen.targets) {
    const started = performance.now(),
      relativeDirectory = `targets/${targetDirectory(target)}`,
      directory = join(destination, relativeDirectory);
    mkdirSync(directory, { mode: 0o700 });
    let result;
    try {
      if (budget.termination() !== "completed") {
        result = {
          schema: "urn:aihq:scan:run-result:1.0.0",
          status: "diagnostic",
          phase: "capture",
          diagnostics: [
            {
              code: budget.termination() === "deadline-exceeded" ? "producer-deadline-exceeded" : "producer-cancelled",
              detail:
                "This source was not started because the frozen batch was cancelled; no assessment identity is retained.",
            },
          ],
        };
      } else {
        scanner.verifyUnchanged();
        result = await scanner.host.runScan(
          {
            schema: "urn:aihq:scan:request:1.0.0",
            source: target.capture ? {kind: "local", path: acquired.get(targetKey(target)).root} : { kind: "git", repository: target.repositoryUrl, commit: target.commit },
            selection: target.selection,
            detectors: target.detectors,
            limits: frozen.limits,
          },
          { signal: budget.signal },
        );
        scanner.verifyUnchanged();
      }
    } catch {
      result = {
        schema: "urn:aihq:scan:run-result:1.0.0",
        status: "diagnostic",
        phase: "assembly",
        diagnostics: [
          {
            code: "producer-failure",
            detail:
              "The installed producer could not complete this source; no assessment identity is retained.",
          },
        ],
      };
    }
    const row = {
      repository: target.repository,
      ...targetIdentity(target),
      commit: target.commit,
      status: result.status,
      resultPath: `${relativeDirectory}/result.json`,
      resultSha256: writeJson(join(directory, "result.json"), result),
      diagnostics: result.diagnostics,
      detectors: target.detectors.map((detector) => ({
        detectorId: detector.detectorId,
        profileId: detector.profileId,
        outcome: "not-run",
        coverage: null,
        diagnostics: result.diagnostics,
      })),
      measurements: {
        durationMs: Math.round(performance.now() - started),
        sourceEntries: null,
        sourceBytes: null,
        reportBytes: null,
        annexBytes: null,
        artifactBytes: null,
      },
    };
    if (result.status === "assessment") {
      try {
        const prepared = await scanner.host.prepareArtifact({
          report: result.report,
          annexes: result.annexes.map((annex) => ({
            id: annex.id,
            bytes: Buffer.from(annex.bytesBase64, "base64"),
          })),
        });
        const read = await scanner.read.readArtifact(prepared.bytes);
        if (
          read.status !== "read" ||
          read.scanId !== result.scanId ||
          !matchesTargetSource(read.report.source, target)
        )
          throw new Error("Prepared assessment source mismatch");
        const report = read.report;
        if (
          report.results.length !== 4 ||
          !target.detectors.every((expected) => {
            const actual = report.requestedDetectors.find(
              (detector) => detector.detectorId === expected.detectorId,
            );
            return (
              actual &&
              canonicalBytes({
                detectorId: actual.detectorId,
                profileId: actual.profileId,
                configuration: actual.configuration,
              }).equals(canonicalBytes(expected))
            );
          }) ||
          !canonicalBytes(report.selection.excludedPaths).equals(
            canonicalBytes(target.selection.excludedPaths),
          )
        )
          throw new Error("Prepared assessment request mismatch");
        const statementBytes = canonicalBytes(prepared.statement);
        if (statementBytes.length > frozen.limits.maxStatementBytes)
          throw new Error("Statement exceeds bound");
        const artifactSha256 = sha256(prepared.bytes),
          statementSha256 = sha256(statementBytes);
        writeFileSync(join(directory, "artifact.json"), prepared.bytes, {
          flag: "wx",
          mode: 0o600,
        });
        writeFileSync(join(directory, "statement.json"), statementBytes, {
          flag: "wx",
          mode: 0o600,
        });
        const candidate = {
          schema: schemas.candidate,
          batchId: frozen.batchId,
          repository: target.repository,
          ...targetIdentity(target),
          commit: target.commit,
          scanId: result.scanId,
          artifactSha256,
          statementSha256,
          resultSha256: row.resultSha256,
        };
        writeJson(join(directory, "candidate.json"), candidate);
        Object.assign(row, {
          scanId: result.scanId,
          completion: report.completion,
          authenticity: "unsigned",
          artifactPath: `${relativeDirectory}/artifact.json`,
          artifactSha256,
          statementPath: `${relativeDirectory}/statement.json`,
          statementSha256,
          candidatePath: `${relativeDirectory}/candidate.json`,
        });
        row.detectors = target.detectors.map((detector) => {
          const result = report.results.find((result) => result.detectorId === detector.detectorId);
          if (!result) throw new Error("Missing requested detector result");
          return {
            detectorId: result.detectorId,
            profileId: detector.profileId,
            outcome: result.outcome,
            coverage: result.coverage,
            diagnostics: result.diagnostics,
          };
        });
        Object.assign(row.measurements, {
          sourceEntries: report.source.capture.entries.length,
          sourceBytes: report.source.capture.entries
            .filter((entry) => entry.kind === "file")
            .reduce((total, entry) => total + entry.byteLength, 0),
          reportBytes: prepared.artifact.report.byteLength,
          annexBytes: prepared.artifact.annexes.reduce(
            (total, annex) => total + annex.byteLength,
            0,
          ),
          artifactBytes: prepared.bytes.length,
        });
      } catch (error) {
        throw new Error(
          "Candidate preparation refused; retained results remain diagnostic evidence and output must not be published",
          { cause: error },
        );
      }
    }
    row.measurements.durationMs = Math.round(performance.now() - started);
    inventory.targets.push(row);
  }
  if (independent) {inventory.termination = budget.termination();inventory.durationMs=budget.durationMs();}
  writeJson(join(destination, "inventory.json"), inventory);
  return inventory;
  } finally { for (const root of acquired.values()) root.cleanup(); budget.dispose(); }
}
let boundaryPhase = "arguments";
const actionRunId = () =>
  /^[1-9][0-9]{0,15}$/.test(process.env.GITHUB_RUN_ID ?? "") ? process.env.GITHUB_RUN_ID : null;
async function cli() {
  const args = process.argv.slice(2),
    mode = args.shift(),
    allowed =
      mode === "freeze"
        ? ["input", "scanner-tgz", "scanner-install", "out"]
        : mode === "run"
          ? ["manifest", "scanner-tgz", "scanner-install", "out"]
          : [];
  if (["freeze", "run"].includes(mode)) boundaryPhase = mode;
  if (args.length !== allowed.length * 2)
    throw new Error("Expected freeze/run and exact named arguments");
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index].replace(/^--/, "");
    if (args[index] !== `--${key}` || !allowed.includes(key) || Object.hasOwn(options, key))
      throw new Error("Unknown or duplicate argument");
    options[key] = args[index + 1];
  }
  if (allowed.some((key) => !options[key])) throw new Error("Missing argument");
  const output = resolve(options.out);
  if (mode === "freeze") {
    const manifest = await freezeBatch({
      input: parseJson(readRegular(options.input, 2097152)),
      scannerTarball: options["scanner-tgz"],
      scannerInstall: options["scanner-install"],
    });
    writeJson(output, manifest);
    process.stdout.write(
      `${JSON.stringify({ event: "scan-refresh.completed", phase: "freeze", runId: actionRunId(), batchId: manifest.batchId, manifestSha256: sha256(canonicalBytes(manifest)), targets: manifest.targets.length })}\n`,
    );
  } else {
    const cancellation = new AbortController(),
      onSignal = () => cancellation.abort();
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    let manifest, result;
    try {
      manifest = parseJson(readRegular(options.manifest, 2097152), 2097152, true);
      result = await runBatch({
        manifest,
        scannerTarball: options["scanner-tgz"],
        scannerInstall: options["scanner-install"],
        output,
        signal: cancellation.signal,
      });
    } finally {
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
    }
    process.stdout.write(
      `${JSON.stringify({
        event: result.termination === "deadline-exceeded" ? "scan-refresh.deadline-exceeded" : cancellation.signal.aborted ? "scan-refresh.cancelled" : "scan-refresh.completed",
        phase: "run",
        runId: actionRunId(),
        inputSha256: sha256(canonicalBytes(manifest)),
        batchId: result.batchId,
        assessments: result.targets.filter((target) => target.status === "assessment").length,
        targets: result.targets.length,
      })}\n`,
    );
    if (cancellation.signal.aborted || (result.termination && result.termination !== "completed")) {
      process.exitCode = 2;
      return;
    }
    if (
      result.targets.some(
        (target) => target.status !== "assessment" || target.completion !== "complete",
      )
    )
      process.exitCode = 1;
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  cli().catch(() => {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh.refused", phase: boundaryPhase, runId: actionRunId(), reason: "input-or-runtime-or-scanner-or-candidate-custody-refused" })}\n`,
    );
    process.exitCode = 2;
  });
