// Maintainer tooling for the manual report workflows (.github/workflows/scan-report-*.yml).
// It never scans, signs or publishes; it validates the reviewed inputs and the custody of the
// candidate the scanning workflow uploaded, and selects the exact summaries the signer signs.
//
//   node tools/publisher/candidate.mjs sources <sources.json> <expected-sha256>
//   node tools/publisher/candidate.mjs check-run <run.json> <artifacts.json> <run-id> <head> <artifact-id> <artifact-digest>
//   node tools/publisher/candidate.mjs select <candidate-dir> <expected-selection-sha256> <out-dir>
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

export const REPOSITORY = Object.freeze({ id: 1336836161, fullName: "samartomar/aih-scan" });
export const OWNER = Object.freeze({ id: 9993940, login: "samartomar" });
export const CANDIDATE_WORKFLOW = ".github/workflows/scan-report-candidate-upload.yml";
export const CANDIDATE_ARTIFACT = "scan-report-candidate";
export const MAX_SOURCES = 64;
export const MAX_CANDIDATE_BYTES = 512 * 1024 * 1024;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fail = (message) => {
  throw new Error(message);
};

/** The URL is transport only: reviewed hashes and explicit public-host policy bind imported bytes. */
export function validatePreparedImport(bytes, expectedSha256) {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256 ?? "") || sha256(bytes) !== expectedSha256)
    fail("Reviewed prepared import digest mismatch");
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!value || Object.keys(value).sort().join(",") !== "allowedHosts,archiveSha256,format,manifestSha256,receiptSha256,url" || value.format !== "aih-scan-prepared-import/1" || !Array.isArray(value.allowedHosts) || value.allowedHosts.length === 0 || !value.allowedHosts.every((host) => typeof host === "string" && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)) || ![value.archiveSha256, value.manifestSha256, value.receiptSha256].every((hash) => /^[0-9a-f]{64}$/.test(hash))) fail("Invalid prepared import descriptor");
  const url = new URL(value.url);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || !value.allowedHosts.includes(url.hostname)) fail("Prepared import URL policy refused");
  return value;
}

export async function importPreparedCandidate(bytes, expectedSha256, consumer, out) {
  const descriptor = validatePreparedImport(bytes, expectedSha256);
  const { downloadArchive } = await import("./prepared-archive.mjs");
  const { importCandidate } = await import("./prepared.mjs");
  const archive = `${out}.download.tar`;
  await downloadArchive({ ...descriptor, sha256: descriptor.archiveSha256 }, archive);
  const checked = await importCandidate(archive, descriptor.archiveSha256, descriptor.manifestSha256, descriptor.receiptSha256, consumer, out);
  writeFileSync(join(out, "prepared-import.json"), `${JSON.stringify({ execution: "local", archiveSha256: descriptor.archiveSha256, manifestSha256: descriptor.manifestSha256, receiptSha256: descriptor.receiptSha256 })}\n`, { flag: "wx" });
  return { execution: "local", count: checked.summaries.length, manifestSha256: descriptor.manifestSha256, receiptSha256: descriptor.receiptSha256 };
}

export async function checkPreparedCandidate(candidate, consumer) {
  const { verifyCandidate } = await import("./prepared.mjs");
  const receipt = JSON.parse(readFileSync(join(candidate, "prepared-import.json"), "utf8"));
  if (receipt.execution !== "local") fail("Prepared execution provenance refused");
  const checked = await verifyCandidate(candidate, receipt.manifestSha256, receipt.receiptSha256, consumer, join(candidate, "scanner.tgz"));
  return { execution: "local", count: checked.summaries.length };
}

/**
 * The reviewed sources of one candidate run: an exact JSON array whose SHA-256 the owner reviewed.
 * Each entry names a public repository at a full commit (optionally one item path) or an exact npm
 * package version. Nothing else is accepted, so the run reads only pinned public content.
 */
export function validateSources(bytes, expectedSha256) {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256 ?? "")) fail("Invalid reviewed sources digest");
  if (sha256(bytes) !== expectedSha256) fail("Reviewed sources digest mismatch");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail("Sources are not UTF-8 JSON");
  }
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_SOURCES)
    fail(`Sources must be a non-empty array of at most ${MAX_SOURCES} entries`);
  return value.map((entry, index) => {
    const where = `sources[${index}]`;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      fail(`${where} must be an object`);
    const keys = Object.keys(entry).sort().join(",");
    if (keys === "ref,repo" || keys === "path,ref,repo") {
      if (!/^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(entry.repo))
        fail(`${where}.repo must be a https://github.com/<owner>/<repo> URL`);
      if (!/^[0-9a-f]{40}$/.test(entry.ref)) fail(`${where}.ref must be a full commit`);
      if (
        entry.path !== undefined &&
        (typeof entry.path !== "string" ||
          !/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(entry.path) ||
          entry.path.split("/").some((segment) => segment === "." || segment === ".."))
      )
        fail(`${where}.path must be a repository-relative item path`);
      const target =
        entry.path === undefined ? entry.repo : `${entry.repo}/tree/${entry.ref}/${entry.path}`;
      return { target, ref: entry.ref };
    }
    if (keys === "npm") {
      if (
        typeof entry.npm !== "string" ||
        !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(
          entry.npm,
        )
      )
        fail(`${where}.npm must be <package>@<exact version>`);
      return { target: `npm:${entry.npm}` };
    }
    return fail(`${where} must be {repo, ref[, path]} or {npm}`);
  });
}

const identifier = (value) => {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,15}$/.test(value)) fail("Invalid immutable ID");
  return Number(value);
};

/** Checks that the selected candidate archive came from one successful reviewed candidate run. */
export function checkCandidateRun(run, artifacts, runId, head, artifactId, artifactDigest) {
  const expectedRun = identifier(runId),
    expectedArtifact = identifier(artifactId);
  if (!/^[0-9a-f]{40}$/.test(head ?? "") || !/^sha256:[0-9a-f]{64}$/.test(artifactDigest ?? ""))
    fail("Invalid custody selector");
  const repository = (value) =>
    value?.id === REPOSITORY.id &&
    value.full_name === REPOSITORY.fullName &&
    value.owner?.id === OWNER.id;
  const owner = (value) => value?.id === OWNER.id && value.login === OWNER.login;
  if (
    run?.id !== expectedRun ||
    run.run_attempt !== 1 ||
    run.event !== "workflow_dispatch" ||
    run.status !== "completed" ||
    run.conclusion !== "success" ||
    run.head_sha !== head ||
    run.head_branch !== "main" ||
    run.path !== CANDIDATE_WORKFLOW ||
    !repository(run.repository) ||
    !repository(run.head_repository) ||
    !owner(run.actor) ||
    !owner(run.triggering_actor)
  )
    fail("Candidate run custody refused");
  if (
    artifacts?.total_count !== 1 ||
    !Array.isArray(artifacts.artifacts) ||
    artifacts.artifacts.length !== 1
  )
    fail("Candidate archive set refused");
  const [archive] = artifacts.artifacts;
  if (
    archive.id !== expectedArtifact ||
    archive.name !== CANDIDATE_ARTIFACT ||
    archive.digest !== artifactDigest ||
    archive.expired !== false ||
    !Number.isSafeInteger(archive.size_in_bytes) ||
    archive.size_in_bytes < 1 ||
    archive.size_in_bytes > MAX_CANDIDATE_BYTES ||
    archive.workflow_run?.id !== expectedRun ||
    archive.workflow_run?.head_sha !== head
  )
    fail("Candidate archive custody refused");
  return { runId: expectedRun, head, artifactId: expectedArtifact, artifactDigest };
}

function regularFiles(root) {
  const files = [];
  const walk = (folder) => {
    for (const name of readdirSync(folder).sort()) {
      const path = join(folder, name);
      const stat = lstatSync(path);
      if (stat.isDirectory()) walk(path);
      else if (stat.isFile() && stat.nlink === 1) files.push(path);
      else fail("The candidate holds a link or special file");
    }
  };
  walk(root);
  return files;
}

/**
 * The selection the signer signs: every `summary.json` in the candidate, listed as
 * `<sha256>  <path>` lines in code-unit path order. Its SHA-256 must equal the digest the owner
 * reviewed; the selected summaries and the SARIF next to them are copied to `out`.
 */
export function selectSummaries(candidate, expectedSha256, out) {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256 ?? "")) fail("Invalid reviewed selection digest");
  const root = resolve(candidate);
  const files = regularFiles(root);
  const posix = (path) => relative(root, path).split(sep).join("/");
  const summaries = files.filter((path) => posix(path).endsWith("/summary.json"));
  if (summaries.length === 0) fail("The candidate holds no summaries");
  const lines = summaries
    .map((path) => `${sha256(readFileSync(path))}  ${posix(path)}\n`)
    .sort((left, right) => (left.slice(66) < right.slice(66) ? -1 : 1));
  const listing = lines.join("");
  if (sha256(listing) !== expectedSha256) fail("Reviewed selection digest mismatch");
  for (const path of files) {
    const local = posix(path);
    if (!summaries.some((summary) => local.startsWith(`${posix(dirname(summary))}/`))) continue;
    const target = join(out, ...local.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(path, target);
  }
  return { count: summaries.length, listing, paths: summaries.map(posix).sort() };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (command === "sources" && args.length === 2) {
      const sources = validateSources(readFileSync(args[0]), args[1]);
      process.stdout.write(`${JSON.stringify(sources)}\n`);
    } else if (command === "check-run" && args.length === 6) {
      const [runPath, artifactsPath, ...selectors] = args;
      const result = checkCandidateRun(
        JSON.parse(readFileSync(runPath, "utf8")),
        JSON.parse(readFileSync(artifactsPath, "utf8")),
        ...selectors,
      );
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } else if (command === "prepared-import" && args.length === 4) {
      const result = await importPreparedCandidate(readFileSync(args[0]), args[1], args[2], args[3]);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } else if (command === "prepared-check" && args.length === 2) {
      const result = await checkPreparedCandidate(args[0], args[1]);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } else if (command === "select" && args.length === 3) {
      const result = selectSummaries(args[0], args[1], args[2]);
      process.stdout.write(result.listing);
    } else throw new Error("usage: candidate.mjs sources|check-run|select ...");
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
