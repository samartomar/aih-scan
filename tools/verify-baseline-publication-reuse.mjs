import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RELEASE_FILES = ["publication.json", "discovery.json", "inspection.json", "SHA256SUMS"];
const HASHED_FILES = RELEASE_FILES.filter((name) => name !== "SHA256SUMS");
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
// Match Core's public evidence policy. The original report date owns this clock.
const REPORT_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const DISCOVERY_MAX_BYTES = 1024 * 1024;

export function baselinePublicationTag(publisherSha, requestSha256, generation = "initial") {
  if (!HEX_40.test(publisherSha) || !HEX_64.test(requestSha256)) fail("publication identity");
  if (generation !== "initial" && !/^\d{8}$/u.test(generation)) fail("publication generation");
  return `baseline-v1-${publisherSha}-${requestSha256}${generation === "initial" ? "" : `-r${generation}`}`;
}

function fail(reason) {
  throw new Error(`baseline publication reuse rejected: ${reason}`);
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 2; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (typeof key !== "string" || !key.startsWith("--") || typeof value !== "string" || values.has(key))
      fail("arguments");
    values.set(key, value);
  }
  const expected = [
    "--requests",
    "--pending",
    "--reuse-directory",
    "--repository",
    "--publisher-sha",
    "--source-ref",
    "--workflow",
    "--scanner",
    "--github-output",
  ];
  const generation = values.get("--generation") ?? "initial";
  values.delete("--generation");
  if (values.size !== expected.length || expected.some((key) => !values.has(key))) fail("arguments");
  const result = Object.fromEntries(values);
  result["--generation"] = generation;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(result["--repository"])) fail("repository");
  if (!HEX_40.test(result["--publisher-sha"])) fail("publisher SHA");
  baselinePublicationTag(result["--publisher-sha"], "0".repeat(64), generation);
  if (result["--source-ref"] !== "refs/heads/main") fail("source ref");
  if (
    result["--workflow"] !==
    `${result["--repository"]}/.github/workflows/baseline-publication.yml`
  )
    fail("workflow identity");
  return result;
}

function regularDirectory(path, label, mustNotExist = false) {
  try {
    const stat = lstatSync(path);
    if (mustNotExist || !stat.isDirectory() || stat.isSymbolicLink()) fail(label);
  } catch (error) {
    if (mustNotExist && error?.code === "ENOENT") return;
    if (error?.message?.startsWith("baseline publication reuse rejected:")) throw error;
    fail(label);
  }
}

function requestFiles(requestDirectory) {
  const root = resolve(requestDirectory);
  regularDirectory(root, "request directory");
  const entries = readdirSync(root, { withFileTypes: true }).sort((left, right) =>
    left.name.localeCompare(right.name),
  );
  const coverage = entries.filter((entry) => entry.name === "coverage-map.json");
  if (coverage.length > 1 || coverage.some((entry) => !entry.isFile() || entry.isSymbolicLink()))
    fail("coverage map layout");
  const batches = entries.filter((entry) => entry.name !== "coverage-map.json");
  if (batches.length === 0 || batches.length + coverage.length !== entries.length)
    fail("request directory layout");
  return batches.map((entry, index) => {
    const expected = `batch-${String(index + 1).padStart(3, "0")}.request.json`;
    if (entry.name !== expected || !entry.isFile() || entry.isSymbolicLink()) fail("request directory layout");
    const path = resolve(join(root, entry.name));
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) fail("request file");
    let request;
    try {
      request = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      fail("request JSON");
    }
    if (
      request === null ||
      typeof request !== "object" ||
      Array.isArray(request) ||
      typeof request.requestSha256 !== "string" ||
      !HEX_64.test(request.requestSha256)
    )
      fail("request SHA");
    return { name: entry.name, path, requestSha256: request.requestSha256 };
  });
}

export function execute(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", windowsHide: true });
  if (result.error) fail(`unable to run ${command}`);
  return {
    status: result.status,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

function isNotFound(result) {
  return result.status !== 0 && /\bHTTP 404\b/u.test(`${result.stdout}\n${result.stderr}`);
}

export function requiredRelease(repository, tag, publisherSha, gh, run = execute) {
  const release = run(gh, ["api", `repos/${repository}/releases/tags/${tag}`]);
  if (release.status !== 0) {
    if (!isNotFound(release)) fail(`release lookup for ${tag}`);
    const tagReference = run(gh, ["api", `repos/${repository}/git/ref/tags/${tag}`]);
    if (tagReference.status === 0) fail(`release tag exists without a completed release: ${tag}`);
    if (!isNotFound(tagReference)) fail(`tag lookup for ${tag}`);
    return undefined;
  }
  let metadata;
  try {
    metadata = JSON.parse(release.stdout);
  } catch {
    fail(`release metadata JSON for ${tag}`);
  }
  if (
    metadata === null ||
    typeof metadata !== "object" ||
    Array.isArray(metadata) ||
    metadata.tag_name !== tag ||
    metadata.target_commitish !== publisherSha ||
    metadata.draft !== false ||
    !Array.isArray(metadata.assets) ||
    metadata.assets.length !== RELEASE_FILES.length
  )
    fail(`release metadata for ${tag}`);
  const names = metadata.assets.map((asset) => asset?.name).sort();
  if (names.join("\n") !== [...RELEASE_FILES].sort().join("\n")) fail(`release asset closure for ${tag}`);
  return metadata;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function verifyDownloadedFiles(directory) {
  const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    left.name.localeCompare(right.name),
  );
  if (entries.length !== RELEASE_FILES.length) fail("downloaded asset count");
  for (const entry of entries) {
    if (!RELEASE_FILES.includes(entry.name) || !entry.isFile() || entry.isSymbolicLink())
      fail("downloaded asset layout");
    const stat = lstatSync(join(directory, entry.name));
    if (!stat.isFile() || stat.isSymbolicLink()) fail("downloaded asset file");
  }
  const sums = readFileSync(join(directory, "SHA256SUMS"), "utf8").replace(/\r\n/gu, "\n");
  const listed = new Map();
  const lines = sums.endsWith("\n") ? sums.slice(0, -1).split("\n") : sums.split("\n");
  if (lines.length !== HASHED_FILES.length) fail("SHA256SUMS count");
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  (publication\.json|discovery\.json|inspection\.json)$/u.exec(line);
    if (match === null || listed.has(match[2])) fail("SHA256SUMS layout");
    listed.set(match[2], match[1]);
  }
  for (const name of HASHED_FILES) {
    if (listed.get(name) !== sha256(readFileSync(join(directory, name)))) fail(`SHA256SUMS ${name}`);
  }
}

function assertDiscoveryLocator(discoveryPath, repository, tag) {
  let bytes;
  try {
    bytes = readFileSync(discoveryPath);
  } catch {
    fail("discovery locator");
  }
  if (bytes.length > DISCOVERY_MAX_BYTES) fail("discovery locator");
  let discovery;
  try {
    discovery = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("discovery locator");
  }
  const expected = `https://github.com/${repository}/releases/download/${tag}/publication.json`;
  if (
    discovery === null ||
    typeof discovery !== "object" ||
    Array.isArray(discovery) ||
    discovery.locator !== expected
  )
    fail("discovery locator");
}

function assertFirstIntakeFreshness(bytes, now) {
  let results;
  try {
    results = JSON.parse(bytes);
  } catch {
    fail("attestation timestamp JSON");
  }
  if (!Array.isArray(results) || results.length !== 1) fail("attestation result count");
  const timestamps = results[0]?.verificationResult?.verifiedTimestamps;
  if (!Array.isArray(timestamps) || timestamps.length === 0 || timestamps.length > 16)
    fail("attestation timestamps");
  const moments = timestamps.map((entry) => {
    if (typeof entry?.timestamp !== "string" || typeof entry?.type !== "string" || typeof entry?.uri !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u.test(entry.timestamp))
      fail("attestation timestamp");
    const moment = Date.parse(entry.timestamp);
    if (!Number.isFinite(moment)) fail("attestation timestamp");
    return moment;
  });
  const clock = Date.parse(now);
  const age = clock - Math.min(...moments);
  if (!Number.isSafeInteger(age) || age < 0) fail("attestation clock");
  if (age >= REPORT_MAX_AGE_MS)
    fail("expired immutable publication: Core first intake requires a renewed attested publication address; rerunning the same immutable tag cannot refresh it");
  return Math.min(...moments);
}

function assertOriginalReportFreshness(publicationPath, publishedAt, now) {
  // baseline-inspect already verified the exact signed envelope and its original
  // short verification window. Neither a new GH attestation nor a new download
  // may reset the longer public-report freshness clock.
  let claims;
  try {
    const publication = JSON.parse(readFileSync(publicationPath, "utf8"));
    const payload = publication.envelope.payload;
    if (typeof payload !== "string" || Buffer.from(payload, "base64").toString("base64") !== payload)
      fail("report claims encoding");
    claims = JSON.parse(Buffer.from(payload, "base64").toString("utf8")).predicate.claims;
  } catch {
    fail("report freshness claims");
  }
  const signed = Date.parse(claims?.signedAt);
  const expires = Date.parse(claims?.expiresAt);
  if (!Number.isFinite(signed) || !Number.isFinite(expires) || signed > publishedAt || publishedAt >= expires)
    fail("report attestation outside its signed validity window");
  const age = Date.parse(now) - signed;
  if (!Number.isSafeInteger(age) || age < 0 || age >= REPORT_MAX_AGE_MS)
    fail("report freshness expired: prepare a newly scanned report at a new immutable publication address");
}

export function verifyCompletedPublication({ repository, publisherSha, sourceRef, workflow, scanner, gh, reuseDirectory, request, generation = "initial", now = new Date().toISOString(), run = execute }) {
  const tag = baselinePublicationTag(publisherSha, request.requestSha256, generation);
  if (requiredRelease(repository, tag, publisherSha, gh, run) === undefined) return false;
  const directory = join(reuseDirectory, request.requestSha256);
  mkdirSync(directory, { recursive: false });
  const downloaded = run(gh, [
    "release",
    "download",
    tag,
    "--repo",
    repository,
    "--dir",
    directory,
    "--pattern",
    "publication.json",
    "--pattern",
    "discovery.json",
    "--pattern",
    "inspection.json",
    "--pattern",
    "SHA256SUMS",
  ]);
  if (downloaded.status !== 0) fail(`release download for ${tag}`);
  verifyDownloadedFiles(directory);
  assertDiscoveryLocator(join(directory, "discovery.json"), repository, tag);
  const inspected = run(process.execPath, [
    scanner,
    "baseline-inspect",
    "--discovery",
    join(directory, "discovery.json"),
    "--publication",
    join(directory, "publication.json"),
    "--request-sha256",
    request.requestSha256,
  ]);
  if (inspected.status !== 0 || inspected.stdout !== readFileSync(join(directory, "inspection.json"), "utf8"))
    fail(`independent inspection for ${tag}`);
  const attested = run(gh, [
    "attestation",
    "verify",
    join(directory, "publication.json"),
    "--repo",
    repository,
    "--signer-workflow",
    workflow,
    "--source-ref",
    sourceRef,
    "--source-digest",
    publisherSha,
    "--deny-self-hosted-runners",
    "--cert-oidc-issuer",
    "https://token.actions.githubusercontent.com",
    "--predicate-type",
    "https://slsa.dev/provenance/v1",
    "--format",
    "json",
  ]);
  if (attested.status !== 0) fail(`publisher attestation for ${tag}`);
  const publishedAt = assertFirstIntakeFreshness(attested.stdout, now);
  assertOriginalReportFreshness(join(directory, "publication.json"), publishedAt, now);
  return true;
}

export function main() {
  const options = parseArguments(process.argv);
  const requests = requestFiles(options["--requests"]);
  const pendingDirectory = resolve(options["--pending"]);
  const reuseDirectory = resolve(options["--reuse-directory"]);
  regularDirectory(pendingDirectory, "pending directory", true);
  regularDirectory(reuseDirectory, "reuse directory", true);
  mkdirSync(pendingDirectory, { recursive: false });
  mkdirSync(reuseDirectory, { recursive: false });
  const gh = process.env.GH ?? "gh";
  const pending = [];
  let reused = 0;
  for (const request of requests) {
    if (
      verifyCompletedPublication({
        repository: options["--repository"],
        publisherSha: options["--publisher-sha"],
        generation: options["--generation"],
        sourceRef: options["--source-ref"],
        workflow: options["--workflow"],
        scanner: resolve(options["--scanner"]),
        gh,
        reuseDirectory,
        request,
      })
    ) {
      reused += 1;
    } else {
      copyFileSync(request.path, join(pendingDirectory, request.name));
      pending.push(request.name);
    }
  }
  writeFileSync(
    options["--github-output"],
    `pending=${pending.length > 0}\npending_count=${pending.length}\nreused_count=${reused}\n`,
    { encoding: "utf8", flag: "a" },
  );
  process.stdout.write(`${JSON.stringify({ pending, reused })}\n`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "baseline publication reuse rejected"}\n`);
    process.exitCode = 1;
  }
}
