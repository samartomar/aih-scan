// Projects one verified immutable Scanner publication into Catalog's
// ScannerPublicationConsumerHandoffV1 (consumed by Catalog's
// tools/generate-source-assessment-rows.mjs). It only projects Scanner bytes: every value is
// either taken from the verified release files, the GitHub attestation/run/release metadata
// bound to them, or the explicit reviewed mapping input. Nothing is re-signed, refreshed or
// defaulted, and any malformed or unbound input fails closed before any output exists.
//
// Usage:
//   node tools/emit-consumer-handoff.mjs
//     --release-root <dir holding exactly SHA256SUMS, discovery.json, inspection.json, publication.json>
//     --release <gh release view <tag> -R <repository> --json assets,isDraft,tagName,targetCommitish,url>
//     --attestation-bundle <the Sigstore bundle of the publication's build-provenance attestation:
//                           one bundle as JSON, or one JSON line (gh attestation download)>
//     --run <gh run view <run id> -R <repository>
//            --json attempt,conclusion,databaseId,event,headBranch,headSha,status,url,workflowName>
//     --mapping <reviewed ScannerConsumerMappingV1 file>
//     --repository <owner/name> --publisher-commit <40-hex>
//     --output <new directory>
//
// The tool verifies the attestation itself: it stages the exact publication.json bytes it
// verified and the supplied bundle in a private directory and runs `gh attestation verify`
// against them with every constraint pinned (repository samartomar/aih-scan, the exact
// signer workflow identity at refs/heads/main, the OIDC issuer, the SLSA provenance predicate,
// source ref, source and signer digest = the publisher commit, GitHub-hosted runners only),
// then checks the verifier's JSON with exact field sets. A supplied verification result is
// never trusted, and a missing, malformed or mismatched bundle refuses.
//
// Output (a new directory; the consumer requires the handoff beside publication.json):
//   <output>/publication.json          exact released bytes
//   <output>/consumer-handoff.json     ScannerPublicationConsumerHandoffV1
//   <output>/components/<id>.json      one ScannerComponentObservationHandoffV1 per mapped component
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyBaselineVetAttestationV1 } from "../dist/baseline/attestation-v1.js";
import {
  baselineVetPublicationResultV1,
  parseBaselineVetDiscoveryV1Json,
  resolveBaselineVetDiscoveryV1,
} from "../dist/baseline/publication-v1.js";
import { sourceRelativeSarifV1 } from "../dist/baseline/sarif-source-relative-v1.js";
import {
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  parseStrictJsonObjectV1,
} from "../dist/contract/strict-json-v1.js";
import {
  assertDiscoveryLocator,
  baselinePublicationTag,
  execute,
  verifyDownloadedFiles,
} from "./verify-baseline-publication-reuse.mjs";

const TOOLS = dirname(fileURLToPath(import.meta.url));
const SCANNER_CLI = resolve(TOOLS, "../dist/cli.js");
const PACKAGE_JSON = resolve(TOOLS, "../package.json");
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const SUBJECT = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const WORKFLOW_PATH = ".github/workflows/baseline-publication.yml";
const SOURCE_REF = "refs/heads/main";
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
// The one repository whose baseline publications this tool projects.
const PUBLICATION_REPOSITORY = "samartomar/aih-scan";
const SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const VERIFICATION_RESULT_MEDIA_TYPE =
  "application/vnd.dev.sigstore.verificationresult+json;version=0.1";
const IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1";
// Exactly what gh attestation verify --format json prints for a GitHub Actions provenance
// certificate; a field gh adds or drops fails closed until it is reviewed here.
const CERTIFICATE_KEYS = [
  "buildConfigDigest",
  "buildConfigURI",
  "buildSignerDigest",
  "buildSignerURI",
  "buildTrigger",
  "certificateIssuer",
  "githubWorkflowName",
  "githubWorkflowRef",
  "githubWorkflowRepository",
  "githubWorkflowSHA",
  "githubWorkflowTrigger",
  "issuer",
  "runInvocationURI",
  "runnerEnvironment",
  "sourceRepositoryDigest",
  "sourceRepositoryIdentifier",
  "sourceRepositoryOwnerIdentifier",
  "sourceRepositoryOwnerURI",
  "sourceRepositoryRef",
  "sourceRepositoryURI",
  "sourceRepositoryVisibilityAtSigning",
  "subjectAlternativeName",
];
const VERIFIER_LIMIT = 16 * 1024 * 1024;
const RELEASE_FILES = ["SHA256SUMS", "discovery.json", "inspection.json", "publication.json"];
const FILE_LIMITS = {
  "SHA256SUMS": 1024,
  "discovery.json": 8 * 1024,
  "inspection.json": 64 * 1024,
  "publication.json": 96 * 1024 * 1024,
};
const INPUT_LIMIT = 4 * 1024 * 1024;
// The only Catalog content classes the consumer accepts.
const CONTENT_CLASSES = [
  "exact compiler/source-file closure for assessment only",
  "exact direct plugin skill/source files for assessment only",
];
// The roots Scan's own analyzer profiles hand to analyzers (the namespace profile's
// /aih/source and the SkillSpector container's /scan). Current publications are already
// source-relative; older ones may still carry these absolute spellings. Anything else is
// refused by Scan's normalizer rather than guessed.
const ANALYZER_SOURCE_ROOTS = ["/aih/source", "/scan"];
// The one coverage-gap reason a component may carry today. Coverage is never inferred from
// silence: an analyzer counts as having covered the subject only with positive, subject-bound
// completion evidence. The native observation carries it (it hashes the exact request source
// tree); Scan's SARIF annexes carry none yet, so every SARIF analyzer is a typed gap until a
// Scan completion-evidence contract exists and is recognized here.
const COMPLETION_EVIDENCE_ABSENT = "completion-evidence-absent";
const SARIF_LEVELS = ["none", "note", "warning", "error"];
const SARIF_KINDS = ["pass", "open", "informational", "notApplicable", "review", "fail"];
const NOTIFICATION_KINDS = ["toolExecutionNotifications", "toolConfigurationNotifications"];
const TIMESTAMP =
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u;

function fail(reason) {
  throw new Error(`consumer handoff rejected: ${reason}`);
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const isRecord = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
function record(value, label) {
  if (!isRecord(value)) fail(`${label} object`);
  return value;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(record(value, label)).sort(codeUnitCompare);
  const wanted = [...expected].sort(codeUnitCompare);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    fail(`${label} fields`);
  return value;
}
function text(value, label, max = 2048) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) fail(`${label} text`);
  return value;
}
function equal(actual, expected, label) {
  if (actual !== expected) fail(label);
  return actual;
}
const canonical = (value) => canonicalStrictJsonBytesV1(value);

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
/** One bounded regular file, read through a descriptor that must not change under us. */
function readRegularFile(path, label, maxBytes) {
  let before;
  try {
    before = lstatSync(path);
  } catch {
    fail(`${label} file missing`);
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size <= 0 ||
    before.size > maxBytes
  )
    fail(`${label} file shape`);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || !sameIdentity(before, opened)) fail(`${label} file replaced`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (bytes.length !== before.size || !sameIdentity(opened, after) || !sameIdentity(after, lstatSync(path)))
      fail(`${label} file changed while read`);
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
function utf8(bytes, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail(`${label} UTF-8`);
  }
}
/** Strict JSON (no duplicate keys, well-formed NFC strings) whose root is an object or array. */
function strictJson(bytes, label) {
  const source = utf8(bytes, label).replace(/\r?\n$/u, "");
  try {
    // The whole text must be exactly one JSON value before the strict parser sees it wrapped.
    const value = JSON.parse(source);
    if (value === null || typeof value !== "object") throw new TypeError("root");
    return parseStrictJsonObjectV1(`{"value":${source}}`, label).value;
  } catch (error) {
    fail(`${label} JSON (${error instanceof Error ? error.message : "invalid"})`);
  }
}

function releaseFiles(releaseRoot, repository, publisherCommit) {
  let stat;
  try {
    stat = lstatSync(releaseRoot);
  } catch {
    fail("release root missing");
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("release root directory");
  verifyDownloadedFiles(releaseRoot);
  const files = Object.fromEntries(
    RELEASE_FILES.map((name) => [
      name,
      readRegularFile(join(releaseRoot, name), `release ${name}`, FILE_LIMITS[name]),
    ]),
  );
  // Re-bind the bytes this tool actually holds to SHA256SUMS; the shared verifier read its own.
  const sums = utf8(files.SHA256SUMS, "SHA256SUMS").replace(/\r\n/gu, "\n");
  const listed = new Map();
  for (const line of sums.endsWith("\n") ? sums.slice(0, -1).split("\n") : sums.split("\n")) {
    const match = /^([0-9a-f]{64}) {2}(publication\.json|discovery\.json|inspection\.json)$/u.exec(line);
    if (match === null || listed.has(match[2])) fail("SHA256SUMS layout");
    listed.set(match[2], match[1]);
  }
  for (const name of ["publication.json", "discovery.json", "inspection.json"])
    if (listed.get(name) !== sha256(files[name])) fail(`SHA256SUMS ${name}`);
  let discovery;
  try {
    discovery = parseBaselineVetDiscoveryV1Json(utf8(files["discovery.json"], "discovery"));
  } catch (error) {
    fail(`discovery (${error instanceof Error ? error.message : "invalid"})`);
  }
  const tag = baselinePublicationTag(publisherCommit, discovery.requestSha256);
  assertDiscoveryLocator(join(releaseRoot, "discovery.json"), repository, tag);
  equal(discovery.locator, `https://github.com/${repository}/releases/download/${tag}/publication.json`, "discovery locator");
  return { files, discovery, tag };
}

/** The exact verification the Scanner's `baseline-inspect` performs, in process. */
function verifiedPublication(files, discovery, releaseRoot) {
  let publication;
  let verified;
  try {
    publication = resolveBaselineVetDiscoveryV1({
      discovery,
      publicationBytes: files["publication.json"],
      expectedRequestSha256: discovery.requestSha256,
    });
    verified = verifyBaselineVetAttestationV1({
      ...baselineVetPublicationResultV1(publication),
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
  } catch (error) {
    fail(`publication verification (${error instanceof Error ? error.message : "invalid"})`);
  }
  const inspection = `${canonical(verified.facts).toString("utf8")}\n`;
  if (!Buffer.from(inspection, "utf8").equals(files["inspection.json"]))
    fail("released inspection differs from the verified publication facts");
  // And the Scanner CLI itself, as the publishing workflow ran it.
  const cli = execute(process.execPath, [
    SCANNER_CLI,
    "baseline-inspect",
    "--discovery",
    join(releaseRoot, "discovery.json"),
    "--publication",
    join(releaseRoot, "publication.json"),
    "--request-sha256",
    discovery.requestSha256,
  ]);
  if (cli.status !== 0 || cli.stdout !== inspection)
    fail("Scanner CLI inspection differs from the released inspection");
  return { publication, facts: verified.facts };
}

function releaseMetadata(bytes, repository, publisherCommit, tag, files) {
  const release = exactKeys(
    strictJson(bytes, "release metadata"),
    ["assets", "isDraft", "tagName", "targetCommitish", "url"],
    "release metadata",
  );
  equal(release.tagName, tag, "release tagName");
  equal(release.targetCommitish, publisherCommit, "release targetCommitish");
  equal(release.isDraft, false, "release isDraft");
  equal(release.url, `https://github.com/${repository}/releases/tag/${tag}`, "release url");
  if (!Array.isArray(release.assets) || release.assets.length !== RELEASE_FILES.length)
    fail("release asset closure");
  const seen = new Set();
  const assets = release.assets.map((value) => {
    const asset = exactKeys(
      value,
      ["apiUrl", "contentType", "createdAt", "digest", "downloadCount", "id", "label", "name", "size", "state", "updatedAt", "url"],
      "release asset",
    );
    const name = asset.name;
    if (!RELEASE_FILES.includes(name) || seen.has(name)) fail("release asset closure");
    seen.add(name);
    const bytes = files[name];
    if (
      asset.size !== bytes.length ||
      asset.digest !== `sha256:${sha256(bytes)}` ||
      asset.state !== "uploaded" ||
      asset.url !== `https://github.com/${repository}/releases/download/${tag}/${name}`
    )
      fail(`release asset ${name}`);
    return { name, size: bytes.length, sha256: sha256(bytes) };
  });
  assets.sort((left, right) => codeUnitCompare(left.name, right.name));
  return { tag, url: release.url, targetCommitish: publisherCommit, isDraft: false, assets };
}

/** One Sigstore bundle: a JSON object, or a JSON-lines file holding exactly one bundle. */
function attestationBundle(bytes) {
  const lines = utf8(bytes, "attestation bundle").replace(/\r?\n$/u, "").split(/\r?\n/u);
  if (lines.length !== 1) fail("attestation bundle must hold exactly one bundle");
  const bundle = exactKeys(
    strictJson(Buffer.from(lines[0], "utf8"), "attestation bundle"),
    ["dsseEnvelope", "mediaType", "verificationMaterial"],
    "attestation bundle",
  );
  equal(bundle.mediaType, SIGSTORE_BUNDLE_MEDIA_TYPE, "attestation bundle mediaType");
  exactKeys(bundle.dsseEnvelope, ["payload", "payloadType", "signatures"], "attestation bundle dsseEnvelope");
  record(bundle.verificationMaterial, "attestation bundle verificationMaterial");
  return { bundle, bytes: Buffer.from(`${lines[0]}\n`, "utf8") };
}

function defaultRunGh(args, cwd) {
  const result = spawnSync("gh", args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: VERIFIER_LIMIT,
  });
  if (result.error) fail("attestation verifier gh is unavailable");
  return { status: result.status, stdout: typeof result.stdout === "string" ? result.stdout : "" };
}

/**
 * Verify the bundle against the exact publication bytes with gh's Sigstore verifier and
 * every constraint pinned, the way Core's own baseline-evidence intake does; return gh's
 * verification JSON.
 */
function verifiedAttestationOutput(publicationBytes, bundleBytes, publisherCommit, runGh) {
  const staging = mkdtempSync(join(tmpdir(), "aih-scan-attestation-"));
  try {
    const subject = join(staging, "publication.json");
    const bundle = join(staging, "attestation.jsonl");
    writeFileSync(subject, publicationBytes, { flag: "wx", mode: 0o600 });
    writeFileSync(bundle, bundleBytes, { flag: "wx", mode: 0o600 });
    const result = runGh(
      [
        "attestation",
        "verify",
        subject,
        "--bundle",
        bundle,
        "--format",
        "json",
        "--repo",
        PUBLICATION_REPOSITORY,
        "--predicate-type",
        PROVENANCE_PREDICATE,
        "--cert-identity",
        `https://github.com/${PUBLICATION_REPOSITORY}/${WORKFLOW_PATH}@${SOURCE_REF}`,
        "--cert-oidc-issuer",
        OIDC_ISSUER,
        "--source-ref",
        SOURCE_REF,
        "--source-digest",
        publisherCommit,
        "--signer-digest",
        publisherCommit,
        "--deny-self-hosted-runners",
      ],
      staging,
    );
    if (result.status !== 0) fail("attestation verification failed");
    if (typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > VERIFIER_LIMIT)
      fail("attestation verification output");
    return Buffer.from(result.stdout, "utf8");
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

function attestationFacts(bytes, bundle, repository, publisherCommit, publicationSha256, claims) {
  const results = strictJson(bytes, "attestation");
  if (!Array.isArray(results) || results.length !== 1) fail("attestation result count");
  const result = exactKeys(results[0], ["attestation", "verificationResult"], "attestation result");
  const attestation = exactKeys(
    result.attestation,
    ["bundle", "bundle_url", "initiator"],
    "attestation record",
  );
  // gh must report on the bundle this tool handed it, byte-for-byte in canonical form.
  if (!canonical(record(attestation.bundle, "attestation record bundle")).equals(canonical(bundle)))
    fail("attestation bundle is not the verified bundle");
  const verification = exactKeys(
    result.verificationResult,
    ["mediaType", "signature", "statement", "verifiedIdentity", "verifiedTimestamps"],
    "attestation verificationResult",
  );
  equal(verification.mediaType, VERIFICATION_RESULT_MEDIA_TYPE, "attestation verificationResult mediaType");
  const statement = exactKeys(
    verification.statement,
    ["_type", "predicate", "predicateType", "subject"],
    "attestation statement",
  );
  equal(statement._type, IN_TOTO_STATEMENT, "attestation statement _type");
  equal(statement.predicateType, PROVENANCE_PREDICATE, "attestation predicateType");
  record(statement.predicate, "attestation predicate");
  // One publish job attests every batch publication of its run (subject-path
  // publications/*/publication.json), so the subject list names each exactly once.
  if (
    !Array.isArray(statement.subject) ||
    statement.subject.length === 0 ||
    statement.subject.length > 1000
  )
    fail("attestation subject count");
  const subjects = statement.subject.map((value) => {
    const subject = exactKeys(value, ["digest", "name"], "attestation subject");
    const digest = exactKeys(subject.digest, ["sha256"], "attestation subject digest");
    if (subject.name !== "publication.json" || typeof digest.sha256 !== "string" || !HEX_64.test(digest.sha256))
      fail("attestation subject is not a publication.json digest");
    return digest.sha256;
  });
  if (new Set(subjects).size !== subjects.length) fail("attestation subject repeated");
  if (!subjects.includes(publicationSha256))
    fail("attestation subject does not cover the released publication.json");
  const certificate = exactKeys(
    exactKeys(verification.signature, ["certificate"], "attestation signature").certificate,
    CERTIFICATE_KEYS,
    "attestation certificate",
  );
  const workflowUri = `https://github.com/${repository}/${WORKFLOW_PATH}@${SOURCE_REF}`;
  const expected = {
    issuer: OIDC_ISSUER,
    subjectAlternativeName: workflowUri,
    buildSignerURI: workflowUri,
    buildSignerDigest: publisherCommit,
    buildConfigURI: workflowUri,
    buildConfigDigest: publisherCommit,
    sourceRepositoryURI: `https://github.com/${repository}`,
    sourceRepositoryDigest: publisherCommit,
    sourceRepositoryRef: SOURCE_REF,
    runnerEnvironment: "github-hosted",
    githubWorkflowRepository: repository,
    githubWorkflowSHA: publisherCommit,
    githubWorkflowRef: SOURCE_REF,
  };
  for (const [key, value] of Object.entries(expected))
    equal(certificate[key], value, `attestation ${key}`);
  const identity = exactKeys(
    verification.verifiedIdentity,
    ["issuer", "runnerEnvironment", "subjectAlternativeName"],
    "attestation verifiedIdentity",
  );
  equal(
    exactKeys(identity.subjectAlternativeName, ["subjectAlternativeName"], "attestation verifiedIdentity SAN")
      .subjectAlternativeName,
    workflowUri,
    "attestation verifiedIdentity subjectAlternativeName",
  );
  exactKeys(identity.issuer, ["issuer", "regexp"], "attestation verifiedIdentity issuer");
  equal(identity.runnerEnvironment, "github-hosted", "attestation verifiedIdentity runnerEnvironment");
  const invocation = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/actions\/runs\/([1-9]\d{0,19})\/attempts\/([1-9]\d{0,3})$/u.exec(
    text(certificate.runInvocationURI, "attestation runInvocationURI"),
  );
  if (invocation === null || invocation[1] !== repository) fail("attestation runInvocationURI");
  const timestamps = verification.verifiedTimestamps;
  if (!Array.isArray(timestamps) || timestamps.length === 0 || timestamps.length > 16)
    fail("attestation timestamps");
  const signed = Date.parse(claims.signedAt);
  const expires = Date.parse(claims.expiresAt);
  const verifiedTimestamps = timestamps.map((value) => {
    const entry = exactKeys(value, ["timestamp", "type", "uri"], "attestation timestamp");
    text(entry.type, "attestation timestamp type", 64);
    text(entry.uri, "attestation timestamp uri", 512);
    if (typeof entry.timestamp !== "string" || !TIMESTAMP.test(entry.timestamp))
      fail("attestation timestamp");
    const moment = Date.parse(entry.timestamp);
    // The publisher attests inside the signed observation window, never after it.
    if (!Number.isFinite(moment) || moment < signed || moment >= expires)
      fail("attestation timestamp outside the signed observation window");
    return { type: entry.type, uri: entry.uri, timestamp: entry.timestamp };
  });
  return {
    facts: {
      subject: { name: "publication.json", digest: { sha256: publicationSha256 } },
      subjectCount: subjects.length,
      predicateType: PROVENANCE_PREDICATE,
      issuer: OIDC_ISSUER,
      buildSignerURI: workflowUri,
      buildSignerDigest: publisherCommit,
      sourceRepositoryURI: expected.sourceRepositoryURI,
      sourceRepositoryDigest: publisherCommit,
      sourceRepositoryRef: SOURCE_REF,
      runnerEnvironment: "github-hosted",
      runInvocationURI: certificate.runInvocationURI,
      verifiedTimestampCount: verifiedTimestamps.length,
      verifiedTimestamps,
    },
    runId: Number(invocation[2]),
    attempt: Number(invocation[3]),
    workflowName: text(certificate.githubWorkflowName, "attestation githubWorkflowName", 256),
  };
}

function runFacts(bytes, repository, publisherCommit, attested) {
  const run = exactKeys(
    strictJson(bytes, "run metadata"),
    ["attempt", "conclusion", "databaseId", "event", "headBranch", "headSha", "status", "url", "workflowName"],
    "run",
  );
  equal(run.databaseId, attested.runId, "run databaseId");
  equal(run.attempt, attested.attempt, "run attempt");
  equal(run.headSha, publisherCommit, "run headSha");
  equal(run.headBranch, "main", "run headBranch");
  equal(run.url, `https://github.com/${repository}/actions/runs/${attested.runId}`, "run url");
  equal(run.workflowName, attested.workflowName, "run workflowName");
  return {
    runId: attested.runId,
    attempt: attested.attempt,
    status: text(run.status, "run status", 64),
    conclusion: text(run.conclusion, "run conclusion", 64),
    headSha: publisherCommit,
    headBranch: "main",
    event: text(run.event, "run event", 64),
    url: run.url,
    workflowName: attested.workflowName,
    workflowPath: WORKFLOW_PATH,
  };
}

function mappingInput(bytes, request) {
  const mapping = exactKeys(
    strictJson(bytes, "mapping"),
    ["components", "contentClass", "exclusions", "protocol", "requestSha256"],
    "mapping",
  );
  equal(mapping.protocol, "ScannerConsumerMappingV1", "mapping protocol");
  equal(mapping.requestSha256, request.requestSha256, "mapping requestSha256");
  if (!CONTENT_CLASSES.includes(mapping.contentClass)) fail("mapping contentClass");
  if (!Array.isArray(mapping.components) || mapping.components.length === 0)
    fail("mapping components");
  if (!Array.isArray(mapping.exclusions)) fail("mapping exclusions");
  const requested = new Map(request.components.map((component) => [component.id, component]));
  const covered = new Set();
  const cover = (id) => {
    if (typeof id !== "string" || !requested.has(id) || covered.has(id))
      fail(`mapping covers an unknown or repeated Scanner component: ${String(id)}`);
    covered.add(id);
    return requested.get(id);
  };
  const assets = new Set();
  const components = mapping.components.map((value) => {
    const entry = exactKeys(value, ["catalogAssetId", "scannerComponentId"], "mapping component");
    const component = cover(entry.scannerComponentId);
    const prefix = `${request.source.id}/${component.content}:`;
    const assetId = text(entry.catalogAssetId, "mapping catalogAssetId", 300);
    if (!assetId.startsWith(prefix) || !SUBJECT.test(assetId.slice(prefix.length)) || assets.has(assetId))
      fail(`mapping catalogAssetId ${assetId}`);
    assets.add(assetId);
    return { component, catalogAssetId: assetId };
  });
  const exclusions = mapping.exclusions.map((value) => {
    const entry = exactKeys(value, ["reason", "scannerComponentId"], "mapping exclusion");
    cover(entry.scannerComponentId);
    return { scannerComponentId: entry.scannerComponentId, reason: text(entry.reason, "mapping exclusion reason", 1024) };
  });
  if (covered.size !== requested.size) fail("mapping covers only part of the Scanner request");
  return { contentClass: mapping.contentClass, components, exclusions };
}

function positive(value, label) {
  if (value === undefined) return null;
  if (!Number.isSafeInteger(value) || value < 1) fail(label);
  return value;
}
function projectedLocations(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(`${label} locations`);
  return value.map((entry) => {
    const physical = record(record(entry, `${label} location`).physicalLocation, `${label} physicalLocation`);
    const artifact = record(physical.artifactLocation, `${label} artifactLocation`);
    const region = physical.region === undefined ? {} : record(physical.region, `${label} region`);
    return {
      path: text(artifact.uri, `${label} artifact uri`, 4096),
      startLine: positive(region.startLine, `${label} startLine`),
      startColumn: positive(region.startColumn, `${label} startColumn`),
    };
  });
}
function messageText(value, label) {
  if (value === undefined) return null;
  const message = record(value, `${label} message`);
  if (typeof message.text !== "string") fail(`${label} message without text`);
  return message.text;
}
function enumOrNull(value, allowed, label) {
  if (value === undefined) return null;
  if (!allowed.includes(value)) fail(label);
  return value;
}
function optionalRecord(value, label) {
  return value === undefined ? null : record(value, label);
}

/** Every finding and coverage notification of the publication, related to its components. */
function observationRows(publication, request) {
  const within = (component, path) =>
    component.paths.some((root) => path === root || path.startsWith(`${root}/`));
  const owners = (locations) =>
    request.components
      .filter((component) => locations.some((location) => within(component, location.path)))
      .map((component) => component.id);
  const annexes = new Map(publication.annexes.map((annex) => [annex.path, annex.bytesBase64]));
  const findings = [];
  const notifications = [];
  const analyzers = [];
  const completionEvidence = new Set();
  for (const observation of publication.receipt.observations) {
    const { analyzer } = observation;
    const encoded = annexes.get(observation.annex.path);
    if (encoded === undefined) fail(`annex ${observation.annex.path}`);
    const document = parseStrictJsonObjectV1(Buffer.from(encoded, "base64").toString("utf8"), `${analyzer} annex`);
    const row = {
      analyzer,
      analyzerVersion: observation.analyzerVersion,
      annex: { ...observation.annex },
      executionSuccessful: false,
      resultCount: 0,
      notificationCount: 0,
    };
    analyzers.push(row);
    if (observation.annex.mediaType === "application/vnd.aih.baseline-native+json") {
      row.executionSuccessful =
        document.protocol === "BaselineNativeObservationV1" &&
        document.sourceTreeSha256 === request.source.treeSha256;
      if (row.executionSuccessful) completionEvidence.add(analyzer);
      continue;
    }
    let sarif;
    try {
      sarif = sourceRelativeSarifV1(document, ANALYZER_SOURCE_ROOTS).document;
    } catch (error) {
      fail(`${analyzer} annex locations (${error instanceof Error ? error.message : "invalid"})`);
    }
    if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) fail(`${analyzer} SARIF runs`);
    let successful = true;
    sarif.runs.forEach((value, runIndex) => {
      const run = record(value, `${analyzer} SARIF run`);
      const label = `${analyzer} run ${runIndex}`;
      if (run.invocations !== undefined && !Array.isArray(run.invocations)) fail(`${label} invocations`);
      const invocations = run.invocations ?? [];
      if (invocations.length === 0) successful = false;
      for (const entry of invocations) {
        const invocation = record(entry, `${label} invocation`);
        if (invocation.executionSuccessful !== true) successful = false;
        for (const kind of NOTIFICATION_KINDS) {
          if (invocation[kind] === undefined) continue;
          if (!Array.isArray(invocation[kind])) fail(`${label} ${kind}`);
          for (const item of invocation[kind]) {
            const notification = record(item, `${label} notification`);
            const locations = projectedLocations(notification.locations, `${label} notification`);
            const componentIds = owners(locations);
            notifications.push({
              analyzer,
              runIndex,
              kind,
              level: enumOrNull(notification.level, SARIF_LEVELS, `${label} notification level`),
              message: messageText(notification.message, `${label} notification`),
              descriptor: optionalRecord(notification.descriptor, `${label} notification descriptor`),
              properties: optionalRecord(notification.properties, `${label} notification properties`),
              locations,
              componentIds,
              unmapped: componentIds.length === 0,
            });
            row.notificationCount += 1;
          }
        }
      }
      if (run.results !== undefined && !Array.isArray(run.results)) fail(`${label} results`);
      for (const item of run.results ?? []) {
        const result = record(item, `${label} result`);
        const locations = projectedLocations(result.locations, `${label} result`);
        const componentIds = owners(locations);
        if (result.ruleId !== undefined) text(result.ruleId, `${label} ruleId`, 512);
        findings.push({
          analyzer,
          runIndex,
          ruleId: result.ruleId ?? null,
          level: enumOrNull(result.level, SARIF_LEVELS, `${label} result level`),
          kind: enumOrNull(result.kind, SARIF_KINDS, `${label} result kind`),
          message: messageText(result.message, `${label} result`),
          locations,
          componentIds,
          unmapped: componentIds.length === 0,
        });
        row.resultCount += 1;
      }
    });
    row.executionSuccessful = successful;
  }
  return { findings, notifications, analyzers, completionEvidence };
}

function tally(rows, keyOf) {
  const counts = new Map();
  for (const row of rows) {
    const key = String(keyOf(row));
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => codeUnitCompare(left, right)));
}
const findingSummary = (rows) => ({
  count: rows.length,
  byAnalyzer: tally(rows, (row) => row.analyzer),
  byLevel: tally(rows, (row) => row.level),
  byRule: tally(rows, (row) => row.ruleId),
});
function reasonCode(row) {
  const code = row.properties?.reasonCode;
  if (code !== undefined && typeof code !== "string") fail("notification reasonCode");
  return code ?? null;
}
const coverageSummary = (rows) => ({
  count: rows.length,
  byAnalyzer: tally(rows, (row) => row.analyzer),
  byLevel: tally(rows, (row) => row.level),
  byMessage: tally(rows, (row) => row.message),
  byReasonCode: tally(rows, reasonCode),
});
function artifactName(scannerComponentId) {
  const name = `${scannerComponentId.replace(/[^a-z0-9-]/gu, "-")}.json`;
  if (!/^[a-z0-9-]+\.json$/u.test(name)) fail(`component artifact name ${scannerComponentId}`);
  return name;
}
function scanPackage() {
  const manifest = record(
    strictJson(readRegularFile(PACKAGE_JSON, "Scanner package.json", 64 * 1024), "Scanner package.json"),
    "Scanner package.json",
  );
  equal(manifest.name, "@aihq/scan", "Scanner package name");
  return {
    package: manifest.name,
    version: text(manifest.version, "Scanner package version", 64),
    node: text(record(manifest.engines, "Scanner engines").node, "Scanner engines.node", 64),
  };
}

export function emitConsumerHandoffV1(options, { runGh = defaultRunGh } = {}) {
  const repository = options.repository;
  const publisherCommit = options.publisherCommit;
  if (typeof repository !== "string" || !REPOSITORY.test(repository)) fail("repository");
  if (repository !== PUBLICATION_REPOSITORY) fail(`repository must be ${PUBLICATION_REPOSITORY}`);
  if (typeof publisherCommit !== "string" || !HEX_40.test(publisherCommit)) fail("publisher commit");
  const output = resolve(text(options.output, "output", 4096));
  if (lstatSync(output, { throwIfNoEntry: false }) !== undefined) fail("output already exists");
  const parent = lstatSync(dirname(output), { throwIfNoEntry: false });
  if (parent === undefined || !parent.isDirectory() || parent.isSymbolicLink())
    fail("output parent directory");

  const releaseRoot = resolve(text(options.releaseRoot, "release root", 4096));
  const { files, discovery, tag } = releaseFiles(releaseRoot, repository, publisherCommit);
  const { publication, facts } = verifiedPublication(files, discovery, releaseRoot);
  const request = publication.request;
  const receipt = publication.receipt;
  const publicationSha256 = sha256(files["publication.json"]);
  const release = releaseMetadata(
    readRegularFile(resolve(options.release), "release metadata", INPUT_LIMIT),
    repository,
    publisherCommit,
    tag,
    files,
  );
  const bundle = attestationBundle(
    readRegularFile(resolve(options.attestationBundle), "attestation bundle", INPUT_LIMIT),
  );
  const attested = attestationFacts(
    verifiedAttestationOutput(files["publication.json"], bundle.bytes, publisherCommit, runGh),
    bundle.bundle,
    repository,
    publisherCommit,
    publicationSha256,
    facts.claims,
  );
  const workflow = runFacts(
    readRegularFile(resolve(options.run), "run metadata", INPUT_LIMIT),
    repository,
    publisherCommit,
    attested,
  );
  const mapping = mappingInput(readRegularFile(resolve(options.mapping), "mapping", INPUT_LIMIT), request);
  const api = scanPackage();

  const rows = observationRows(publication, request);
  const globalRows = rows.notifications.filter((row) => row.locations.length === 0);
  const locationRows = rows.notifications.filter((row) => row.locations.length > 0);
  const executionByAnalyzer = new Map(rows.analyzers.map((row) => [row.analyzer, row]));
  const requestedAnalyzers = [...new Set(request.components.flatMap((component) => component.analyzers))];
  const missingAnalyzers = requestedAnalyzers.filter((analyzer) => !executionByAnalyzer.has(analyzer)).sort(codeUnitCompare);
  const failedAnalyzers = rows.analyzers.filter((row) => !row.executionSuccessful).map((row) => row.analyzer).sort(codeUnitCompare);
  const completionEvidenceAbsent = requestedAnalyzers
    .filter((analyzer) => !rows.completionEvidence.has(analyzer))
    .sort(codeUnitCompare);
  const coverageComplete = rows.notifications.length === 0 && completionEvidenceAbsent.length === 0;
  const common = {
    authority: "none",
    riskDecision: "consumer_required",
    publisherCommit,
    source: request.source,
    requestSha256: request.requestSha256,
    receiptSha256: receipt.receiptSha256,
    publicationSha256,
  };

  const artifacts = [];
  const summaries = [];
  const mappedFindings = [];
  const names = new Set();
  for (const { component, catalogAssetId } of mapping.components) {
    const findings = rows.findings.filter((row) => row.componentIds.includes(component.id));
    const locationBound = locationRows.filter((row) => row.componentIds.includes(component.id));
    const coverageGaps = component.analyzers
      .filter((analyzer) => !rows.completionEvidence.has(analyzer))
      .map((analyzer) => ({ analyzer, reason: COMPLETION_EVIDENCE_ABSENT }));
    const componentCoverageComplete =
      locationBound.length === 0 && globalRows.length === 0 && coverageGaps.length === 0;
    const notified = `${locationBound.length} location-bound and ${globalRows.length} global Scanner coverage notifications remain unresolved`;
    const artifact = {
      protocol: "ScannerComponentObservationHandoffV1",
      ...common,
      outcome: "observed",
      scannerComponentId: component.id,
      catalogAssetId,
      content: component.content,
      paths: component.paths,
      treeSha256: component.treeSha256,
      requestedAnalyzers: component.analyzers,
      analyzerExecution: component.analyzers.flatMap((analyzer) => {
        const row = executionByAnalyzer.get(analyzer);
        return row === undefined ? [] : [row];
      }),
      findings,
      findingSummary: findingSummary(findings),
      locationBoundCoverageNotifications: locationBound,
      locationBoundCoverageSummary: coverageSummary(locationBound),
      globalCoverageNotifications: globalRows,
      globalCoverageSummary: coverageSummary(globalRows),
      coverageComplete: componentCoverageComplete,
      coverageGaps,
      coverageDisposition: componentCoverageComplete
        ? "Every requested analyzer carries subject-bound completion evidence and the Scanner reported no coverage notifications for this component; Scanner authority none."
        : coverageGaps.length === 0
          ? `${notified}; Scanner authority none.`
          : `${notified}, and ${coverageGaps.length} requested analyzers (${coverageGaps.map((gap) => gap.analyzer).join(", ")}) carry no subject-bound completion evidence; Scanner authority none.`,
    };
    const name = artifactName(component.id);
    if (names.has(name)) fail(`component artifact name collision ${name}`);
    names.add(name);
    const bytes = canonical(artifact);
    artifacts.push({ name, bytes });
    mappedFindings.push(...findings);
    summaries.push({
      scannerComponentId: component.id,
      catalogAssetId,
      content: component.content,
      paths: component.paths,
      treeSha256: component.treeSha256,
      requestedAnalyzers: component.analyzers,
      findings: artifact.findingSummary,
      locationBoundCoverage: artifact.locationBoundCoverageSummary,
      globalCoverage: artifact.globalCoverageSummary,
      observationArtifact: { path: `components/${name}`, byteLength: bytes.length, sha256: sha256(bytes) },
    });
  }
  const unmappedFindings = rows.findings.filter((row) => row.unmapped);
  const gaps =
    !coverageComplete || unmappedFindings.length > 0 || missingAnalyzers.length > 0 || failedAnalyzers.length > 0;
  const handoff = {
    protocol: "ScannerPublicationConsumerHandoffV1",
    ...common,
    outcome: gaps ? "observed_with_gaps" : "observed",
    api,
    sourceArchive: {
      repository: `${request.source.owner}/${request.source.repository}`,
      pinnedCommit: request.source.pinnedCommit,
      treeSha256: request.source.treeSha256,
      basis: "The signed request source of the verified publication; the Scanner hashed this exact tree.",
    },
    discoverySha256: sha256(files["discovery.json"]),
    inspectionSha256: sha256(files["inspection.json"]),
    release,
    workflow,
    attestation: attested.facts,
    envelope: {
      authority: facts.authority,
      envelopeValid: facts.envelopeValid,
      annexesComplete: facts.annexesComplete,
      // The same run's publish job attests only the publication.json it downloaded from the
      // run's own artifact (by artifact id, digest checked); the attested subject digest is the
      // released asset digest and these release bytes.
      sameRunArtifactAndReleaseBytesMatch:
        attested.facts.subject.digest.sha256 === publicationSha256 &&
        release.assets.some((asset) => asset.name === "publication.json" && asset.sha256 === publicationSha256),
      cliInspectionMatchesReleasedInspection: true,
      signer: facts.signer,
      claims: facts.claims,
    },
    analyzers: rows.analyzers,
    analyzerGaps: {
      missingAnalyzers,
      failedAnalyzers,
      errorNotificationCount: rows.notifications.filter((row) => row.level === "error").length,
      coverageWarningCount: rows.notifications.filter((row) => row.level === "warning").length,
      completionEvidenceAbsent,
      coverageComplete,
    },
    findings: {
      mappedToDeclaredClosures: findingSummary(mappedFindings),
      repository: findingSummary(rows.findings),
      unmapped: findingSummary(unmappedFindings),
    },
    coverageNotifications: {
      global: coverageSummary(globalRows),
      locationBound: coverageSummary(locationRows),
      unmappedLocationBound: coverageSummary(locationRows.filter((row) => row.unmapped)),
    },
    mapping: {
      sourceId: request.source.id,
      requestSha256: request.requestSha256,
      sourceTreeSha256: request.source.treeSha256,
      contentClass: mapping.contentClass,
      runtimeCapabilityClaim: [],
      exclusions: mapping.exclusions,
      components: mapping.components.map(({ component, catalogAssetId }) => ({
        scannerComponentId: component.id,
        catalogAssetId,
        paths: component.paths,
        treeSha256: component.treeSha256,
        analyzers: component.analyzers,
      })),
    },
    components: summaries,
    rawReports: receipt.observations.map((observation, index) => ({
      analyzer: observation.analyzer,
      analyzerVersion: observation.analyzerVersion,
      ...observation.annex,
      locator: `publication.json#/annexes/${index}`,
    })),
    localInspection: {
      tool: `${api.package}@${api.version} baseline-inspect`,
      inspectionSha256: sha256(files["inspection.json"]),
      matchesReleasedInspection: true,
    },
  };
  const handoffBytes = canonical(handoff);

  // Everything is verified and rendered; only now create the new output.
  mkdirSync(output, { recursive: false });
  try {
    mkdirSync(join(output, "components"), { recursive: false });
    writeFileSync(join(output, "publication.json"), files["publication.json"], { flag: "wx" });
    for (const { name, bytes } of artifacts)
      writeFileSync(join(output, "components", name), bytes, { flag: "wx" });
    writeFileSync(join(output, "consumer-handoff.json"), handoffBytes, { flag: "wx" });
  } catch (error) {
    rmSync(output, { recursive: true, force: true });
    throw error;
  }
  return {
    handoff: join(output, "consumer-handoff.json"),
    publication: join(output, "publication.json"),
    components: artifacts.length,
    outcome: handoff.outcome,
  };
}

const ARGUMENTS = {
  "release-root": "releaseRoot",
  release: "release",
  "attestation-bundle": "attestationBundle",
  run: "run",
  mapping: "mapping",
  repository: "repository",
  "publisher-commit": "publisherCommit",
  output: "output",
};
export function parseArguments(argv) {
  const values = {};
  if (argv.length !== Object.keys(ARGUMENTS).length * 2) fail("arguments");
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    const name = typeof key === "string" && key.startsWith("--") ? ARGUMENTS[key.slice(2)] : undefined;
    if (name === undefined || !Object.hasOwn(ARGUMENTS, key.slice(2)) || name in values)
      fail("arguments");
    if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) fail("arguments");
    values[name] = value;
  }
  return values;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    const result = emitConsumerHandoffV1(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "consumer handoff rejected"}\n`);
    process.exitCode = 1;
  }
}
