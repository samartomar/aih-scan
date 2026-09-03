#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  parseBaselineVetAttestationEnvelopeV1Json,
  signBaselineVetBundleV1,
  verifyBaselineVetAttestationV1,
} from "./baseline/attestation-v1.js";
import {
  canonicalBaselineVetRequestV1Bytes,
  executeBaselineVetBatchV1,
  parseBaselineVetRequestV1Json,
} from "./baseline/batch-v1.js";
import {
  readBaselineVetBundleForSigningV1,
  readBaselineVetBundleV1,
  writeBaselineVetBundleV1,
} from "./baseline/bundle-v1.js";
import {
  baselineVetPublicationResultV1,
  canonicalBaselineVetDiscoveryV1Bytes,
  canonicalBaselineVetPublicationV1Bytes,
  createBaselineVetDiscoveryV1,
  createBaselineVetPublicationV1,
  parseBaselineVetDiscoveryV1Json,
  resolveBaselineVetDiscoveryV1,
} from "./baseline/publication-v1.js";
import { createBaselineAnalyzerExecutionV1 } from "./baseline/runtime-v1.js";
import { captureCiscoOciCandidateV2 } from "./cisco/capture-v2.js";
import { dockerRunner } from "./cli/docker-runner.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "./contract/strict-json-v1.js";
import {
  canonicalCoreOrganizationEvidenceEnvelopeV1Bytes,
  coreOrganizationEvidenceEnvelopeDigestV1,
  projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1,
} from "./core/organization-evidence-envelope-v1.js";
import {
  canonicalScanAttestationEnvelopeBytesV2,
  parseScanAttestationEnvelopeV2Json,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "./observation/scan-attestation-v2.js";
import { readScanCaptureBundleV2, writeScanCaptureBundleV2 } from "./observation/scan-bundle-v2.js";
import { captureRegisteredDetectorCandidateV2 } from "./registration/capture-registered-detector-v2.js";

const maxInputBytes = 2 * 1024 * 1024;
const projectCoreEvidenceUsage =
  "Usage: aih-scan project-core-evidence --evidence <file> --bundle <directory> --roots <file> --expected <file> --subject-digest <sha256:...> --output <new-file> [--seen <file>]\n";
const baselineVetUsage =
  "Usage: aih-scan baseline-vet --request <canonical-file> --source <directory> --output <new-directory>\n";
const baselineSignUsage =
  "Usage: aih-scan baseline-sign --request <canonical-file> --bundle <directory> --signer <file> --private-key <file> --claims <file> --output <new-file>\n";
const baselineVerifyUsage =
  "Usage: aih-scan baseline-verify --evidence <file> --request <canonical-file> --bundle <directory> --roots <file> --expected <file> [--seen <file>]\n";
const baselinePackUsage =
  "Usage: aih-scan baseline-pack --evidence <file> --request <canonical-file> --bundle <directory> --roots <file> --expected <file> --locator <immutable-https-url> --publication <new-file> --discovery <new-file> [--seen <file>]\n";
const baselineInspectUsage =
  "Usage: aih-scan baseline-inspect --discovery <file> --publication <file> --request-sha256 <sha256>\n";
function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}
function sameIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
function sameFileReference(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}
function readBoundedRegularFile(path: string, label: string, maximumBytes: number): Buffer {
  const resolved = resolve(path);
  const beforePath = lstatSync(resolved);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > maximumBytes
  )
    fail(`${label} file shape`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(beforePath, before))
      fail(`${label} file replacement`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(resolved);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > maximumBytes ||
      after.nlink !== 1 ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, afterPath)
    )
      fail(`${label} file replacement`);
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
function readText(path: string, label: string, maximumBytes = maxInputBytes): string {
  const bytes = readBoundedRegularFile(path, label, maximumBytes);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail(`${label} UTF-8`);
  return text;
}
function readPrivateKey(path: string): string {
  const resolved = resolve(path),
    stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > 64 * 1024)
    fail("private key file shape");
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    fail("private key file permissions");
  const bytes = readBoundedRegularFile(resolved, "private key", 64 * 1024);
  const after = lstatSync(resolved);
  if (process.platform !== "win32" && (after.mode & 0o077) !== 0)
    fail("private key file permissions");
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail("private key UTF-8");
  return text;
}
function decodeCanonicalBase64(value: string, label: string, maximumBytes: number): Buffer {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    value.length > Math.ceil(maximumBytes / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    fail(`${label} base64`);
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength > maximumBytes || decoded.toString("base64") !== value)
    fail(`${label} base64`);
  return decoded;
}
function exactWire(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0 ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field)) ||
    fields.some((field) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, field);
      return descriptor === undefined || !("value" in descriptor);
    })
  )
    fail(`${label} fields`);
}
function rootsFromFile(path: string) {
  const rootsWire = readJson(path, "roots");
  exactWire(rootsWire, ["roots"], "roots");
  const rootsValue = rootsWire.roots;
  if (!Array.isArray(rootsValue) || rootsValue.length === 0 || rootsValue.length > 64)
    fail("roots shape");
  return rootsValue.map((value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) fail("root object");
    const root = value as Record<string, unknown>;
    exactWire(root, ["identity", "class", "keyId", "publicKeySpkiBase64"], "root");
    if (
      typeof root.identity !== "string" ||
      (root.class !== "test-ephemeral" && root.class !== "organization") ||
      typeof root.keyId !== "string" ||
      typeof root.publicKeySpkiBase64 !== "string"
    )
      fail("root fields");
    return {
      identity: root.identity,
      class: root.class as "test-ephemeral" | "organization",
      keyId: root.keyId,
      publicKey: createPublicKey({
        key: decodeCanonicalBase64(root.publicKeySpkiBase64, "root SPKI", 4096),
        format: "der",
        type: "spki",
      }),
    };
  });
}
function readJson(path: string, label: string): Record<string, unknown> {
  return parseStrictJsonObjectV1(readText(path, label), label);
}
function flag(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  if (index < 0 || index + 1 >= args.length || args[index + 1]?.startsWith("--"))
    fail(`missing ${name}`);
  if (args.filter((value) => value === name).length !== 1) fail(`duplicate ${name}`);
  return args[index + 1] as string;
}
function verifiedFromCli(args: readonly string[], allowed: ReadonlySet<string>) {
  if (args.length % 2 !== 0 || args.some((arg, index) => index % 2 === 0 && !allowed.has(arg)))
    fail("unknown verify argument");
  const evidence = parseScanAttestationEnvelopeV2Json(
    readText(flag(args, "--evidence"), "evidence"),
  );
  const bundle = readScanCaptureBundleV2({ bundleDirectory: flag(args, "--bundle") });
  const expected = readJson(flag(args, "--expected"), "expected policy");
  const roots = rootsFromFile(flag(args, "--roots"));
  const seen = (() => {
    if (!args.includes("--seen")) return [];
    const seenWire = readJson(flag(args, "--seen"), "replay identities");
    exactWire(seenWire, ["identities"], "replay identities");
    if (!Array.isArray(seenWire.identities)) fail("replay identities");
    return seenWire.identities;
  })();
  return verifyScanAttestationV2({
    envelope: evidence,
    roots,
    expected,
    seenReplayIdentities: seen,
    candidate: bundle.candidate,
    annexArtifacts: bundle.annexArtifacts,
  });
}
function verify(args: readonly string[]): void {
  const result = verifiedFromCli(
    args,
    new Set(["--evidence", "--bundle", "--roots", "--expected", "--seen"]),
  );
  process.stdout.write(`${canonicalStrictJsonBytesV1(result.facts).toString("utf8")}\n`);
}
function writeNew(path: string, bytes: Uint8Array): void {
  const descriptor = openSync(resolve(path), "wx", 0o600);
  try {
    writeFileSync(descriptor, bytes);
  } finally {
    closeSync(descriptor);
  }
}

type DirectorySnapshot = Readonly<{ path: string; realPath: string; stat: Stats }>;
function safeOutputParents(path: string): readonly DirectorySnapshot[] {
  const parents: DirectorySnapshot[] = [];
  for (let current = dirname(path); ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail("output parent link or reparse");
    parents.push({ path: current, realPath: realpathSync.native(current), stat });
    const next = dirname(current);
    if (next === current) return parents;
  }
}
function sameParents(
  left: readonly DirectorySnapshot[],
  right: readonly DirectorySnapshot[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (entry, index) =>
        entry.path === right[index]?.path &&
        entry.realPath === right[index]?.realPath &&
        sameFileReference(entry.stat, right[index]?.stat ?? entry.stat),
    )
  );
}
function writeNewSafeProjection(path: string, bytes: Uint8Array): void {
  const output = resolve(path);
  if (!bytes.byteLength || bytes.byteLength > maxInputBytes) fail("projection output bounds");
  try {
    lstatSync(output);
    fail("projection output already exists");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      // Must-not-exist is the only acceptable pre-write output state.
    } else throw error;
  }
  const beforeParents = safeOutputParents(output);
  const descriptor = openSync(output, "wx", 0o600);
  try {
    const before = fstatSync(descriptor);
    const outputStat = lstatSync(output);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      !outputStat.isFile() ||
      outputStat.isSymbolicLink() ||
      outputStat.nlink !== 1 ||
      !sameIdentity(before, outputStat)
    )
      fail("projection output replacement");
    writeFileSync(descriptor, bytes);
    const after = fstatSync(descriptor);
    const afterOutput = lstatSync(output);
    if (
      after.nlink !== 1 ||
      !sameFileReference(before, after) ||
      !sameFileReference(after, afterOutput) ||
      !sameParents(beforeParents, safeOutputParents(output))
    )
      fail("projection output replacement");
  } finally {
    closeSync(descriptor);
  }
}
function projectCoreEvidence(args: readonly string[]): void {
  const allowed = new Set([
    "--evidence",
    "--bundle",
    "--roots",
    "--expected",
    "--seen",
    "--subject-digest",
    "--output",
  ]);
  const result = verifiedFromCli(args, allowed);
  const envelope = projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
    verified: result,
    subjectDigest: flag(args, "--subject-digest"),
  });
  const bytes = canonicalCoreOrganizationEvidenceEnvelopeV1Bytes(envelope);
  writeNewSafeProjection(flag(args, "--output"), bytes);
  process.stdout.write(
    `${canonicalStrictJsonBytesV1({
      outcome: "projected",
      envelopeSha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      organizationEvidenceDigest: coreOrganizationEvidenceEnvelopeDigestV1(envelope),
    }).toString("utf8")}\n`,
  );
}
async function capture(args: readonly string[]): Promise<void> {
  if (args.length !== 4 || args[0] !== "--request" || args[2] !== "--output") fail("capture usage");
  const requestPath = args[1],
    outputPath = args[3];
  if (typeof requestPath !== "string" || typeof outputPath !== "string") fail("capture arguments");
  const request = readJson(requestPath, "capture request");
  const registered = Object.hasOwn(request, "registration");
  const captureLabel = registered ? "registered capture request" : "Cisco capture request";
  exactWire(
    request,
    registered
      ? ["registration", "detectorId", "layout", "sourceRoot", "selectedClosurePaths", "annexFiles"]
      : ["layout", "sourceRoot", "selectedClosurePaths", "runtime", "annexFiles", "broker"],
    captureLabel,
  );
  const requestBytes = canonicalStrictJsonBytesV1(request);
  if (!Array.isArray(request.annexFiles) || request.annexFiles.length !== 2)
    fail(`${captureLabel} annex files`);
  const annexPayloads = request.annexFiles.map((entry) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      fail(`${captureLabel} annex file`);
    const wire = entry as Record<string, unknown>;
    exactWire(wire, ["descriptorId", "path"], `${captureLabel} annex file`);
    if (
      (wire.descriptorId !== "annex.sbom" && wire.descriptorId !== "annex.provenance") ||
      typeof wire.path !== "string"
    )
      fail(`${captureLabel} annex file`);
    return {
      descriptorId: wire.descriptorId,
      bytes: readBoundedRegularFile(wire.path, `${captureLabel} annex`, 16 * 1024 * 1024),
    };
  });
  if (new Set(annexPayloads.map((entry) => entry.descriptorId)).size !== annexPayloads.length)
    fail(`${captureLabel} annex file duplicate`);
  const captured = registered
    ? await captureRegisteredDetectorCandidateV2({
        registration: request.registration,
        detectorId: request.detectorId,
        layout: request.layout,
        sourceRoot: request.sourceRoot,
        selectedClosurePaths: request.selectedClosurePaths,
        annexPayloads,
        runner: dockerRunner,
      })
    : await captureCiscoOciCandidateV2({
        layout: request.layout,
        sourceRoot: request.sourceRoot,
        selectedClosurePaths: request.selectedClosurePaths,
        runtime: request.runtime,
        annexPayloads,
        broker: request.broker,
        runner: dockerRunner,
      });
  const afterRequest = readJson(requestPath, "capture request");
  if (!requestBytes.equals(canonicalStrictJsonBytesV1(afterRequest)))
    fail("capture request changed during capture");
  writeScanCaptureBundleV2({ outputDirectory: outputPath, ...captured });
}
async function baselineVet(args: readonly string[]): Promise<void> {
  if (
    args.length !== 6 ||
    args[0] !== "--request" ||
    args[2] !== "--source" ||
    args[4] !== "--output"
  )
    fail("baseline-vet usage");
  const requestPath = args[1];
  const sourceRoot = args[3];
  const outputDirectory = args[5];
  if (
    typeof requestPath !== "string" ||
    typeof sourceRoot !== "string" ||
    typeof outputDirectory !== "string"
  )
    fail("baseline-vet arguments");
  const request = parseBaselineVetRequestV1Json(readText(requestPath, "baseline vet request"));
  const requestBytes = canonicalBaselineVetRequestV1Bytes(request);
  const result = await executeBaselineVetBatchV1(request, {
    sourceRoot,
    execute: createBaselineAnalyzerExecutionV1(),
  });
  const afterRequest = parseBaselineVetRequestV1Json(readText(requestPath, "baseline vet request"));
  if (!requestBytes.equals(canonicalBaselineVetRequestV1Bytes(afterRequest)))
    fail("baseline vet request changed during execution");
  writeBaselineVetBundleV1({ outputDirectory, result });
  process.stdout.write(
    `${canonicalStrictJsonBytesV1({
      outcome: "observed",
      requestSha256: request.requestSha256,
      receiptSha256: result.receipt.receiptSha256,
      authority: "none",
    }).toString("utf8")}\n`,
  );
}
function baselineSign(args: readonly string[]): void {
  if (
    args.length !== 12 ||
    args[0] !== "--request" ||
    args[2] !== "--bundle" ||
    args[4] !== "--signer" ||
    args[6] !== "--private-key" ||
    args[8] !== "--claims" ||
    args[10] !== "--output"
  )
    fail("baseline-sign usage");
  const requestPath = args[1],
    bundleDirectory = args[3],
    signerPath = args[5],
    privateKeyPath = args[7],
    claimsPath = args[9],
    outputPath = args[11];
  if (
    [requestPath, bundleDirectory, signerPath, privateKeyPath, claimsPath, outputPath].some(
      (entry) => typeof entry !== "string",
    )
  )
    fail("baseline-sign arguments");
  const request = parseBaselineVetRequestV1Json(
    readText(requestPath as string, "baseline vet request"),
  );
  const signerWire = readJson(signerPath as string, "baseline signer");
  exactWire(signerWire, ["identity", "class", "keyId"], "baseline signer");
  if (
    typeof signerWire.identity !== "string" ||
    (signerWire.class !== "test-ephemeral" && signerWire.class !== "organization") ||
    typeof signerWire.keyId !== "string"
  )
    fail("baseline signer fields");
  const result =
    signerWire.class === "organization"
      ? readBaselineVetBundleForSigningV1({ bundleDirectory: bundleDirectory as string })
      : readBaselineVetBundleV1({ bundleDirectory: bundleDirectory as string });
  const evidence = signBaselineVetBundleV1({
    request,
    result,
    signer: {
      identity: signerWire.identity,
      class: signerWire.class,
      keyId: signerWire.keyId,
      privateKey: createPrivateKey(readPrivateKey(privateKeyPath as string)),
    },
    claims: readJson(claimsPath as string, "baseline claims"),
  });
  writeNew(outputPath as string, canonicalBaselineVetAttestationEnvelopeV1Bytes(evidence));
}
function baselineVerify(args: readonly string[]): void {
  const allowed = new Set([
    "--evidence",
    "--request",
    "--bundle",
    "--roots",
    "--expected",
    "--seen",
  ]);
  if (
    (args.length !== 10 && args.length !== 12) ||
    args.length % 2 !== 0 ||
    args.some((arg, index) => index % 2 === 0 && !allowed.has(arg))
  )
    fail("baseline-verify usage");
  for (const required of ["--evidence", "--request", "--bundle", "--roots", "--expected"])
    flag(args, required);
  const request = parseBaselineVetRequestV1Json(
    readText(flag(args, "--request"), "baseline vet request"),
  );
  const result = readBaselineVetBundleV1({ bundleDirectory: flag(args, "--bundle") });
  const seen = (() => {
    if (!args.includes("--seen")) return { digests: [], receipts: [] };
    const seen = readJson(flag(args, "--seen"), "baseline replay evidence");
    exactWire(seen, ["digests", "receipts"], "baseline replay evidence");
    if (!Array.isArray(seen.digests) || !Array.isArray(seen.receipts))
      fail("baseline replay evidence entries");
    return { digests: seen.digests, receipts: seen.receipts };
  })();
  const verified = verifyBaselineVetAttestationV1({
    envelope: parseBaselineVetAttestationEnvelopeV1Json(
      readText(flag(args, "--evidence"), "baseline evidence"),
    ),
    request,
    result,
    roots: rootsFromFile(flag(args, "--roots")),
    expected: readJson(flag(args, "--expected"), "baseline expected policy"),
    seenEvidenceDigests: seen.digests,
    seenReceiptBindings: seen.receipts,
  });
  process.stdout.write(`${canonicalStrictJsonBytesV1(verified.facts).toString("utf8")}\n`);
}
function baselineReplayFromArgs(args: readonly string[]) {
  if (!args.includes("--seen")) return { digests: [], receipts: [] };
  const seen = readJson(flag(args, "--seen"), "baseline replay evidence");
  exactWire(seen, ["digests", "receipts"], "baseline replay evidence");
  if (!Array.isArray(seen.digests) || !Array.isArray(seen.receipts))
    fail("baseline replay evidence entries");
  return { digests: seen.digests, receipts: seen.receipts };
}
function baselinePack(args: readonly string[]): void {
  const allowed = new Set([
    "--evidence",
    "--request",
    "--bundle",
    "--roots",
    "--expected",
    "--locator",
    "--publication",
    "--discovery",
    "--seen",
  ]);
  if (
    (args.length !== 16 && args.length !== 18) ||
    args.length % 2 !== 0 ||
    args.some((arg, index) => index % 2 === 0 && !allowed.has(arg))
  )
    fail("baseline-pack usage");
  for (const required of [
    "--evidence",
    "--request",
    "--bundle",
    "--roots",
    "--expected",
    "--locator",
    "--publication",
    "--discovery",
  ])
    flag(args, required);
  const replay = baselineReplayFromArgs(args);
  const expected = readJson(flag(args, "--expected"), "baseline expected policy") as {
    readonly now: string;
    readonly signer: {
      readonly identity: string;
      readonly class: "test-ephemeral" | "organization";
      readonly keyId: string;
    };
  };
  const publication = createBaselineVetPublicationV1({
    envelope: parseBaselineVetAttestationEnvelopeV1Json(
      readText(flag(args, "--evidence"), "baseline evidence"),
    ),
    request: parseBaselineVetRequestV1Json(
      readText(flag(args, "--request"), "baseline vet request"),
    ),
    result: readBaselineVetBundleV1({ bundleDirectory: flag(args, "--bundle") }),
    roots: rootsFromFile(flag(args, "--roots")),
    expected,
    seenEvidenceDigests: replay.digests as string[],
    seenReceiptBindings: replay.receipts as Array<{
      requestSha256: string;
      receiptSha256: string;
    }>,
  });
  const discovery = createBaselineVetDiscoveryV1({
    publication,
    locator: flag(args, "--locator"),
  });
  writeNew(flag(args, "--publication"), canonicalBaselineVetPublicationV1Bytes(publication));
  writeNew(flag(args, "--discovery"), canonicalBaselineVetDiscoveryV1Bytes(discovery));
  process.stdout.write(`${canonicalStrictJsonBytesV1(discovery).toString("utf8")}\n`);
}
function baselineInspect(args: readonly string[]): void {
  if (
    args.length !== 6 ||
    args.length % 2 !== 0 ||
    args.some(
      (arg, index) =>
        index % 2 === 0 && !new Set(["--discovery", "--publication", "--request-sha256"]).has(arg),
    )
  )
    fail("baseline-inspect usage");
  const discovery = parseBaselineVetDiscoveryV1Json(
    readText(flag(args, "--discovery"), "baseline discovery", 8 * 1024),
  );
  const publication = resolveBaselineVetDiscoveryV1({
    discovery,
    publicationBytes: readBoundedRegularFile(
      flag(args, "--publication"),
      "baseline publication",
      96 * 1024 * 1024,
    ),
    expectedRequestSha256: flag(args, "--request-sha256"),
  });
  const portable = baselineVetPublicationResultV1(publication);
  const verified = verifyBaselineVetAttestationV1({
    ...portable,
    seenEvidenceDigests: [],
    seenReceiptBindings: [],
  });
  process.stdout.write(`${canonicalStrictJsonBytesV1(verified.facts).toString("utf8")}\n`);
}
function sign(args: readonly string[]): void {
  if (
    args.length !== 10 ||
    args[0] !== "--bundle" ||
    args[2] !== "--signer" ||
    args[4] !== "--private-key" ||
    args[6] !== "--claims" ||
    args[8] !== "--output"
  )
    fail("sign usage");
  const bundleDirectory = args[1],
    signerPath = args[3],
    privateKeyPath = args[5],
    claimsPath = args[7],
    outputPath = args[9];
  if (
    [bundleDirectory, signerPath, privateKeyPath, claimsPath, outputPath].some(
      (entry) => typeof entry !== "string",
    )
  )
    fail("sign arguments");
  const bundle = readScanCaptureBundleV2({ bundleDirectory: bundleDirectory as string });
  const signerWire = readJson(signerPath as string, "signer");
  const claims = readJson(claimsPath as string, "claims");
  exactWire(signerWire, ["identity", "class", "keyId"], "signer");
  if (
    typeof signerWire.identity !== "string" ||
    typeof signerWire.class !== "string" ||
    typeof signerWire.keyId !== "string" ||
    Object.keys(signerWire).length !== 3
  )
    fail("signer fields");
  const evidence = signScanCandidateV2({
    candidate: bundle.candidate,
    signer: {
      identity: signerWire.identity,
      class: signerWire.class,
      keyId: signerWire.keyId,
      privateKey: createPrivateKey(readPrivateKey(privateKeyPath as string)),
    },
    claims,
    annexArtifacts: bundle.annexArtifacts,
  });
  writeNew(outputPath as string, canonicalScanAttestationEnvelopeBytesV2(evidence));
}
async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === "verify") {
    verify(args);
    return;
  }
  if (command === "project-core-evidence") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(projectCoreEvidenceUsage);
      return;
    }
    return projectCoreEvidence(args);
  }
  if (command === "capture") return capture(args);
  if (command === "baseline-vet") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(baselineVetUsage);
      return;
    }
    return baselineVet(args);
  }
  if (command === "baseline-sign") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(baselineSignUsage);
      return;
    }
    return baselineSign(args);
  }
  if (command === "baseline-verify") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(baselineVerifyUsage);
      return;
    }
    return baselineVerify(args);
  }
  if (command === "baseline-pack") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(baselinePackUsage);
      return;
    }
    return baselinePack(args);
  }
  if (command === "baseline-inspect") {
    if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
      process.stdout.write(baselineInspectUsage);
      return;
    }
    return baselineInspect(args);
  }
  if (command === "sign") return sign(args);
  if (command === "--help" || command === "-h") {
    process.stdout.write(
      "Usage: aih-scan baseline-vet ... | baseline-sign ... | baseline-verify ... | baseline-pack ... | baseline-inspect ... | capture ... | sign ... | verify ... | project-core-evidence ...\n",
    );
    return;
  }
  fail("unknown command");
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "invalid input"}\n`);
  process.exitCode = 2;
});
