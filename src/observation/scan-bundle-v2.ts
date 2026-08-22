import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "../contract/strict-json-v1.js";
import {
  assertCompleteScanAnnexArtifactsV2,
  canonicalScanCandidateBytesV2,
  parseScanCandidateV2Json,
  type ScanAnnexArtifactV2,
  type ScanCandidateV2,
} from "./scan-attestation-v2.js";

const fail = (reason: string): never => {
  throw new TypeError(`invalid ScanBundleV2: ${reason}`);
};
const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const sameIdentity = (left: Stats, right: Stats) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ctimeMs === right.ctimeMs;
function exact(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    fail(`${label} fields`);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (descriptor === undefined || !("value" in descriptor)) fail(`${label} accessor`);
  }
}
function boundedRegularFile(path: string, label: string, maximumBytes: number): Buffer {
  const beforePath = lstatSync(path);
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
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(beforePath, before))
      fail(`${label} replacement`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor),
      afterPath = lstatSync(path);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > maximumBytes ||
      after.nlink !== 1 ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, afterPath)
    )
      fail(`${label} replacement`);
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
function removeOwnedStage(parent: string, outputName: string, staging: string): void {
  if (dirname(staging) !== parent || !basename(staging).startsWith(`.${outputName}.stage-`))
    fail("staging cleanup target");
  rmSync(staging, { recursive: true, force: true, maxRetries: 1 });
}

export interface ScanCaptureBundleV2 {
  readonly candidate: ScanCandidateV2;
  readonly annexArtifacts: readonly ScanAnnexArtifactV2[];
}

/** Reads only a canonical, complete detached bundle; loose annex directories are not evidence bundles. */
export function readScanCaptureBundleV2(value: unknown): ScanCaptureBundleV2 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("reader input");
  const input = value as Record<string, unknown>;
  exact(input, ["bundleDirectory"], "reader input");
  const bundleDirectory = input.bundleDirectory;
  if (typeof bundleDirectory !== "string" || bundleDirectory.length === 0) fail("bundle directory");
  const root = resolve(bundleDirectory as string),
    before = lstatSync(root),
    realRoot = realpathSync.native(root);
  if (!before.isDirectory() || before.isSymbolicLink()) fail("bundle directory shape");
  const names = readdirSync(root).sort();
  if (
    names.length < 3 ||
    names.length > 5 ||
    !names.includes("candidate.json") ||
    !names.includes("bundle.json")
  )
    fail("bundle file set");
  const candidateBytes = boundedRegularFile(
    join(root, "candidate.json"),
    "candidate",
    2 * 1024 * 1024,
  );
  const candidateText = candidateBytes.toString("utf8");
  if (!Buffer.from(candidateText, "utf8").equals(candidateBytes)) fail("candidate UTF-8");
  const candidate = parseScanCandidateV2Json(candidateText);
  const manifestBytes = boundedRegularFile(
    join(root, "bundle.json"),
    "bundle manifest",
    128 * 1024,
  );
  const manifestText = manifestBytes.toString("utf8");
  if (!Buffer.from(manifestText, "utf8").equals(manifestBytes)) fail("bundle manifest UTF-8");
  const manifest = parseStrictJsonObjectV1(manifestText, "ScanBundleV2 manifest");
  exact(manifest, ["protocol", "candidate", "annexes"], "bundle manifest");
  if (manifest.protocol !== "ScanBundleV2" || !Array.isArray(manifest.annexes))
    fail("bundle manifest shape");
  const manifestAnnexes = manifest.annexes as unknown[];
  if (!canonicalStrictJsonBytesV1(manifest).equals(manifestBytes))
    fail("noncanonical bundle manifest");
  if (
    typeof manifest.candidate !== "object" ||
    manifest.candidate === null ||
    Array.isArray(manifest.candidate)
  )
    fail("bundle candidate");
  const manifestCandidate = manifest.candidate as Record<string, unknown>;
  exact(manifestCandidate, ["file", "candidateSha256", "fileSha256"], "bundle candidate");
  if (
    manifestCandidate.file !== "candidate.json" ||
    manifestCandidate.candidateSha256 !== candidate.candidateSha256 ||
    manifestCandidate.fileSha256 !== sha256(candidateBytes)
  )
    fail("bundle candidate binding");
  if (manifestAnnexes.length !== candidate.annexes.length) fail("bundle annex count");
  const artifactNames = new Set(["candidate.json", "bundle.json"]);
  const annexArtifacts: ScanAnnexArtifactV2[] = manifestAnnexes.map((entry) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) fail("bundle annex");
    const annex = entry as Record<string, unknown>;
    exact(annex, ["descriptorId", "file", "sha256", "byteLength"], "bundle annex");
    if (
      typeof annex.descriptorId !== "string" ||
      typeof annex.file !== "string" ||
      annex.file !== `${annex.descriptorId}.bin` ||
      !/^annex\.[a-z0-9][a-z0-9.-]*\.bin$/.test(annex.file) ||
      typeof annex.sha256 !== "string" ||
      typeof annex.byteLength !== "number" ||
      !Number.isSafeInteger(annex.byteLength) ||
      annex.byteLength <= 0 ||
      artifactNames.has(annex.file)
    )
      fail("bundle annex fields");
    const file = annex.file as string,
      byteLength = annex.byteLength as number,
      expectedSha256 = annex.sha256 as string;
    artifactNames.add(file);
    const bytes = boundedRegularFile(join(root, file), "bundle annex", 16 * 1024 * 1024);
    if (bytes.byteLength !== byteLength || sha256(bytes) !== expectedSha256)
      fail("bundle annex binding");
    return { descriptorId: annex.descriptorId as string, bytes };
  });
  if (artifactNames.size !== names.length || names.some((name) => !artifactNames.has(name)))
    fail("bundle extra or missing file");
  assertCompleteScanAnnexArtifactsV2(candidate.annexes, annexArtifacts);
  const after = lstatSync(root),
    afterNames = readdirSync(root).sort();
  if (
    !sameIdentity(before, after) ||
    realpathSync.native(root) !== realRoot ||
    names.join("\0") !== afterNames.join("\0")
  )
    fail("bundle directory replacement");
  return { candidate, annexArtifacts };
}

/** Writes a complete detached-evidence capture bundle by atomically renaming a private sibling stage. */
export function writeScanCaptureBundleV2(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value as Record<string, unknown>;
  const fields = ["outputDirectory", "candidate", "annexArtifacts"];
  if (
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.getOwnPropertySymbols(input).length > 0 ||
    Object.keys(input).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(input, field))
  )
    fail("input fields");
  const requestedOutputDirectory = input.outputDirectory;
  if (typeof requestedOutputDirectory !== "string" || requestedOutputDirectory.length === 0)
    fail("output directory");
  const candidate = input.candidate as ScanCandidateV2;
  const candidateBytes = canonicalScanCandidateBytesV2(candidate);
  const annexArtifacts = input.annexArtifacts as readonly ScanAnnexArtifactV2[];
  assertCompleteScanAnnexArtifactsV2(candidate.annexes, annexArtifacts);
  const outputDirectory = resolve(requestedOutputDirectory as string);
  if (existsSync(outputDirectory)) fail("output already exists");
  const parent = dirname(outputDirectory),
    outputName = basename(outputDirectory);
  if (!outputName || outputName === "." || outputName === "..") fail("output directory name");
  const staging = mkdtempSync(join(parent, `.${outputName}.stage-`));
  try {
    writeFileSync(join(staging, "candidate.json"), candidateBytes, { flag: "wx", mode: 0o600 });
    const annexes = candidate.annexes.map((descriptor) => {
      const artifact = annexArtifacts.find(
        (entry) => entry.descriptorId === descriptor.descriptorId,
      );
      if (artifact === undefined) fail("annex artifact binding");
      const bytes = (artifact as ScanAnnexArtifactV2).bytes;
      const file = `${descriptor.descriptorId}.bin`;
      writeFileSync(join(staging, file), bytes, { flag: "wx", mode: 0o600 });
      return {
        descriptorId: descriptor.descriptorId,
        file,
        sha256: descriptor.sha256,
        byteLength: descriptor.byteLength,
      };
    });
    const manifest = canonicalStrictJsonBytesV1({
      protocol: "ScanBundleV2",
      candidate: {
        file: "candidate.json",
        candidateSha256: candidate.candidateSha256,
        fileSha256: sha256(candidateBytes),
      },
      annexes,
    });
    writeFileSync(join(staging, "bundle.json"), manifest, { flag: "wx", mode: 0o600 });
    if (existsSync(outputDirectory)) fail("output already exists");
    renameSync(staging, outputDirectory);
  } catch (error) {
    removeOwnedStage(parent, outputName, staging);
    throw error;
  }
}
