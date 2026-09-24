import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readlinkSync,
  readSync,
  realpathSync,
  rmSync,
  type Stats,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { z } from "zod";
import { resolveDetectorCapabilityV1 } from "../capability/detector-capability-v1.js";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  attachScanCompletionV1,
  SCAN_COMPLETION_PROPERTY_V1,
  scanCompletionEvidenceV1,
  scanCompletionSubjectFilesV1,
} from "../detectors/completion-evidence-v1.js";
import { assertSarifCompletedV1 } from "../detectors/sarif-completion-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../observation/source-hash-v1.js";
import {
  type SourceObservationSealV1,
  sealSourceObservationV1,
} from "../observation/source-observation-seal-v1.js";
import { createBaselineAnalyzerExecutionV1 } from "./runtime-v1.js";

export const BASELINE_ANALYZERS_V1 = ["aih-native", "skillspector", "semgrep", "cisco"] as const;
export type BaselineAnalyzerV1 = (typeof BASELINE_ANALYZERS_V1)[number];

const maxComponents = 100;
const maxAnnexBytes = 16 * 1024 * 1024;
const maxSourceEntries = 100_000;
const maxSourceBytes = 256 * 1024 * 1024;
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const gitCommit = z.string().regex(/^[0-9a-f]{40}$/);
const safeId = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9][a-z0-9:._-]*$/);
const repositoryPart = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.-]+$/);
const analyzer = z.enum(BASELINE_ANALYZERS_V1);
const requestSource = z
  .object({
    id: safeId,
    owner: repositoryPart,
    repository: repositoryPart,
    pinnedCommit: gitCommit,
    treeSha256: sha256,
  })
  .strict();
const requestComponent = z
  .object({
    id: safeId,
    content: z.enum(["general", "skill"]),
    paths: z.array(z.string()).min(1).max(4_096),
    treeSha256: sha256,
    analyzers: z.array(analyzer).min(1).max(BASELINE_ANALYZERS_V1.length),
  })
  .strict();
const requestInput = z
  .object({
    protocol: z.literal("BaselineVetRequestV1"),
    profile: z.literal("aih-baseline-v1"),
    source: requestSource,
    components: z.array(requestComponent).min(1).max(maxComponents),
  })
  .strict();
const requestWire = requestInput.extend({ requestSha256: sha256 }).strict();

export type BaselineVetRequestV1 = Readonly<z.infer<typeof requestWire>>;

const annexDescriptor = z
  .object({
    path: z.string(),
    mediaType: z.enum(["application/sarif+json", "application/vnd.aih.baseline-native+json"]),
    sha256,
    byteLength: z.number().int().positive().max(maxAnnexBytes),
  })
  .strict();
const observation = z
  .object({
    analyzer,
    analyzerVersion: z.string().min(1).max(200),
    annex: annexDescriptor,
  })
  .strict();
const componentObservation = z.object({ analyzer, annexSha256: sha256 }).strict();
const receiptComponent = z
  .object({
    id: safeId,
    content: z.enum(["general", "skill"]),
    paths: z.array(z.string()).min(1).max(4_096),
    treeSha256: sha256,
    observations: z.array(componentObservation).min(1).max(BASELINE_ANALYZERS_V1.length),
  })
  .strict();
const receiptInput = z
  .object({
    protocol: z.literal("BaselineVetReceiptV1"),
    profile: z.literal("aih-baseline-v1"),
    requestSha256: sha256,
    source: requestSource,
    observations: z.array(observation).min(1).max(BASELINE_ANALYZERS_V1.length),
    components: z.array(receiptComponent).min(1).max(maxComponents),
  })
  .strict();
const receiptWire = receiptInput.extend({ receiptSha256: sha256 }).strict();
const replayEntry = z.object({ requestSha256: sha256, receiptSha256: sha256 }).strict();

export type BaselineVetReceiptV1 = Readonly<z.infer<typeof receiptWire>>;
export type BaselineVetAnnexArtifactV1 = Readonly<{ path: string; bytes: Buffer }>;
export type BaselineVetBatchResultV1 = Readonly<{
  receipt: BaselineVetReceiptV1;
  annexArtifacts: readonly BaselineVetAnnexArtifactV1[];
}>;
export type BaselineAnalyzerExecutionV1 = (input: {
  readonly analyzer: BaselineAnalyzerV1;
  readonly sourceRoot: string;
  readonly source: BaselineVetRequestV1["source"];
}) => Promise<{
  readonly mediaType: "application/sarif+json" | "application/vnd.aih.baseline-native+json";
  readonly bytes: Uint8Array;
  readonly analyzerVersion: string;
  /**
   * The execution profile the analyzer actually ran under, one of its detector's
   * observation profiles. Its published `analyzerLock` is the lock the SARIF annex's
   * completion evidence names (D24).
   */
  readonly executionProfileId: string;
}>;

export type BaselineVetVerificationV1 =
  | Readonly<{ kind: "complete" }>
  | Readonly<{
      kind: "required";
      reason:
        | "request-mismatch"
        | "receipt-mismatch"
        | "missing-annex"
        | "duplicate-annex"
        | "annex-mismatch"
        | "replay-conflict";
    }>;

const requestBytes = new WeakMap<object, Buffer>();
const receiptBytes = new WeakMap<object, Buffer>();

function fail(reason: string): never {
  throw new TypeError(`invalid BaselineVetRequestV1 or BaselineVetReceiptV1: ${reason}`);
}

function assertUnique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) fail(`duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

function analyzerOrder(values: readonly BaselineAnalyzerV1[]): BaselineAnalyzerV1[] {
  const selected = new Set(values);
  return BASELINE_ANALYZERS_V1.filter((value) => selected.has(value));
}

function normalizedPaths(values: readonly string[]): string[] {
  const paths = values.map((value) =>
    assertSafeRelativePosixPathV1(value, "baseline component path"),
  );
  assertUnique(paths, "component path");
  return paths.sort(codeUnitCompare);
}

function normalizedComponents(
  values: readonly z.infer<typeof requestComponent>[],
): z.infer<typeof requestComponent>[] {
  assertUnique(
    values.map((value) => value.id),
    "component ID",
  );
  return values.map((value) => {
    const analyzers = analyzerOrder(value.analyzers);
    assertUnique(value.analyzers, `analyzer for ${value.id}`);
    const expected =
      value.content === "skill" ? BASELINE_ANALYZERS_V1 : BASELINE_ANALYZERS_V1.slice(0, 3);
    if (
      analyzers.length !== expected.length ||
      analyzers.some((analyzerName, index) => analyzerName !== expected[index])
    )
      fail(`component ${value.id} analyzer floor for ${value.content} content`);
    return { ...value, paths: normalizedPaths(value.paths), analyzers };
  });
}

function requestAuthoring(value: BaselineVetRequestV1): z.input<typeof requestInput> {
  const { requestSha256: _digest, ...authoring } = value;
  return authoring;
}

export function createBaselineVetRequestV1(value: unknown): BaselineVetRequestV1 {
  assertStrictJsonValueV1(value, "BaselineVetRequestV1");
  const parsed = requestInput.parse(structuredClone(value));
  const authoring = {
    ...parsed,
    components: normalizedComponents(parsed.components),
  };
  const result = deepFreezeStrictJsonV1({
    ...authoring,
    requestSha256: canonicalStrictJsonSha256V1({
      domain: "aih.baseline-vet-request-v1",
      request: authoring,
    }),
  });
  requestBytes.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}

export function parseBaselineVetRequestV1Json(text: string): BaselineVetRequestV1 {
  try {
    const parsed = requestWire.parse(parseStrictJsonObjectV1(text, "BaselineVetRequestV1"));
    const result = createBaselineVetRequestV1(requestAuthoring(parsed));
    if (result.requestSha256 !== parsed.requestSha256) fail("request digest");
    if (!Buffer.from(text, "utf8").equals(canonicalBaselineVetRequestV1Bytes(result)))
      fail("request canonical wire");
    return result;
  } catch (error) {
    throw new TypeError(
      `invalid BaselineVetRequestV1: ${error instanceof Error ? error.message : "shape"}`,
    );
  }
}

export function canonicalBaselineVetRequestV1Bytes(value: BaselineVetRequestV1): Buffer {
  const bytes = typeof value === "object" && value !== null ? requestBytes.get(value) : undefined;
  if (bytes === undefined) fail("request canonical bytes require validated value");
  return Buffer.from(bytes);
}

function receiptAuthoring(value: BaselineVetReceiptV1): z.input<typeof receiptInput> {
  const { receiptSha256: _digest, ...authoring } = value;
  return authoring;
}

function validateReceipt(value: unknown): BaselineVetReceiptV1 {
  assertStrictJsonValueV1(value, "BaselineVetReceiptV1");
  const parsed = receiptWire.parse(structuredClone(value));
  assertUnique(
    parsed.observations.map((item) => item.analyzer),
    "receipt analyzer",
  );
  if (
    parsed.observations.some(
      (item, index) =>
        item.analyzer !== analyzerOrder(parsed.observations.map((x) => x.analyzer))[index],
    )
  )
    fail("receipt analyzer order");
  for (const item of parsed.observations) {
    assertSafeRelativePosixPathV1(item.annex.path, "baseline annex path");
    if (!item.annex.path.startsWith("annex/")) fail("baseline annex namespace");
  }
  assertUnique(
    parsed.observations.map((item) => item.annex.path),
    "annex path",
  );
  assertUnique(
    parsed.components.map((item) => item.id),
    "receipt component ID",
  );
  for (const component of parsed.components) {
    const paths = normalizedPaths(component.paths);
    if (paths.some((path, index) => path !== component.paths[index])) fail("receipt path order");
    assertUnique(
      component.observations.map((item) => item.analyzer),
      `receipt component analyzer ${component.id}`,
    );
    if (
      component.observations.some(
        (item, index) =>
          item.analyzer !== analyzerOrder(component.observations.map((x) => x.analyzer))[index],
      )
    )
      fail("receipt component analyzer order");
    const topLevel = new Map(parsed.observations.map((item) => [item.analyzer, item]));
    for (const item of component.observations) {
      if (topLevel.get(item.analyzer)?.annex.sha256 !== item.annexSha256)
        fail(`receipt component annex binding: ${component.id}/${item.analyzer}`);
    }
  }
  const expected = canonicalStrictJsonSha256V1({
    domain: "aih.baseline-vet-receipt-v1",
    receipt: receiptAuthoring(parsed),
  });
  if (parsed.receiptSha256 !== expected) fail("receipt digest");
  const result = deepFreezeStrictJsonV1(parsed);
  receiptBytes.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}

export function canonicalBaselineVetReceiptV1Bytes(value: BaselineVetReceiptV1): Buffer {
  const bytes = typeof value === "object" && value !== null ? receiptBytes.get(value) : undefined;
  if (bytes === undefined) fail("receipt canonical bytes require validated value");
  return Buffer.from(bytes);
}

export function parseBaselineVetReceiptV1Json(text: string): BaselineVetReceiptV1 {
  try {
    const parsed = receiptWire.parse(parseStrictJsonObjectV1(text, "BaselineVetReceiptV1"));
    const result = validateReceipt(parsed);
    if (!Buffer.from(text, "utf8").equals(canonicalBaselineVetReceiptV1Bytes(result)))
      fail("receipt canonical wire");
    return result;
  } catch (error) {
    throw new TypeError(
      `invalid BaselineVetReceiptV1: ${error instanceof Error ? error.message : "shape"}`,
    );
  }
}

/**
 * Contract-checks one analyzer result and returns its canonical annex bytes.
 *
 * Exported for Scan's own single-detector runner so both paths apply the same
 * media-type, protocol and byte bounds; it is not part of the package API.
 */
export function normalizedObservation(
  analyzerName: BaselineAnalyzerV1,
  value: Pick<
    Awaited<ReturnType<BaselineAnalyzerExecutionV1>>,
    "mediaType" | "bytes" | "analyzerVersion"
  >,
): { bytes: Buffer; mediaType: typeof value.mediaType; analyzerVersion: string } {
  const bytes = Buffer.from(value.bytes);
  if (bytes.byteLength === 0 || bytes.byteLength > maxAnnexBytes) fail("observation byte bounds");
  if (!value.analyzerVersion.trim() || value.analyzerVersion.length > 200)
    fail("observation analyzer version");
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail("observation UTF-8");
  let parsed: Record<string, unknown>;
  try {
    parsed = parseStrictJsonObjectV1(text, `${analyzerName} observation`);
  } catch (error) {
    throw new TypeError(
      `baseline ${analyzerName} observation is invalid: ${error instanceof Error ? error.message : "JSON"}`,
    );
  }
  if (analyzerName === "aih-native") {
    if (
      value.mediaType !== "application/vnd.aih.baseline-native+json" ||
      parsed.protocol !== "BaselineNativeObservationV1"
    )
      fail("native observation contract");
  } else if (
    value.mediaType !== "application/sarif+json" ||
    parsed.version !== "2.1.0" ||
    !Array.isArray(parsed.runs)
  ) {
    fail(`${analyzerName} SARIF observation contract`);
  }
  return {
    bytes: canonicalStrictJsonBytesV1(parsed),
    mediaType: value.mediaType,
    analyzerVersion: value.analyzerVersion,
  };
}

function sourceAndComponentsMatch(request: BaselineVetRequestV1, sourceRoot: string): void {
  const source = hashSourceTreeV1(sourceRoot);
  if (source.treeSha256 !== request.source.treeSha256) fail("baseline source digest mismatch");
  for (const component of request.components) {
    const current = hashComponentTreeV1(sourceRoot, component.paths);
    if (current.treeSha256 !== component.treeSha256)
      fail(`baseline component digest mismatch: ${component.id}`);
  }
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

function readBoundedSourceFile(path: string, beforePath: Stats): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(beforePath, before))
      fail("baseline source file replacement");
    const bytes = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = readSync(descriptor, bytes, offset, bytes.byteLength - offset, offset);
      if (count <= 0) fail("baseline source short read");
      offset += count;
    }
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    if (after.nlink !== 1 || !sameIdentity(before, after) || !sameIdentity(before, afterPath))
      fail("baseline source file replacement");
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

type SafeAnalyzerSourceSymlink =
  | Readonly<{ rule: "relative"; target: string; targetType: "directory" | "file" }>
  | Readonly<{ rule: "observation"; targetType: "directory" }>
  | Readonly<{ rule: "observation"; targetType: "file"; real: string; identity: Stats }>;

/**
 * What an analyzer snapshot copies. By default a top-level `.git` is left out, as the
 * batch receipts have always done; a single-detector run for an analyzer that scans the
 * whole tree (Semgrep, SkillSpector) copies it too.
 */
export type BaselineAnalyzerSnapshotOptionsV1 = Readonly<{
  includeGitDirectory?: boolean;
  /**
   * The largest single file the snapshot copies, at most the 256 MiB tree budget; 16 MiB
   * (the batch receipts' bound) when absent.
   */
  maxFileBytes?: number;
  /**
   * Which symbolic links the snapshot accepts. `"relative"` (the default, the batch
   * receipts' rule) accepts a relative target that resolves through real directories inside
   * the root and recreates the link. `"observation"` accepts exactly what
   * `SourceObservationSealV1` accepts, any link whose real target is inside the root
   * (absolute targets and chains included): a file link becomes a regular file holding the
   * target's bytes at the link path, and a directory link, which the seal records but does
   * not traverse, is not copied. An observation snapshot then holds no link at all.
   */
  links?: "relative" | "observation";
}>;

/** The link rule for a tree: a snapshot taken under "observation" may hold no link. */
type LinkRule = "relative" | "observation" | "none";

function snapshotLinkRule(options: BaselineAnalyzerSnapshotOptionsV1): LinkRule {
  if (options.links === undefined || options.links === "relative") return "relative";
  if (options.links === "observation") return "observation";
  return fail("baseline source link rule");
}

/** The seal's containment: the real target, relative to the real root, never escaping it. */
function containedRealTarget(realRoot: string, real: string): void {
  const child = relative(realRoot, real);
  if (child === "") return;
  if (
    child === ".." ||
    child.startsWith(`..${sep}`) ||
    isAbsolute(child) ||
    /^[A-Za-z]:/.test(child)
  )
    fail("baseline source symbolic link target");
}

function snapshotFileBound(options: BaselineAnalyzerSnapshotOptionsV1): number {
  const bound = options.maxFileBytes ?? maxAnnexBytes;
  if (!Number.isSafeInteger(bound) || bound < 0 || bound > maxSourceBytes)
    fail("baseline source file bound");
  return bound;
}

function topLevelNames(root: string, options: BaselineAnalyzerSnapshotOptionsV1): string[] {
  return readdirSync(root)
    .filter((value) => options.includeGitDirectory === true || value !== ".git")
    .sort(codeUnitCompare);
}

function inspectSafeAnalyzerSource(
  sourceRoot: string,
  options: BaselineAnalyzerSnapshotOptionsV1 = {},
  rule: LinkRule = snapshotLinkRule(options),
): ReadonlyMap<string, SafeAnalyzerSourceSymlink> {
  const root = resolve(sourceRoot);
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("baseline source directory shape");
  const realRoot = realpathSync.native(root);
  const budget = { entries: 0, bytes: 0 };
  const entries = new Map<string, "directory" | "file">();
  const symlinks = new Map<string, string>();
  const observed = new Map<string, SafeAnalyzerSourceSymlink>();
  const visit = (path: string): void => {
    const stat = lstatSync(path);
    budget.entries += 1;
    if (budget.entries > maxSourceEntries) fail("baseline source entry bound");
    if (stat.isSymbolicLink()) {
      if (rule === "none") fail("baseline analyzer snapshot holds a symbolic link");
      const target = readlinkSync(path);
      if (rule === "observation") {
        let real: string;
        try {
          real = realpathSync.native(path);
        } catch {
          fail("baseline source symbolic link target");
        }
        containedRealTarget(realRoot, real);
        const targetStat = statSync(real);
        if (targetStat.isDirectory()) observed.set(path, { rule, targetType: "directory" });
        else if (targetStat.isFile()) {
          if (targetStat.nlink !== 1) fail("baseline source file shape");
          if (
            targetStat.size > snapshotFileBound(options) ||
            targetStat.size > maxSourceBytes - budget.bytes
          )
            fail("baseline source byte bound");
          budget.bytes += targetStat.size;
          observed.set(path, { rule, targetType: "file", real, identity: targetStat });
        } else fail("baseline source symbolic link target");
      } else symlinks.set(path, target);
      const after = lstatSync(path);
      if (!sameIdentity(stat, after) || target !== readlinkSync(path))
        fail("baseline source symbolic link replacement");
      return;
    }
    if (stat.isDirectory()) {
      entries.set(path, "directory");
      for (const name of readdirSync(path).sort(codeUnitCompare)) visit(join(path, name));
      const after = lstatSync(path);
      if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(stat, after))
        fail("baseline source directory replacement");
      return;
    }
    if (!stat.isFile() || stat.nlink !== 1) fail("baseline source file shape");
    if (stat.size > snapshotFileBound(options) || stat.size > maxSourceBytes - budget.bytes)
      fail("baseline source byte bound");
    budget.bytes += stat.size;
    entries.set(path, "file");
  };
  for (const name of topLevelNames(root, options)) visit(join(root, name));
  const rootAfter = lstatSync(root);
  if (!rootAfter.isDirectory() || rootAfter.isSymbolicLink() || !sameIdentity(rootStat, rootAfter))
    fail("baseline source directory replacement");
  // An observation snapshot may be empty: the seal accepts a tree of directory links only.
  if (budget.entries === 0 && rule !== "none") fail("baseline source has no content");
  if (rule !== "relative") return observed;

  const safeSymlinks = new Map<string, SafeAnalyzerSourceSymlink>();
  const directoriesContainingSymlinks = new Set<string>();
  for (const path of symlinks.keys()) {
    let parent = dirname(path);
    while (true) {
      if (directoriesContainingSymlinks.has(parent)) break;
      directoriesContainingSymlinks.add(parent);
      if (parent === root) break;
      const next = dirname(parent);
      if (next === parent) fail("baseline source symbolic link target");
      parent = next;
    }
  }
  const containedEntryType = (path: string): "directory" | "file" | undefined => {
    const pathRelative = relative(root, path).replaceAll("\\", "/");
    if (pathRelative === ".." || pathRelative.startsWith("../") || isAbsolute(pathRelative))
      fail("baseline source symbolic link target");
    return pathRelative === "" ? "directory" : entries.get(path);
  };
  for (const [path, stored] of symlinks) {
    // Windows stores a relative link target with its own separator; the check below is on
    // the portable form, and the link is still copied with the target as stored.
    const target = process.platform === "win32" ? stored.replaceAll("\\", "/") : stored;
    if (
      !target ||
      target.includes("\\") ||
      isAbsolute(target) ||
      win32.isAbsolute(target) ||
      /(^|\/)[A-Za-z]:/.test(target)
    )
      fail("baseline source symbolic link target");
    let targetPath = dirname(path);
    for (const segment of target.split("/")) {
      if (containedEntryType(targetPath) !== "directory")
        fail("baseline source symbolic link target");
      if (segment === "" || segment === ".") continue;
      targetPath = resolve(targetPath, segment);
      containedEntryType(targetPath);
    }
    const targetType = containedEntryType(targetPath);
    if (targetType === undefined) fail("baseline source symbolic link target");
    if (targetType === "directory" && directoriesContainingSymlinks.has(targetPath))
      fail("baseline source symbolic link cycle");
    safeSymlinks.set(path, { rule: "relative", target: stored, targetType });
  }
  return safeSymlinks;
}

function copyAnalyzerSource(
  source: string,
  snapshot: string,
  options: BaselineAnalyzerSnapshotOptionsV1 = {},
): void {
  const rootBefore = lstatSync(source);
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink())
    fail("baseline source directory shape");
  const safeSymlinks = inspectSafeAnalyzerSource(source, options);
  const rootAfterInspection = lstatSync(source);
  if (
    !rootAfterInspection.isDirectory() ||
    rootAfterInspection.isSymbolicLink() ||
    !sameIdentity(rootBefore, rootAfterInspection)
  )
    fail("baseline source directory replacement");
  const budget = { entries: 0, bytes: 0 };
  const copy = (from: string, to: string): void => {
    const before = lstatSync(from);
    budget.entries += 1;
    if (budget.entries > maxSourceEntries) fail("baseline source entry bound");
    if (before.isSymbolicLink()) {
      const expected = safeSymlinks.get(from);
      const target = readlinkSync(from);
      const after = lstatSync(from);
      if (
        expected === undefined ||
        (expected.rule === "relative" && target !== expected.target) ||
        target !== readlinkSync(from) ||
        !sameIdentity(before, after)
      )
        fail("baseline source symbolic link replacement");
      if (expected.rule === "relative") {
        symlinkSync(target, to, expected.targetType === "directory" ? "dir" : "file");
        return;
      }
      // Recorded by the seal and not traversed, so the analyzer is not shown it.
      if (expected.targetType === "directory") return;
      if (realpathSync.native(from) !== expected.real)
        fail("baseline source symbolic link replacement");
      const targetStat = lstatSync(expected.real);
      if (!targetStat.isFile() || !sameIdentity(expected.identity, targetStat))
        fail("baseline source file replacement");
      if (targetStat.size > maxSourceBytes - budget.bytes) fail("baseline source byte bound");
      const bytes = readBoundedSourceFile(expected.real, targetStat);
      budget.bytes += bytes.byteLength;
      writeFileSync(to, bytes, { flag: "wx", mode: 0o600 });
      return;
    }
    if (before.isDirectory()) {
      mkdirSync(to, { recursive: false, mode: 0o700 });
      for (const name of readdirSync(from).sort(codeUnitCompare))
        copy(join(from, name), join(to, name));
      const after = lstatSync(from);
      if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after))
        fail("baseline source directory replacement");
      return;
    }
    if (!before.isFile() || before.nlink !== 1) fail("baseline source file shape");
    if (before.size > snapshotFileBound(options) || before.size > maxSourceBytes - budget.bytes)
      fail("baseline source byte bound");
    const bytes = readBoundedSourceFile(from, before);
    budget.bytes += bytes.byteLength;
    writeFileSync(to, bytes, { flag: "wx", mode: 0o600 });
  };
  for (const name of topLevelNames(source, options)) copy(join(source, name), join(snapshot, name));
  const rootAfter = lstatSync(source);
  if (
    !rootAfter.isDirectory() ||
    rootAfter.isSymbolicLink() ||
    !sameIdentity(rootBefore, rootAfter)
  )
    fail("baseline source directory replacement");
  if (budget.entries === 0) fail("baseline source has no content");
}

/** A snapshot taken under the observation rule holds no link; one taken as relative, safe ones. */
function assertSafeAnalyzerSnapshot(
  snapshotRoot: string,
  options: BaselineAnalyzerSnapshotOptionsV1 = {},
): void {
  inspectSafeAnalyzerSource(
    snapshotRoot,
    options,
    snapshotLinkRule(options) === "observation" ? "none" : "relative",
  );
}

/**
 * Copies the source root into a private analyzer snapshot and proves the copy is safe.
 *
 * Exported for Scan's own single-detector runner so the snapshot, symbolic-link and
 * byte-bound rules are one implementation; it is not part of the package API.
 */
export function createBaselineAnalyzerSnapshotV1(
  sourceRoot: string,
  options: BaselineAnalyzerSnapshotOptionsV1 = {},
): string {
  const source = resolve(sourceRoot);
  const snapshot = mkdtempSync(join(tmpdir(), "aih-scan-baseline-source-"));
  try {
    chmodSync(snapshot, 0o700);
  } catch {
    // Windows ACLs are platform-managed; mkdtemp remains the private creation boundary.
  }
  try {
    copyAnalyzerSource(source, snapshot, options);
    assertSafeAnalyzerSnapshot(snapshot, options);
    return snapshot;
  } catch (error) {
    rmSync(snapshot, { recursive: true, force: true });
    throw error;
  }
}

/** Re-proves that a snapshot still matches the source shape it was taken from. */
export function assertBaselineAnalyzerSnapshotUnchangedV1(
  snapshotRoot: string,
  options: BaselineAnalyzerSnapshotOptionsV1 = {},
): void {
  assertSafeAnalyzerSnapshot(snapshotRoot, options);
}

function createAnalyzerSnapshot(request: BaselineVetRequestV1, sourceRoot: string): string {
  const snapshot = createBaselineAnalyzerSnapshotV1(sourceRoot);
  try {
    sourceAndComponentsMatch(request, snapshot);
    return snapshot;
  } catch (error) {
    rmSync(snapshot, { recursive: true, force: true });
    throw error;
  }
}

/** The detector a baseline analyzer is, for its capability and its completion evidence. */
const BASELINE_DETECTOR_IDS_V1: Readonly<Record<BaselineAnalyzerV1, string>> = Object.freeze({
  "aih-native": "detector.aih-native",
  skillspector: "detector.skillspector",
  semgrep: "detector.semgrep",
  cisco: "detector.cisco",
});

/** The declared profile, which must be one of the detector's observation profiles. */
function executedProfile(analyzerName: BaselineAnalyzerV1, executionProfileId: unknown) {
  const capability = resolveDetectorCapabilityV1(BASELINE_DETECTOR_IDS_V1[analyzerName]);
  const profile = capability?.executionProfiles.find(
    (item) => item.id === executionProfileId && item.evidence === "BaselineAnalyzerObservationV1",
  );
  if (capability === undefined || profile === undefined)
    fail(
      `${analyzerName} execution profile ${JSON.stringify(executionProfileId)} is not one it runs under`,
    );
  return { capability, profile };
}

/** The analyzer snapshot's seal: what every analyzer received, top-level `.git` never among it. */
function sealAnalyzerSnapshot(snapshotRoot: string): SourceObservationSealV1 {
  return sealSourceObservationV1({ sourceRoot: snapshotRoot, selectedClosurePaths: [] });
}

export async function executeBaselineVetBatchV1(
  request: BaselineVetRequestV1,
  runtime: {
    readonly sourceRoot: string;
    /** Optional: Scan's own hardened analyzer execution is the default. */
    readonly execute?: BaselineAnalyzerExecutionV1;
  },
): Promise<BaselineVetBatchResultV1> {
  canonicalBaselineVetRequestV1Bytes(request);
  const execute = runtime.execute ?? createBaselineAnalyzerExecutionV1();
  const snapshotRoot = createAnalyzerSnapshot(request, runtime.sourceRoot);
  const selected = analyzerOrder(request.components.flatMap((component) => component.analyzers));
  const observations: z.infer<typeof observation>[] = [];
  const annexArtifacts: BaselineVetAnnexArtifactV1[] = [];
  try {
    const sealed = sealAnalyzerSnapshot(snapshotRoot);
    const ran: {
      analyzer: BaselineAnalyzerV1;
      observed: ReturnType<typeof normalizedObservation>;
      executed: ReturnType<typeof executedProfile>;
    }[] = [];
    for (const analyzerName of selected) {
      const result = await execute({
        analyzer: analyzerName,
        sourceRoot: snapshotRoot,
        source: request.source,
      });
      const executed = executedProfile(analyzerName, result.executionProfileId);
      const observed = normalizedObservation(analyzerName, result);
      // S2e: the analyzer's own completion proof, before anything is published from it.
      if (observed.mediaType === "application/sarif+json")
        assertSarifCompletedV1(parseStrictJsonObjectV1(observed.bytes.toString("utf8"), "SARIF"));
      ran.push({ analyzer: analyzerName, observed, executed });
    }
    assertSafeAnalyzerSnapshot(snapshotRoot);
    if (
      !canonicalStrictJsonBytesV1(sealAnalyzerSnapshot(snapshotRoot)).equals(
        canonicalStrictJsonBytesV1(sealed),
      )
    )
      fail("baseline analyzer snapshot changed during the run");
    sourceAndComponentsMatch(request, snapshotRoot);
    const reobservedRoot = createAnalyzerSnapshot(request, runtime.sourceRoot);
    rmSync(reobservedRoot, { recursive: true, force: true });
    // C2a §1.6 (D24): only now, every proof passed, does each SARIF run name the files of the
    // snapshot the analyzer received, under the lock of the profile that ran.
    for (const { analyzer: analyzerName, observed, executed } of ran) {
      let bytes = observed.bytes;
      if (observed.mediaType === "application/sarif+json") {
        const evidence = scanCompletionEvidenceV1({
          detectorId: executed.capability.detectorId,
          files: scanCompletionSubjectFilesV1({
            engine: analyzerName as "semgrep" | "skillspector" | "cisco",
            entries: sealed.entries,
            selectedClosurePaths: sealed.selectedClosurePaths,
          }),
          emptyAllowed: executed.capability.emptySource === "completes",
          analyzer: {
            version: observed.analyzerVersion,
            lockSha256: executed.profile.analyzerLock?.sha256 ?? null,
          },
        });
        bytes = canonicalStrictJsonBytesV1(
          attachScanCompletionV1(
            parseStrictJsonObjectV1(bytes.toString("utf8"), `${analyzerName} SARIF`),
            evidence,
            { scanBuilt: false },
          ),
        );
        normalizedObservation(analyzerName, { ...observed, bytes });
      }
      const path = `annex/${analyzerName}.json`;
      observations.push({
        analyzer: analyzerName,
        analyzerVersion: observed.analyzerVersion,
        annex: {
          path,
          mediaType: observed.mediaType,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          byteLength: bytes.byteLength,
        },
      });
      annexArtifacts.push({ path, bytes });
    }
  } finally {
    rmSync(snapshotRoot, { recursive: true, force: true });
  }
  const observationByAnalyzer = new Map(observations.map((item) => [item.analyzer, item]));
  const authoring: z.input<typeof receiptInput> = {
    protocol: "BaselineVetReceiptV1",
    profile: request.profile,
    requestSha256: request.requestSha256,
    source: request.source,
    observations,
    components: request.components.map((component) => ({
      id: component.id,
      content: component.content,
      paths: component.paths,
      treeSha256: component.treeSha256,
      observations: component.analyzers.map((name) => ({
        analyzer: name,
        annexSha256:
          observationByAnalyzer.get(name)?.annex.sha256 ?? fail(`missing observation: ${name}`),
      })),
    })),
  };
  const receipt = validateReceipt({
    ...authoring,
    receiptSha256: canonicalStrictJsonSha256V1({
      domain: "aih.baseline-vet-receipt-v1",
      receipt: authoring,
    }),
  });
  return Object.freeze({ receipt, annexArtifacts: Object.freeze(annexArtifacts) });
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

/**
 * D24: whether a published SARIF annex still proves what the batch wrote into it. Every run
 * passes the S2e completion rule and carries, only in its first invocation, one equal
 * completion-evidence-v1 object for this analyzer's detector, the receipt's analyzer
 * version and a lock one of the detector's observation profiles installs (null only where
 * one installs none). The subject itself is recomputed by whoever holds the source.
 */
function carriesBaselineCompletion(
  analyzerName: BaselineAnalyzerV1,
  analyzerVersion: string,
  bytes: Buffer,
): boolean {
  const capability = resolveDetectorCapabilityV1(BASELINE_DETECTOR_IDS_V1[analyzerName]);
  if (capability === undefined) return false;
  const locks = new Set(
    capability.executionProfiles
      .filter((profile) => profile.evidence === "BaselineAnalyzerObservationV1")
      .map((profile) => profile.analyzerLock?.sha256 ?? null),
  );
  let log: Record<string, unknown>;
  try {
    log = parseStrictJsonObjectV1(bytes.toString("utf8"), "SARIF");
    assertSarifCompletedV1(log);
  } catch {
    return false;
  }
  let first: Buffer | undefined;
  for (const run of log.runs as unknown[]) {
    const invocations = isRecord(run) ? run.invocations : undefined;
    if (!Array.isArray(invocations)) return false;
    const [head, ...rest] = invocations as unknown[];
    const properties = isRecord(head) ? head.properties : undefined;
    const evidence = isRecord(properties) ? properties[SCAN_COMPLETION_PROPERTY_V1] : undefined;
    if (
      rest.some(
        (invocation) =>
          isRecord(invocation) &&
          isRecord(invocation.properties) &&
          Object.hasOwn(invocation.properties, SCAN_COMPLETION_PROPERTY_V1),
      ) ||
      !isRecord(evidence) ||
      !hasExactKeys(evidence, ["detectorId", "subjectTreeSha256", "analyzedFileCount", "analyzer"])
    )
      return false;
    const analyzer = evidence.analyzer;
    const count = evidence.analyzedFileCount;
    if (
      evidence.detectorId !== capability.detectorId ||
      typeof evidence.subjectTreeSha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(evidence.subjectTreeSha256) ||
      typeof count !== "number" ||
      !Number.isSafeInteger(count) ||
      count < 0 ||
      (count === 0 && capability.emptySource !== "completes") ||
      !isRecord(analyzer) ||
      !hasExactKeys(analyzer, ["version", "lockSha256"]) ||
      analyzer.version !== analyzerVersion ||
      !(analyzer.lockSha256 === null || typeof analyzer.lockSha256 === "string") ||
      !locks.has(analyzer.lockSha256)
    )
      return false;
    const canonical = canonicalStrictJsonBytesV1(evidence);
    if (first === undefined) first = canonical;
    else if (!first.equals(canonical)) return false;
  }
  return true;
}

function sameRequest(receipt: BaselineVetReceiptV1, request: BaselineVetRequestV1): boolean {
  const expectedAnalyzers = analyzerOrder(
    request.components.flatMap((component) => component.analyzers),
  );
  return (
    receipt.requestSha256 === request.requestSha256 &&
    receipt.profile === request.profile &&
    canonicalStrictJsonBytesV1(receipt.source).equals(canonicalStrictJsonBytesV1(request.source)) &&
    receipt.observations.length === expectedAnalyzers.length &&
    receipt.observations.every(
      (observation, index) => observation.analyzer === expectedAnalyzers[index],
    ) &&
    receipt.components.length === request.components.length &&
    receipt.components.every((component, index) => {
      const expected = request.components[index];
      return (
        expected !== undefined &&
        component.id === expected.id &&
        component.content === expected.content &&
        component.treeSha256 === expected.treeSha256 &&
        canonicalStrictJsonBytesV1(component.paths).equals(
          canonicalStrictJsonBytesV1(expected.paths),
        ) &&
        canonicalStrictJsonBytesV1(component.observations.map((item) => item.analyzer)).equals(
          canonicalStrictJsonBytesV1(expected.analyzers),
        )
      );
    })
  );
}

export function verifyBaselineVetReceiptV1(
  request: BaselineVetRequestV1,
  result: BaselineVetBatchResultV1,
  seen: readonly Readonly<{ requestSha256: string; receiptSha256: string }>[] = [],
): BaselineVetVerificationV1 {
  try {
    canonicalBaselineVetRequestV1Bytes(request);
    const receipt = validateReceipt(result.receipt);
    if (!sameRequest(receipt, request)) return { kind: "required", reason: "request-mismatch" };
    assertStrictJsonValueV1(seen, "baseline replay ledger");
    const validatedSeen = z.array(replayEntry).max(10_000).parse(structuredClone(seen));
    assertUnique(
      validatedSeen.map((entry) => entry.requestSha256),
      "replay request digest",
    );
    if (
      validatedSeen.some(
        (entry) =>
          entry.requestSha256 === request.requestSha256 &&
          entry.receiptSha256 !== receipt.receiptSha256,
      )
    )
      return { kind: "required", reason: "replay-conflict" };
    const byPath = new Map<string, Buffer>();
    for (const artifact of result.annexArtifacts) {
      if (byPath.has(artifact.path)) return { kind: "required", reason: "duplicate-annex" };
      byPath.set(artifact.path, Buffer.from(artifact.bytes));
    }
    if (byPath.size !== receipt.observations.length)
      return { kind: "required", reason: "missing-annex" };
    for (const item of receipt.observations) {
      const bytes = byPath.get(item.annex.path);
      if (bytes === undefined) return { kind: "required", reason: "missing-annex" };
      if (
        bytes.byteLength !== item.annex.byteLength ||
        createHash("sha256").update(bytes).digest("hex") !== item.annex.sha256
      )
        return { kind: "required", reason: "annex-mismatch" };
      normalizedObservation(item.analyzer, {
        mediaType: item.annex.mediaType,
        bytes,
        analyzerVersion: item.analyzerVersion,
      });
      if (
        item.annex.mediaType === "application/sarif+json" &&
        !carriesBaselineCompletion(item.analyzer, item.analyzerVersion, bytes)
      )
        return { kind: "required", reason: "annex-mismatch" };
    }
    return { kind: "complete" };
  } catch {
    return { kind: "required", reason: "receipt-mismatch" };
  }
}
