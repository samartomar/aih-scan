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
  readSync,
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../observation/source-hash-v1.js";

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

function normalizedObservation(
  analyzerName: BaselineAnalyzerV1,
  value: Awaited<ReturnType<BaselineAnalyzerExecutionV1>>,
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

function copyAnalyzerSource(source: string, snapshot: string): void {
  const rootBefore = lstatSync(source);
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink())
    fail("baseline source directory shape");
  const budget = { entries: 0, bytes: 0 };
  const copy = (from: string, to: string): void => {
    const before = lstatSync(from);
    budget.entries += 1;
    if (budget.entries > maxSourceEntries) fail("baseline source entry bound");
    if (before.isSymbolicLink()) fail("baseline source symbolic link");
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
    if (before.size > maxAnnexBytes || before.size > maxSourceBytes - budget.bytes)
      fail("baseline source byte bound");
    const bytes = readBoundedSourceFile(from, before);
    budget.bytes += bytes.byteLength;
    writeFileSync(to, bytes, { flag: "wx", mode: 0o600 });
  };
  for (const name of readdirSync(source)
    .filter((value) => value !== ".git")
    .sort(codeUnitCompare))
    copy(join(source, name), join(snapshot, name));
  const rootAfter = lstatSync(source);
  if (
    !rootAfter.isDirectory() ||
    rootAfter.isSymbolicLink() ||
    !sameIdentity(rootBefore, rootAfter)
  )
    fail("baseline source directory replacement");
  if (budget.entries === 0) fail("baseline source has no content");
}

function assertSafeAnalyzerSource(sourceRoot: string): void {
  const root = resolve(sourceRoot);
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("baseline source directory shape");
  const budget = { entries: 0, bytes: 0 };
  const visit = (path: string): void => {
    const stat = lstatSync(path);
    budget.entries += 1;
    if (budget.entries > maxSourceEntries) fail("baseline source entry bound");
    if (stat.isSymbolicLink()) fail("baseline source symbolic link");
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort(codeUnitCompare)) visit(join(path, name));
      return;
    }
    if (!stat.isFile() || stat.nlink !== 1) fail("baseline source file shape");
    if (stat.size > maxAnnexBytes || stat.size > maxSourceBytes - budget.bytes)
      fail("baseline source byte bound");
    budget.bytes += stat.size;
  };
  for (const name of readdirSync(root)
    .filter((value) => value !== ".git")
    .sort(codeUnitCompare))
    visit(join(root, name));
  if (budget.entries === 0) fail("baseline source has no content");
}

function createAnalyzerSnapshot(request: BaselineVetRequestV1, sourceRoot: string): string {
  const source = resolve(sourceRoot);
  const snapshot = mkdtempSync(join(tmpdir(), "aih-scan-baseline-source-"));
  try {
    chmodSync(snapshot, 0o700);
  } catch {
    // Windows ACLs are platform-managed; mkdtemp remains the private creation boundary.
  }
  try {
    copyAnalyzerSource(source, snapshot);
    assertSafeAnalyzerSource(snapshot);
    sourceAndComponentsMatch(request, snapshot);
    return snapshot;
  } catch (error) {
    rmSync(snapshot, { recursive: true, force: true });
    throw error;
  }
}

export async function executeBaselineVetBatchV1(
  request: BaselineVetRequestV1,
  runtime: { readonly sourceRoot: string; readonly execute: BaselineAnalyzerExecutionV1 },
): Promise<BaselineVetBatchResultV1> {
  canonicalBaselineVetRequestV1Bytes(request);
  const snapshotRoot = createAnalyzerSnapshot(request, runtime.sourceRoot);
  const selected = analyzerOrder(request.components.flatMap((component) => component.analyzers));
  const observations: z.infer<typeof observation>[] = [];
  const annexArtifacts: BaselineVetAnnexArtifactV1[] = [];
  try {
    for (const analyzerName of selected) {
      const observed = normalizedObservation(
        analyzerName,
        await runtime.execute({
          analyzer: analyzerName,
          sourceRoot: snapshotRoot,
          source: request.source,
        }),
      );
      const path = `annex/${analyzerName}.json`;
      const digest = createHash("sha256").update(observed.bytes).digest("hex");
      observations.push({
        analyzer: analyzerName,
        analyzerVersion: observed.analyzerVersion,
        annex: {
          path,
          mediaType: observed.mediaType,
          sha256: digest,
          byteLength: observed.bytes.byteLength,
        },
      });
      annexArtifacts.push({ path, bytes: observed.bytes });
    }
    assertSafeAnalyzerSource(snapshotRoot);
    sourceAndComponentsMatch(request, snapshotRoot);
    const reobservedRoot = createAnalyzerSnapshot(request, runtime.sourceRoot);
    rmSync(reobservedRoot, { recursive: true, force: true });
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
    }
    return { kind: "complete" };
  } catch {
    return { kind: "required", reason: "receipt-mismatch" };
  }
}
