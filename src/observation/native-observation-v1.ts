import { createHash } from "node:crypto";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "./source-hash-v1.js";

const sha = (value: string) => /^[a-f0-9]{64}$/.test(value);
const raw = (value: string) => /^raw-occurrence-v1:[a-f0-9]{64}$/.test(value);
const brand = new WeakMap<object, Buffer>();
const snapshotBrand = new WeakMap<object, Buffer>();
type File = { readonly path: string; readonly bytes: number; readonly sha256: string };
export type SourceSealV1 = Readonly<{
  protocol: "SourceSealV1";
  sourceTreeSha256: string;
  selectedClosureSha256: string;
  sealedSnapshotSha256: string;
}>;
export type SealedSourceSnapshotV1 = Readonly<{
  protocol: "SealedSourceSnapshotV1";
  sourceTreeSha256: string;
  selectedClosureSha256: string;
  sourceFiles: readonly File[];
  selectedClosureFiles: readonly File[];
  sealedSnapshotSha256: string;
}>;
export type NativeObservationV1 = Readonly<Record<string, unknown>> & {
  readonly protocol: "NativeObservationV1";
  readonly sourceSeal: SourceSealV1;
  readonly nativeAnalyzerIdentity: string;
  readonly observationConfigurationSha256: string;
  readonly platform: {
    readonly os: "linux" | "darwin" | "windows";
    readonly architecture: "amd64" | "arm64";
    readonly relevantFactsSha256: string;
  };
  readonly facts: readonly {
    readonly rawOccurrenceFingerprint: string;
    readonly multiplicity: number;
  }[];
  readonly coverage: readonly {
    readonly coverageKind: "selected-closure" | "source-tree";
    readonly coverageSha256: string;
  }[];
  readonly reuseScope: "local-optimization-only";
  readonly observationKeySha256: string;
  readonly resultSha256: string;
};
export type NativeObservationReuseV1 =
  | { readonly kind: "reusable-local" }
  | {
      readonly kind: "required";
      readonly code: "NATIVE_OBSERVATION_REQUIRED";
      readonly reason:
        | "source-bytes-unavailable"
        | "source-tree-mismatch"
        | "selected-closure-mismatch"
        | "invalid-observation"
        | "sealed-snapshot-required"
        | "sealed-snapshot-mismatch"
        | "expected-key-context-required"
        | "expected-key-context-mismatch";
    };
const clone = <T>(value: T): T => structuredClone(value);
const requireObject = (value: unknown, label: string): Record<string, unknown> => {
  assertStrictJsonValueV1(value, label);
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
};
const exact = (value: Record<string, unknown>, keys: readonly string[], label: string) => {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !(key in value)))
    throw new TypeError(`${label} has unknown or missing fields`);
};
const required = (
  reason: Exclude<NativeObservationReuseV1, { kind: "reusable-local" }>["reason"],
): NativeObservationReuseV1 => ({ kind: "required", code: "NATIVE_OBSERVATION_REQUIRED", reason });
function file(value: unknown, label: string): File {
  const v = requireObject(value, label);
  exact(v, ["path", "bytes", "sha256"], label);
  if (
    typeof v.path !== "string" ||
    typeof v.bytes !== "number" ||
    !Number.isSafeInteger(v.bytes) ||
    v.bytes < 0 ||
    typeof v.sha256 !== "string" ||
    !sha(v.sha256)
  )
    throw new TypeError(`${label} invalid`);
  assertSafeRelativePosixPathV1(v.path, label);
  return { path: v.path, bytes: v.bytes, sha256: v.sha256 };
}
function seal(value: unknown): SourceSealV1 {
  const v = requireObject(value, "source seal");
  exact(
    v,
    ["protocol", "sourceTreeSha256", "selectedClosureSha256", "sealedSnapshotSha256"],
    "source seal",
  );
  if (
    v.protocol !== "SourceSealV1" ||
    typeof v.sourceTreeSha256 !== "string" ||
    typeof v.selectedClosureSha256 !== "string" ||
    typeof v.sealedSnapshotSha256 !== "string" ||
    ![v.sourceTreeSha256, v.selectedClosureSha256, v.sealedSnapshotSha256].every(sha)
  )
    throw new TypeError("invalid source seal");
  return deepFreezeStrictJsonV1(clone(v)) as SourceSealV1;
}
function platform(value: unknown) {
  const v = requireObject(value, "platform");
  exact(v, ["os", "architecture", "relevantFactsSha256"], "platform");
  if (
    !["linux", "darwin", "windows"].includes(String(v.os)) ||
    !["amd64", "arm64"].includes(String(v.architecture)) ||
    typeof v.relevantFactsSha256 !== "string" ||
    !sha(v.relevantFactsSha256)
  )
    throw new TypeError("invalid platform");
  return clone(v) as NativeObservationV1["platform"];
}
export function createSealedSourceSnapshotV1(input: unknown): SealedSourceSnapshotV1 {
  const v = requireObject(input, "sealed source snapshot");
  exact(
    v,
    [
      "protocol",
      "sourceTreeSha256",
      "selectedClosureSha256",
      "sourceFiles",
      "selectedClosureFiles",
    ],
    "sealed source snapshot",
  );
  if (
    v.protocol !== "SealedSourceSnapshotV1" ||
    typeof v.sourceTreeSha256 !== "string" ||
    typeof v.selectedClosureSha256 !== "string" ||
    !sha(v.sourceTreeSha256) ||
    !sha(v.selectedClosureSha256) ||
    !Array.isArray(v.sourceFiles) ||
    !Array.isArray(v.selectedClosureFiles) ||
    v.sourceFiles.length === 0 ||
    v.selectedClosureFiles.length === 0 ||
    v.sourceFiles.length > 100_000 ||
    v.selectedClosureFiles.length > 100_000
  )
    throw new TypeError("invalid sealed source snapshot");
  const sourceFiles = v.sourceFiles
    .map((x) => file(x, "source file"))
    .sort((a, b) => codeUnitCompare(a.path, b.path));
  const selectedClosureFiles = v.selectedClosureFiles
    .map((x) => file(x, "selected closure file"))
    .sort((a, b) => codeUnitCompare(a.path, b.path));
  if (
    new Set(sourceFiles.map((x) => x.path)).size !== sourceFiles.length ||
    new Set(selectedClosureFiles.map((x) => x.path)).size !== selectedClosureFiles.length
  )
    throw new TypeError("duplicate source inventory");
  const byPath = new Map(sourceFiles.map((x) => [x.path, x]));
  for (const f of selectedClosureFiles) {
    const source = byPath.get(f.path);
    if (source === undefined || source.bytes !== f.bytes || source.sha256 !== f.sha256)
      throw new TypeError("inconsistent selected source inventory");
  }
  const result = deepFreezeStrictJsonV1({
    protocol: "SealedSourceSnapshotV1" as const,
    sourceTreeSha256: v.sourceTreeSha256,
    selectedClosureSha256: v.selectedClosureSha256,
    sourceFiles,
    selectedClosureFiles,
    sealedSnapshotSha256: canonicalStrictJsonSha256V1({
      domain: "aih.sealed-source-snapshot-v1",
      protocol: v.protocol,
      sourceTreeSha256: v.sourceTreeSha256,
      selectedClosureSha256: v.selectedClosureSha256,
      sourceFiles,
      selectedClosureFiles,
    }),
  });
  snapshotBrand.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}
export function describeNativeObservationSourceV1(input: {
  readonly sourceRoot: string;
  readonly selectedClosurePaths: readonly string[];
}): SealedSourceSnapshotV1 {
  const all = hashSourceTreeV1(input.sourceRoot);
  const selected = hashComponentTreeV1(input.sourceRoot, input.selectedClosurePaths);
  return createSealedSourceSnapshotV1({
    protocol: "SealedSourceSnapshotV1",
    sourceTreeSha256: all.treeSha256,
    selectedClosureSha256: selected.treeSha256,
    sourceFiles: all.files,
    selectedClosureFiles: selected.files,
  });
}
export function sealNativeObservationSourceV1(input: {
  readonly sourceRoot: string;
  readonly selectedClosurePaths: readonly string[];
}): SourceSealV1 {
  const s = describeNativeObservationSourceV1(input);
  return seal({
    protocol: "SourceSealV1",
    sourceTreeSha256: s.sourceTreeSha256,
    selectedClosureSha256: s.selectedClosureSha256,
    sealedSnapshotSha256: s.sealedSnapshotSha256,
  });
}
export function canonicalSealedSourceSnapshotBytesV1(value: SealedSourceSnapshotV1): Buffer {
  const bytes = snapshotBrand.get(value as object);
  if (bytes === undefined)
    throw new TypeError(
      "sealed source snapshot canonical bytes require a validated branded snapshot",
    );
  return Buffer.from(bytes);
}
export function createNativeObservationV1(input: unknown): NativeObservationV1 {
  const v = requireObject(input, "native observation");
  exact(
    v,
    [
      "protocol",
      "sourceSeal",
      "nativeAnalyzerIdentity",
      "observationConfigurationSha256",
      "platform",
      "facts",
      "coverage",
    ],
    "native observation",
  );
  const sourceSeal = seal(v.sourceSeal);
  const p = platform(v.platform);
  if (
    v.protocol !== "NativeObservationV1" ||
    typeof v.nativeAnalyzerIdentity !== "string" ||
    !/^native\.[0-9a-f]{12}$/.test(v.nativeAnalyzerIdentity) ||
    typeof v.observationConfigurationSha256 !== "string" ||
    !sha(v.observationConfigurationSha256) ||
    !Array.isArray(v.facts) ||
    !Array.isArray(v.coverage) ||
    v.coverage.length === 0 ||
    v.facts.length > 4_096 ||
    v.coverage.length > 4_096
  )
    throw new TypeError("invalid native observation");
  const facts = v.facts
    .map((entry) => {
      const f = requireObject(entry, "fact");
      exact(f, ["rawOccurrenceFingerprint", "multiplicity"], "fact");
      if (
        typeof f.rawOccurrenceFingerprint !== "string" ||
        !raw(f.rawOccurrenceFingerprint) ||
        typeof f.multiplicity !== "number" ||
        !Number.isSafeInteger(f.multiplicity) ||
        f.multiplicity <= 0
      )
        throw new TypeError("invalid fact");
      return { rawOccurrenceFingerprint: f.rawOccurrenceFingerprint, multiplicity: f.multiplicity };
    })
    .sort((a, b) => codeUnitCompare(a.rawOccurrenceFingerprint, b.rawOccurrenceFingerprint));
  const coverage = v.coverage
    .map((entry) => {
      const c = requireObject(entry, "coverage");
      exact(c, ["coverageKind", "coverageSha256"], "coverage");
      if (
        !["selected-closure", "source-tree"].includes(String(c.coverageKind)) ||
        typeof c.coverageSha256 !== "string" ||
        !sha(c.coverageSha256)
      )
        throw new TypeError("invalid coverage");
      return {
        coverageKind: c.coverageKind as "selected-closure" | "source-tree",
        coverageSha256: c.coverageSha256,
      };
    })
    .sort((a, b) => codeUnitCompare(a.coverageKind, b.coverageKind));
  if (
    new Set(facts.map((x) => x.rawOccurrenceFingerprint)).size !== facts.length ||
    new Set(coverage.map((x) => x.coverageKind)).size !== coverage.length
  )
    throw new TypeError("duplicate fact or coverage");
  const observationKeySha256 = canonicalStrictJsonSha256V1({
    domain: "aih.native-observation-v1.key",
    protocol: v.protocol,
    sourceTreeSha256: sourceSeal.sourceTreeSha256,
    selectedClosureSha256: sourceSeal.selectedClosureSha256,
    sealedSnapshotSha256: sourceSeal.sealedSnapshotSha256,
    nativeAnalyzerIdentity: v.nativeAnalyzerIdentity,
    observationConfigurationSha256: v.observationConfigurationSha256,
    platform: p,
  });
  const result = deepFreezeStrictJsonV1({
    protocol: "NativeObservationV1" as const,
    sourceSeal,
    nativeAnalyzerIdentity: v.nativeAnalyzerIdentity,
    observationConfigurationSha256: v.observationConfigurationSha256,
    platform: p,
    facts,
    coverage,
    reuseScope: "local-optimization-only" as const,
    observationKeySha256,
    resultSha256: canonicalStrictJsonSha256V1({
      domain: "aih.native-observation-v1.result",
      observationKeySha256,
      facts,
      coverage,
    }),
  });
  brand.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}
export function parseNativeObservationV1Json(text: string): NativeObservationV1 {
  return createNativeObservationV1(parseStrictJsonObjectV1(text, "native observation"));
}
export function canonicalNativeObservationBytesV1(value: NativeObservationV1): Buffer {
  const bytes = brand.get(value as object);
  if (bytes === undefined)
    throw new TypeError(
      "native observation canonical bytes require a validated branded observation",
    );
  return Buffer.from(bytes);
}
export function canonicalNativeObservationSha256V1(value: NativeObservationV1): string {
  return createHash("sha256").update(canonicalNativeObservationBytesV1(value)).digest("hex");
}
function validExpectedKeyContext(value: unknown): value is {
  protocol: string;
  nativeAnalyzerIdentity: string;
  observationConfigurationSha256: string;
  platform: { os: string; architecture: string; relevantFactsSha256: string };
} {
  try {
    assertStrictJsonValueV1(value, "expected native observation key context");
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const context = value as Record<string, unknown>;
    exact(
      context,
      ["protocol", "nativeAnalyzerIdentity", "observationConfigurationSha256", "platform"],
      "expected native observation key context",
    );
    if (
      typeof context.protocol !== "string" ||
      typeof context.nativeAnalyzerIdentity !== "string" ||
      !/^native\.[0-9a-f]{12}$/.test(context.nativeAnalyzerIdentity) ||
      typeof context.observationConfigurationSha256 !== "string" ||
      !sha(context.observationConfigurationSha256) ||
      typeof context.platform !== "object" ||
      context.platform === null ||
      Array.isArray(context.platform)
    )
      return false;
    const platformValue = context.platform as Record<string, unknown>;
    exact(platformValue, ["os", "architecture", "relevantFactsSha256"], "expected platform");
    return (
      typeof platformValue.os === "string" &&
      typeof platformValue.architecture === "string" &&
      typeof platformValue.relevantFactsSha256 === "string" &&
      sha(platformValue.relevantFactsSha256)
    );
  } catch {
    return false;
  }
}
export function assessNativeObservationReuseV1(input: {
  readonly observation: unknown;
  readonly sourceRoot: string;
  readonly selectedClosurePaths: readonly string[];
  readonly sealedSnapshot: SealedSourceSnapshotV1;
  readonly expectedKeyContext: {
    readonly protocol: string;
    readonly nativeAnalyzerIdentity: string;
    readonly observationConfigurationSha256: string;
    readonly platform: {
      readonly os: string;
      readonly architecture: string;
      readonly relevantFactsSha256: string;
    };
  };
}): NativeObservationReuseV1 {
  if (
    typeof input.observation !== "object" ||
    input.observation === null ||
    !brand.has(input.observation)
  )
    return required("invalid-observation");
  const observation = input.observation as NativeObservationV1;
  if (
    typeof input.sealedSnapshot !== "object" ||
    input.sealedSnapshot === null ||
    !snapshotBrand.has(input.sealedSnapshot)
  )
    return required("sealed-snapshot-required");
  if (!validExpectedKeyContext(input.expectedKeyContext))
    return required("expected-key-context-required");
  const expected = input.expectedKeyContext;
  if (
    expected.protocol !== observation.protocol ||
    expected.nativeAnalyzerIdentity !== observation.nativeAnalyzerIdentity ||
    expected.observationConfigurationSha256 !== observation.observationConfigurationSha256 ||
    expected.platform?.os !== observation.platform.os ||
    expected.platform?.architecture !== observation.platform.architecture ||
    expected.platform?.relevantFactsSha256 !== observation.platform.relevantFactsSha256
  )
    return required("expected-key-context-mismatch");
  let current: SealedSourceSnapshotV1;
  try {
    current = describeNativeObservationSourceV1({
      sourceRoot: input.sourceRoot,
      selectedClosurePaths: input.selectedClosurePaths,
    });
  } catch {
    return required("source-bytes-unavailable");
  }
  if (current.sealedSnapshotSha256 !== input.sealedSnapshot.sealedSnapshotSha256)
    return required("sealed-snapshot-mismatch");
  if (current.selectedClosureSha256 !== observation.sourceSeal.selectedClosureSha256)
    return required("selected-closure-mismatch");
  if (current.sourceTreeSha256 !== observation.sourceSeal.sourceTreeSha256)
    return required("source-tree-mismatch");
  if (observation.sourceSeal.sealedSnapshotSha256 !== input.sealedSnapshot.sealedSnapshotSha256)
    return required("sealed-snapshot-mismatch");
  return { kind: "reusable-local" };
}
