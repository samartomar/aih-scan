import { createHash } from "node:crypto";
import { existsSync, lstatSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";
import { canonicalSealedSourceSnapshotBytesV1 } from "../observation/native-observation-v1.js";
import { probeCiscoLinuxAmd64V1 } from "./linux-amd64-probe-v1.js";
import { executeCiscoOciBrokerV1 } from "./oci-broker-v1.js";
import { parseCiscoOciLayoutV1 } from "./oci-layout-v1.js";

const DIGEST = /^[a-f0-9]{64}$/;
const RAW = /^raw-occurrence-v1:[a-f0-9]{64}$/;
const LOCK_SHA256 = "3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3";
const WHEEL_SHA256 = "d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837";
const brands = new WeakMap<object, Buffer>();

type RecordValue = Record<string, unknown>;
type Fact = {
  readonly detectorClass: "cisco";
  readonly nativeRuleId: string;
  readonly path: string;
  readonly fileSha256: string;
  readonly canonicalOrdinal: number;
  readonly multiplicity: 1;
  readonly rawOccurrenceFingerprint: string;
};
type Coverage = { readonly coverageKind: "selected-closure"; readonly coverageSha256: string };
type Descriptor = {
  readonly descriptorId: "annex.cisco-raw";
  readonly mediaType: "application/json";
  readonly sha256: string;
  readonly byteLength: number;
  readonly uri: "annex/cisco-raw.json";
};
type EvidenceAnnex = {
  readonly protocol: "EvidenceAnnexV1";
  readonly descriptors: readonly [Descriptor];
  readonly evidenceAnnexSha256: string;
};
type SourceSeal = {
  readonly protocol: "SourceSealV1";
  readonly sourceTreeSha256: string;
  readonly selectedClosureSha256: string;
  readonly sealedSnapshotSha256: string;
};
type Observation = {
  readonly facts: readonly Fact[];
  readonly coverage: readonly Coverage[];
  readonly annexBytes: Buffer;
  readonly evidenceAnnex: EvidenceAnnex;
};
type DirectRun = Observation & {
  readonly executionOrdinal: number;
  readonly beforeSourceSeal: SourceSeal;
  readonly afterSourceSeal: SourceSeal;
  readonly sarifSha256: string;
};
type DirectProducer = {
  readonly sourceSeal: SourceSeal;
  readonly executions: readonly [DirectRun, DirectRun];
};
type OciProducer = Observation & { readonly sourceSeal: SourceSeal };

export interface CiscoDualRunEquivalenceV1 {
  readonly protocol: "CiscoDualRunEquivalenceV1";
  readonly validationState: "cryptographically-unverified";
  readonly directDigestSha256: string;
  readonly ociDigestSha256: string;
  readonly semanticDigestSha256: string;
}

export interface CiscoOciEquivalenceLiveNotRunV1 {
  readonly protocol: "CiscoOciEquivalenceLiveV1";
  readonly kind: "not-run";
  readonly reason: "opt-in-required";
}

function fail(message: string): never {
  throw new TypeError(`invalid Cisco dual-run equivalence V1: ${message}`);
}

function record(value: unknown, label: string): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${label} object`);
  if (
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(value).some((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor === undefined || !("value" in descriptor);
    })
  )
    fail(`${label} plain data`);
  return value as RecordValue;
}

function exact(value: RecordValue, keys: readonly string[], label: string): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)))
    fail(`${label} closed shape`);
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} SHA-256`);
  return value;
}

function seal(value: unknown, label: string): SourceSeal {
  const parsed = record(value, label);
  exact(
    parsed,
    ["protocol", "sourceTreeSha256", "selectedClosureSha256", "sealedSnapshotSha256"],
    label,
  );
  if (parsed.protocol !== "SourceSealV1") fail(`${label} protocol`);
  return {
    protocol: "SourceSealV1",
    sourceTreeSha256: digest(parsed.sourceTreeSha256, `${label} source tree`),
    selectedClosureSha256: digest(parsed.selectedClosureSha256, `${label} selected closure`),
    sealedSnapshotSha256: digest(parsed.sealedSnapshotSha256, `${label} snapshot`),
  };
}

function sameSeal(left: SourceSeal, right: SourceSeal): boolean {
  return (
    left.sourceTreeSha256 === right.sourceTreeSha256 &&
    left.selectedClosureSha256 === right.selectedClosureSha256 &&
    left.sealedSnapshotSha256 === right.sealedSnapshotSha256
  );
}

function linuxAmd64(value: unknown, label: string): void {
  const parsed = record(value, label);
  exact(parsed, ["os", "architecture"], label);
  if (parsed.os !== "linux" || parsed.architecture !== "amd64") fail(`${label} linux amd64`);
}

function runtime(value: unknown): void {
  const parsed = record(value, "direct runtime");
  exact(
    parsed,
    ["packageName", "version", "uvVersion", "lockSha256", "wheelSha256"],
    "direct runtime",
  );
  if (
    parsed.packageName !== "cisco-ai-skill-scanner" ||
    parsed.version !== "2.0.13" ||
    parsed.uvVersion !== "0.12.5" ||
    parsed.lockSha256 !== LOCK_SHA256 ||
    parsed.wheelSha256 !== WHEEL_SHA256
  )
    fail("direct runtime");
}

function snapshotSeal(value: unknown): SourceSeal {
  let bytes: Buffer;
  try {
    bytes = canonicalSealedSourceSnapshotBytesV1(value as never);
  } catch {
    fail("direct source snapshot");
  }
  const parsed = record(JSON.parse(bytes.toString("utf8")), "direct source snapshot");
  exact(
    parsed,
    [
      "protocol",
      "sourceTreeSha256",
      "selectedClosureSha256",
      "sourceFiles",
      "selectedClosureFiles",
      "sealedSnapshotSha256",
    ],
    "direct source snapshot",
  );
  if (parsed.protocol !== "SealedSourceSnapshotV1") fail("direct source snapshot protocol");
  return {
    protocol: "SourceSealV1",
    sourceTreeSha256: digest(parsed.sourceTreeSha256, "direct source snapshot tree"),
    selectedClosureSha256: digest(parsed.selectedClosureSha256, "direct source snapshot closure"),
    sealedSnapshotSha256: digest(parsed.sealedSnapshotSha256, "direct source snapshot digest"),
  };
}

function fact(value: unknown, label: string): Fact {
  const parsed = record(value, label);
  exact(
    parsed,
    [
      "detectorClass",
      "nativeRuleId",
      "path",
      "fileSha256",
      "canonicalOrdinal",
      "multiplicity",
      "rawOccurrenceFingerprint",
    ],
    label,
  );
  if (
    parsed.detectorClass !== "cisco" ||
    typeof parsed.nativeRuleId !== "string" ||
    !parsed.nativeRuleId ||
    parsed.nativeRuleId.length > 256 ||
    typeof parsed.path !== "string" ||
    typeof parsed.canonicalOrdinal !== "number" ||
    !Number.isSafeInteger(parsed.canonicalOrdinal) ||
    parsed.canonicalOrdinal < 0 ||
    parsed.multiplicity !== 1 ||
    typeof parsed.rawOccurrenceFingerprint !== "string" ||
    !RAW.test(parsed.rawOccurrenceFingerprint)
  )
    fail(`${label} fields`);
  assertSafeRelativePosixPathV1(parsed.path, `${label} path`);
  const result = {
    detectorClass: "cisco" as const,
    nativeRuleId: parsed.nativeRuleId,
    path: parsed.path,
    fileSha256: digest(parsed.fileSha256, `${label} file`),
    canonicalOrdinal: parsed.canonicalOrdinal,
    multiplicity: 1 as const,
    rawOccurrenceFingerprint: parsed.rawOccurrenceFingerprint,
  };
  const expected =
    "raw-occurrence-v1:" +
    canonicalStrictJsonSha256V1({
      protocol: "RawOccurrenceFingerprintV1",
      detectorClass: result.detectorClass,
      nativeRuleId: result.nativeRuleId,
      path: result.path,
      fileSha256: result.fileSha256,
      canonicalOrdinal: result.canonicalOrdinal,
    });
  if (expected !== result.rawOccurrenceFingerprint) fail(`${label} raw fingerprint`);
  return result;
}

function facts(value: unknown, label: string): readonly Fact[] {
  if (!Array.isArray(value) || value.length > 4096) fail(`${label} array`);
  const parsed = value.map((item, index) => fact(item, `${label}[${String(index)}]`));
  const groups = new Map<string, number[]>();
  const raw = new Set<string>();
  for (const item of parsed) {
    if (raw.has(item.rawOccurrenceFingerprint)) fail(`${label} duplicate raw fingerprint`);
    raw.add(item.rawOccurrenceFingerprint);
    const group = `${item.nativeRuleId}\0${item.path}\0${item.fileSha256}`;
    const ordinals = groups.get(group) ?? [];
    ordinals.push(item.canonicalOrdinal);
    groups.set(group, ordinals);
  }
  for (const ordinals of groups.values()) {
    const ordered = [...ordinals].sort((left, right) => left - right);
    if (ordered.some((ordinal, index) => ordinal !== index)) fail(`${label} ordinal partition`);
  }
  return Object.freeze(parsed);
}

function coverage(value: unknown, label: string): readonly Coverage[] {
  if (!Array.isArray(value) || value.length !== 1) fail(`${label} array`);
  const parsed = record(value[0], `${label}[0]`);
  exact(parsed, ["coverageKind", "coverageSha256"], `${label}[0]`);
  if (parsed.coverageKind !== "selected-closure") fail(`${label} kind`);
  return Object.freeze([
    { coverageKind: "selected-closure", coverageSha256: digest(parsed.coverageSha256, label) },
  ]);
}

function descriptor(value: unknown, label: string): Descriptor {
  const parsed = record(value, label);
  exact(parsed, ["descriptorId", "mediaType", "sha256", "byteLength", "uri"], label);
  if (
    parsed.descriptorId !== "annex.cisco-raw" ||
    parsed.mediaType !== "application/json" ||
    parsed.uri !== "annex/cisco-raw.json" ||
    typeof parsed.byteLength !== "number" ||
    !Number.isSafeInteger(parsed.byteLength) ||
    parsed.byteLength < 1
  )
    fail(`${label} fields`);
  return {
    descriptorId: "annex.cisco-raw",
    mediaType: "application/json",
    sha256: digest(parsed.sha256, `${label} digest`),
    byteLength: parsed.byteLength,
    uri: "annex/cisco-raw.json",
  };
}

function annex(value: unknown, bytes: Buffer, label: string): EvidenceAnnex {
  const parsed = record(value, label);
  exact(parsed, ["protocol", "descriptors", "evidenceAnnexSha256"], label);
  if (
    parsed.protocol !== "EvidenceAnnexV1" ||
    !Array.isArray(parsed.descriptors) ||
    parsed.descriptors.length !== 1
  )
    fail(`${label} shape`);
  const item = descriptor(parsed.descriptors[0], `${label} descriptor`);
  if (
    item.byteLength !== bytes.byteLength ||
    item.sha256 !== createHash("sha256").update(bytes).digest("hex")
  )
    fail(`${label} descriptor binding`);
  const expectedDigest = canonicalStrictJsonSha256V1({
    domain: "aih.evidence-annex-v1",
    descriptors: [item],
  });
  if (digest(parsed.evidenceAnnexSha256, `${label} digest`) !== expectedDigest)
    fail(`${label} digest binding`);
  return {
    protocol: "EvidenceAnnexV1",
    descriptors: Object.freeze([item]) as readonly [Descriptor],
    evidenceAnnexSha256: expectedDigest,
  };
}

function canonicalAnnex(bytes: unknown, label: string): Buffer {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength < 1 || bytes.byteLength > 16 * 1024 * 1024)
    fail(`${label} bytes`);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail(`${label} UTF-8`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail(`${label} JSON`);
  }
  assertStrictJsonValueV1(parsed, `${label} JSON`);
  if (!Array.isArray(parsed) || !canonicalStrictJsonBytesV1(parsed).equals(bytes))
    fail(`${label} canonical JSON`);
  return Buffer.from(bytes);
}

function observation(value: RecordValue, label: string): Observation {
  const bytes = canonicalAnnex(value.annexBytes, `${label} annex`);
  return {
    facts: facts(value.facts, `${label} facts`),
    coverage: coverage(value.coverage, `${label} coverage`),
    annexBytes: bytes,
    evidenceAnnex: annex(value.evidenceAnnex, bytes, `${label} evidence annex`),
  };
}

function direct(value: unknown): DirectProducer {
  const parsed = record(value, "direct producer");
  exact(
    parsed,
    [
      "protocol",
      "observationScope",
      "platform",
      "runtime",
      "sourceSnapshot",
      "sourceSeal",
      "executions",
    ],
    "direct producer",
  );
  if (
    parsed.protocol !== "CiscoLinuxAmd64ProbeV1" ||
    parsed.observationScope !== "ephemeral" ||
    !Array.isArray(parsed.executions) ||
    parsed.executions.length !== 2
  )
    fail("direct producer shape");
  const sourceSeal = seal(parsed.sourceSeal, "direct source seal");
  linuxAmd64(parsed.platform, "direct platform");
  runtime(parsed.runtime);
  if (!sameSeal(snapshotSeal(parsed.sourceSnapshot), sourceSeal)) fail("direct snapshot seal");
  const executions = parsed.executions.map((item, index) => {
    const execution = record(item, "direct execution");
    exact(
      execution,
      [
        "executionOrdinal",
        "beforeSourceSeal",
        "afterSourceSeal",
        "sarifSha256",
        "facts",
        "annexBytes",
        "evidenceAnnex",
        "coverage",
      ],
      "direct execution",
    );
    if (execution.executionOrdinal !== index) fail("direct execution ordinal");
    const beforeSourceSeal = seal(execution.beforeSourceSeal, "direct before seal");
    const afterSourceSeal = seal(execution.afterSourceSeal, "direct after seal");
    if (!sameSeal(sourceSeal, beforeSourceSeal) || !sameSeal(sourceSeal, afterSourceSeal))
      fail("direct execution source seal");
    const observed = observation(execution, "direct execution");
    return {
      executionOrdinal: index,
      beforeSourceSeal,
      afterSourceSeal,
      sarifSha256: digest(execution.sarifSha256, "direct SARIF"),
      ...observed,
    };
  });
  if (executions[0] === undefined || executions[1] === undefined) fail("direct executions");
  if (
    executions[0].annexBytes === executions[1].annexBytes ||
    canonicalStrictJsonBytesV1(semantic(executions[0])).compare(
      canonicalStrictJsonBytesV1(semantic(executions[1])),
    ) !== 0
  )
    fail("direct repeatability");
  return { sourceSeal, executions: Object.freeze([executions[0], executions[1]]) };
}

function oci(value: unknown): OciProducer {
  const parsed = record(value, "OCI producer");
  exact(
    parsed,
    [
      "protocol",
      "observationScope",
      "validationState",
      "platform",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "sourceSeal",
      "sarifSha256",
      "facts",
      "coverage",
      "annexBytes",
      "evidenceAnnex",
      "cleanup",
    ],
    "OCI producer",
  );
  if (
    parsed.protocol !== "CiscoOciBrokerV1" ||
    parsed.observationScope !== "candidate" ||
    parsed.validationState !== "cryptographically-unverified"
  )
    fail("OCI producer protocol");
  linuxAmd64(parsed.platform, "OCI platform");
  if (
    typeof parsed.manifestDigestSha256 !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(parsed.manifestDigestSha256)
  )
    fail("OCI manifest");
  if (
    typeof parsed.configDigestSha256 !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(parsed.configDigestSha256)
  )
    fail("OCI config");
  if (
    parsed.logicalReference !==
    `local.invalid/aih-scan/cisco@${String(parsed.manifestDigestSha256)}`
  )
    fail("OCI logical reference");
  const cleanup = record(parsed.cleanup, "OCI cleanup");
  exact(cleanup, ["kind"], "OCI cleanup");
  if (cleanup.kind !== "clean") fail("OCI cleanup");
  digest(parsed.sarifSha256, "OCI SARIF");
  return {
    sourceSeal: seal(parsed.sourceSeal, "OCI source seal"),
    ...observation(parsed, "OCI producer"),
  };
}

function semantic(value: Observation) {
  return {
    facts: value.facts,
    coverage: value.coverage,
    evidenceAnnex: value.evidenceAnnex,
    annexBytesSha256: createHash("sha256").update(value.annexBytes).digest("hex"),
    annexBytes: value.annexBytes.toString("base64"),
  };
}

function equal(left: unknown, right: unknown): boolean {
  return canonicalStrictJsonBytesV1(left).equals(canonicalStrictJsonBytesV1(right));
}

function separateRoots(directRoot: unknown, ociRoot: unknown): void {
  if (
    typeof directRoot !== "string" ||
    typeof ociRoot !== "string" ||
    !isAbsolute(directRoot) ||
    !isAbsolute(ociRoot)
  )
    fail("absolute roots");
  const directPath = resolve(directRoot);
  const ociPath = resolve(ociRoot);
  if (
    directPath === ociPath ||
    relative(directPath, ociPath) === "" ||
    relative(directPath, ociPath).startsWith("..") === false ||
    relative(ociPath, directPath).startsWith("..") === false
  )
    fail("separate roots");
}

function parsedInput(value: unknown) {
  const input = record(value, "input");
  exact(input, ["protocol", "directRoot", "ociRoot", "direct", "oci"], "input");
  if (input.protocol !== "CiscoDualRunEquivalenceV1") fail("protocol");
  separateRoots(input.directRoot, input.ociRoot);
  const directProducer = direct(input.direct);
  const ociProducer = oci(input.oci);
  if (!sameSeal(directProducer.sourceSeal, ociProducer.sourceSeal)) fail("source seal mismatch");
  if (
    directProducer.executions[0].annexBytes === ociProducer.annexBytes ||
    directProducer.executions[1].annexBytes === ociProducer.annexBytes ||
    !equal(semantic(directProducer.executions[0]), semantic(ociProducer))
  )
    fail("producer semantic mismatch");
  return { direct: directProducer, oci: ociProducer };
}

export function compareCiscoDualRunV1(input: unknown): CiscoDualRunEquivalenceV1 {
  const value = parsedInput(input);
  const directDigestSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco-dual-run-v1.direct",
    sourceSeal: value.direct.sourceSeal,
    semantic: semantic(value.direct.executions[0]),
  });
  const ociDigestSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco-dual-run-v1.oci",
    sourceSeal: value.oci.sourceSeal,
    semantic: semantic(value.oci),
  });
  const result = deepFreezeStrictJsonV1({
    protocol: "CiscoDualRunEquivalenceV1" as const,
    validationState: "cryptographically-unverified" as const,
    directDigestSha256,
    ociDigestSha256,
    semanticDigestSha256: canonicalStrictJsonSha256V1({
      domain: "aih.cisco-dual-run-v1.semantic",
      directDigestSha256,
      ociDigestSha256,
    }),
  });
  brands.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}

export function createCiscoDualRunDigestV1(value: CiscoDualRunEquivalenceV1): string {
  const bytes = typeof value === "object" && value !== null ? brands.get(value) : undefined;
  if (bytes === undefined) fail("validated result required");
  return canonicalStrictJsonSha256V1(value);
}

type LiveRunner = (
  argv: readonly string[],
  options: {
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
    readonly cwd?: string;
  },
) => Promise<unknown>;

function liveRecord(value: unknown): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("live input");
  return value as RecordValue;
}

export async function runCiscoOciEquivalenceLiveV1(
  input: unknown,
): Promise<CiscoDualRunEquivalenceV1 | CiscoOciEquivalenceLiveNotRunV1> {
  const value = liveRecord(input);
  if (value.protocol !== "CiscoOciEquivalenceLiveV1" || typeof value.enabled !== "boolean")
    fail("live protocol");
  if (value.enabled === false) {
    exact(
      value,
      ["protocol", "enabled", "directRoot", "ociRoot", "configDigestSha256"],
      "disabled live input",
    );
    return deepFreezeStrictJsonV1({
      protocol: "CiscoOciEquivalenceLiveV1" as const,
      kind: "not-run" as const,
      reason: "opt-in-required" as const,
    });
  }
  exact(
    value,
    [
      "protocol",
      "enabled",
      "directRoot",
      "ociRoot",
      "runtimeProjectRoot",
      "layoutBytes",
      "configDigestSha256",
      "summaryPath",
      "uvRunner",
      "dockerRunner",
    ],
    "live input",
  );
  separateRoots(value.directRoot, value.ociRoot);
  if (
    typeof value.runtimeProjectRoot !== "string" ||
    !isAbsolute(value.runtimeProjectRoot) ||
    !Buffer.isBuffer(value.layoutBytes) ||
    typeof value.configDigestSha256 !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(value.configDigestSha256) ||
    typeof value.summaryPath !== "string" ||
    !isAbsolute(value.summaryPath) ||
    typeof value.uvRunner !== "function" ||
    typeof value.dockerRunner !== "function"
  )
    fail("live input fields");
  const layout = parseCiscoOciLayoutV1(value.layoutBytes);
  if (layout.configDigestSha256 !== value.configDigestSha256) fail("live config identity");
  const summaryDirectory = dirname(value.summaryPath);
  if (!existsSync(summaryDirectory) || !lstatSync(summaryDirectory).isDirectory())
    fail("summary directory");
  const host = {
    os: process.platform === "linux" ? "linux" : "windows",
    architecture: process.arch === "x64" ? "amd64" : "arm64",
  };
  if (host.os !== "linux" || host.architecture !== "amd64") fail("linux amd64 required");
  const direct = await probeCiscoLinuxAmd64V1({
    protocol: "CiscoLinuxAmd64ProbeV1",
    sourceRoot: value.directRoot,
    selectedClosurePaths: ["skills/demo/SKILL.md"],
    runtimeProjectRoot: value.runtimeProjectRoot,
    platform: { os: "linux", architecture: "amd64" },
    runtime: {
      packageName: "cisco-ai-skill-scanner",
      version: "2.0.13",
      uvVersion: "0.12.5",
      lockSha256: LOCK_SHA256,
      wheelSha256: WHEEL_SHA256,
    },
    environment: { AIH_SCAN_CISCO_LINUX_AMD64_PROBE: "1" },
    host,
    runner: value.uvRunner as LiveRunner,
  });
  const ociResult = await executeCiscoOciBrokerV1({
    protocol: "CiscoOciBrokerV1",
    layout,
    sourceRoot: value.ociRoot,
    selectedClosurePaths: ["skills/demo/SKILL.md"],
    host,
    runner: value.dockerRunner as LiveRunner,
  });
  const result = compareCiscoDualRunV1({
    protocol: "CiscoDualRunEquivalenceV1",
    directRoot: value.directRoot,
    ociRoot: value.ociRoot,
    direct,
    oci: ociResult,
  });
  writeFileSync(
    value.summaryPath,
    canonicalStrictJsonBytesV1({
      protocol: "CiscoOciEquivalenceLiveV1",
      validationState: result.validationState,
      directDigestSha256: result.directDigestSha256,
      ociDigestSha256: result.ociDigestSha256,
      semanticDigestSha256: result.semanticDigestSha256,
    }),
  );
  return result;
}
