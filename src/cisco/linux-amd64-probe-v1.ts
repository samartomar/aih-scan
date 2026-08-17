import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, type Stats } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
} from "../contract/strict-json-v1.js";
import {
  describeNativeObservationSourceV1,
  type SealedSourceSnapshotV1,
  type SourceSealV1,
  sealNativeObservationSourceV1,
} from "../observation/native-observation-v1.js";
import { createCiscoFactsOnlyV1 } from "./facts-only-v1.js";
import { type CiscoSarifV1, parseCiscoSarifV1 } from "./sarif-v1.js";

const LOCK_SHA256 = "3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3";
const WHEEL_SHA256 = "d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837";
const MAX_STDIO_BYTES = 64 * 1024;
const MAX_SARIF_BYTES = 16 * 1024 * 1024;
const TIMEOUT_MS = 120_000;
const inputKeys = [
  "protocol",
  "sourceRoot",
  "selectedClosurePaths",
  "runtimeProjectRoot",
  "platform",
  "runtime",
  "environment",
  "host",
  "runner",
] as const;

const runtimeSchema = z.strictObject({
  packageName: z.literal("cisco-ai-skill-scanner"),
  version: z.literal("2.0.13"),
  uvVersion: z.literal("0.12.5"),
  lockSha256: z.literal(LOCK_SHA256),
  wheelSha256: z.literal(WHEEL_SHA256),
});
const platformSchema = z.strictObject({ os: z.literal("linux"), architecture: z.literal("amd64") });
const hostSchema = z.strictObject({
  os: z.enum(["linux", "darwin", "windows"]),
  architecture: z.enum(["amd64", "arm64"]),
});
const dataSchema = z.strictObject({
  protocol: z.literal("CiscoLinuxAmd64ProbeV1"),
  sourceRoot: z.string().min(1).max(4096),
  selectedClosurePaths: z.array(z.string()).min(1).max(100_000),
  runtimeProjectRoot: z.string().min(1).max(4096),
  platform: platformSchema,
  runtime: runtimeSchema,
  environment: z
    .record(z.string(), z.string())
    .refine((value) => Object.keys(value).length <= 32, "environment exceeds bounds"),
  host: hostSchema,
});
type Data = z.infer<typeof dataSchema>;
type Runner = (
  argv: readonly string[],
  options: {
    readonly cwd: string;
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
  },
) => Promise<unknown>;

function fail(message: string): never {
  throw new TypeError(`invalid Cisco Linux amd64 probe: ${message}`);
}

function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`input ${key} must be own data`);
  return descriptor.value;
}

function parseInput(input: unknown): { data: Data; runner: Runner } {
  if (typeof input !== "object" || input === null || Array.isArray(input))
    fail("input must be object");
  if (
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.getOwnPropertySymbols(input).length > 0
  )
    fail("input must be plain data");
  const keys = Object.keys(input);
  if (keys.length !== inputKeys.length || inputKeys.some((key) => !keys.includes(key)))
    fail("input has unknown or missing fields");
  const source = input as object;
  const runner = ownData(source, "runner");
  if (typeof runner !== "function") fail("runner must be injected function");
  const data = Object.fromEntries(
    inputKeys.filter((key) => key !== "runner").map((key) => [key, ownData(source, key)]),
  );
  assertStrictJsonValueV1(data, "Cisco Linux amd64 probe input");
  const parsed = dataSchema.safeParse(data);
  if (!parsed.success) fail(parsed.error.issues[0]?.message ?? "schema");
  const selected = parsed.data.selectedClosurePaths;
  for (const path of selected) assertSafeRelativePosixPathV1(path, "selected closure path");
  if (new Set(selected).size !== selected.length) fail("duplicate selected closure path");
  return { data: parsed.data, runner: runner as Runner };
}

function parseResponse(value: unknown): { code: number; stdout: string; stderr: string } {
  assertStrictJsonValueV1(value, "Cisco Linux amd64 runner response");
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("runner response");
  const response = value as Record<string, unknown>;
  const keys = Object.keys(response);
  const allowed = ["code", "stdout", "stderr", "truncated"];
  if (
    !keys.every((key) => allowed.includes(key)) ||
    !["code", "stdout", "stderr"].every((key) => key in response)
  )
    fail("runner response fields");
  if (
    typeof response.code !== "number" ||
    !Number.isSafeInteger(response.code) ||
    typeof response.stdout !== "string" ||
    typeof response.stderr !== "string" ||
    response.stdout.length > MAX_STDIO_BYTES ||
    response.stderr.length > MAX_STDIO_BYTES ||
    response.truncated === true
  )
    fail("runner response bounds");
  if (response.code !== 0) fail("runner failed");
  return { code: response.code, stdout: response.stdout, stderr: response.stderr };
}

function outputBytes(path: string): Buffer {
  if (!existsSync(path)) fail("SARIF output missing");
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch {
    fail("SARIF output missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_SARIF_BYTES)
    fail("SARIF output invalid");
  const bytes = readFileSync(path);
  if (bytes.length > MAX_SARIF_BYTES) fail("SARIF output exceeds bounded size");
  return bytes;
}

function strictUtf8(bytes: Buffer): string {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail("SARIF output is not UTF-8");
  return text;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value) || seen.has(value))
    return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function sameSeal(left: SourceSealV1, right: SourceSealV1): boolean {
  return (
    left.sourceTreeSha256 === right.sourceTreeSha256 &&
    left.selectedClosureSha256 === right.selectedClosureSha256 &&
    left.sealedSnapshotSha256 === right.sealedSnapshotSha256
  );
}

function sourceFileSha256(snapshot: SealedSourceSnapshotV1): Record<string, string> {
  return Object.fromEntries(snapshot.selectedClosureFiles.map((file) => [file.path, file.sha256]));
}

function compareStrictJson(left: unknown, right: unknown): number {
  return canonicalStrictJsonBytesV1(left).compare(canonicalStrictJsonBytesV1(right));
}

function normalizeSarifSemantics(value: CiscoSarifV1): CiscoSarifV1 {
  const run = value.runs[0];
  if (run === undefined) fail("SARIF run");
  const results = run.results
    .map((result) => ({
      ruleId: result.ruleId,
      ...(result.level === undefined ? {} : { level: result.level }),
      message: { text: result.message.text },
      locations: [...result.locations].sort(compareStrictJson),
    }))
    .sort(compareStrictJson);
  return deepFreeze(
    JSON.parse(
      canonicalStrictJsonBytesV1({
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "cisco-ai-skill-scanner" } }, results }],
      }).toString("utf8"),
    ),
  ) as CiscoSarifV1;
}

function repeatabilitySemantics(factsOnly: {
  readonly facts: unknown;
  readonly coverage: unknown;
  readonly evidenceAnnex: unknown;
}): Buffer {
  return canonicalStrictJsonBytesV1({
    protocol: "CiscoLinuxAmd64RepeatabilityV1",
    facts: factsOnly.facts,
    coverage: factsOnly.coverage,
    evidenceAnnex: factsOnly.evidenceAnnex,
  });
}

// biome-ignore lint/suspicious/noExplicitAny: this internal probe returns a branded, closed runtime record.
export async function probeCiscoLinuxAmd64V1(input: unknown): Promise<any> {
  const { data, runner } = parseInput(input);
  if (data.environment.AIH_SCAN_CISCO_LINUX_AMD64_PROBE !== "1")
    return deepFreeze({
      protocol: "CiscoLinuxAmd64ProbeV1" as const,
      observationScope: "ephemeral" as const,
      kind: "not-run" as const,
      reason: "opt-in-required" as const,
    });
  if (data.host.os !== "linux" || data.host.architecture !== "amd64")
    return deepFreeze({
      protocol: "CiscoLinuxAmd64ProbeV1" as const,
      observationScope: "ephemeral" as const,
      kind: "not-run" as const,
      reason: "linux-amd64-required" as const,
    });

  const sourceInput = {
    sourceRoot: data.sourceRoot,
    selectedClosurePaths: data.selectedClosurePaths,
  };
  const sourceSnapshot = describeNativeObservationSourceV1(sourceInput);
  const sourceSeal = sealNativeObservationSourceV1(sourceInput);
  const executions: unknown[] = [];
  let previousRepeatabilitySemantics: Buffer | undefined;

  for (let ordinal = 0; ordinal < 2; ordinal += 1) {
    const beforeSourceSeal = sealNativeObservationSourceV1(sourceInput);
    if (!sameSeal(sourceSeal, beforeSourceSeal)) fail("source drift before execution");
    const outputDirectory = mkdtempSync(join(tmpdir(), "aih-scan-cisco-linux-amd64-"));
    const outputPath = join(outputDirectory, `execution-${String(ordinal)}.sarif`);
    try {
      const argv = [
        "uv",
        "run",
        "--project",
        data.runtimeProjectRoot,
        "--locked",
        "--isolated",
        "--python",
        "3.12",
        "--offline",
        "--no-python-downloads",
        "--no-env-file",
        "skill-scanner",
        "scan",
        data.sourceRoot,
        "--format",
        "sarif",
        "--output-sarif",
        outputPath,
      ];
      parseResponse(
        await runner(argv, {
          cwd: data.runtimeProjectRoot,
          env: { UV_OFFLINE: "1" },
          timeoutMs: TIMEOUT_MS,
          maxStdoutBytes: MAX_STDIO_BYTES,
          maxStderrBytes: MAX_STDIO_BYTES,
        }),
      );
      const bytes = outputBytes(outputPath);
      const parsedSarif = parseCiscoSarifV1(strictUtf8(bytes), { sourceRoot: data.sourceRoot });
      const normalizedSarif = normalizeSarifSemantics(parsedSarif);
      const afterSourceSeal = sealNativeObservationSourceV1(sourceInput);
      if (!sameSeal(beforeSourceSeal, afterSourceSeal)) fail("source changed during probe");
      const factsOnly = createCiscoFactsOnlyV1({
        protocol: "CiscoFactsOnlyV1",
        sarif: normalizedSarif,
        fileSha256ByPath: sourceFileSha256(sourceSnapshot),
        platform: { os: "linux", architecture: "amd64" },
      });
      const currentRepeatabilitySemantics = repeatabilitySemantics(factsOnly);
      if (
        previousRepeatabilitySemantics !== undefined &&
        !previousRepeatabilitySemantics.equals(currentRepeatabilitySemantics)
      )
        fail("semantic SARIF repeatability mismatch");
      previousRepeatabilitySemantics = currentRepeatabilitySemantics;
      executions.push({
        executionOrdinal: ordinal,
        beforeSourceSeal,
        afterSourceSeal,
        sarifSha256: createHash("sha256").update(bytes).digest("hex"),
        facts: factsOnly.facts,
        annexBytes: Buffer.from(factsOnly.annexBytes),
        evidenceAnnex: factsOnly.evidenceAnnex,
        coverage: factsOnly.coverage,
      });
    } finally {
      rmSync(outputDirectory, { recursive: true, force: true });
    }
  }
  return deepFreeze({
    protocol: "CiscoLinuxAmd64ProbeV1" as const,
    observationScope: "ephemeral" as const,
    platform: { os: "linux" as const, architecture: "amd64" as const },
    runtime: data.runtime,
    sourceSnapshot,
    sourceSeal,
    executions,
  });
}
