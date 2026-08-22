import { createHash } from "node:crypto";

export const AI_HARNESS_STRICT_V2_COMMIT = "e27a55dcebb635c8298aa4fd6fd871f59089bcf7";
export const AI_HARNESS_DECISION_V2_SCHEMA_SHA256 =
  "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff";

type SchemaLockInput = {
  readonly coreCommit: string;
  readonly schemaBytes: Uint8Array;
  readonly expectedSchemaSha256: string;
};

function fail(reason: string): never {
  throw new TypeError(`invalid Core Strict V2 compatibility lock: ${reason}`);
}

function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`${key} must be own data`);
  return descriptor.value;
}

function parseInput(value: unknown): SchemaLockInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  const keys = Object.keys(value);
  if (
    keys.length !== 3 ||
    !keys.includes("coreCommit") ||
    !keys.includes("schemaBytes") ||
    !keys.includes("expectedSchemaSha256")
  )
    fail("input fields");
  const coreCommit = ownData(value, "coreCommit");
  const schemaBytes = ownData(value, "schemaBytes");
  const expectedSchemaSha256 = ownData(value, "expectedSchemaSha256");
  if (
    typeof coreCommit !== "string" ||
    !/^[0-9a-f]{40}$/.test(coreCommit) ||
    typeof expectedSchemaSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(expectedSchemaSha256) ||
    (!Buffer.isBuffer(schemaBytes) && !(schemaBytes instanceof Uint8Array)) ||
    schemaBytes.byteLength === 0 ||
    schemaBytes.byteLength > 2 * 1024 * 1024
  )
    fail("input values");
  return { coreCommit, schemaBytes, expectedSchemaSha256 };
}

/** Validates a caller-declared immutable schema lock without performing I/O. */
export function verifyCoreDecisionSchemaLockV2(value: unknown): void {
  const input = parseInput(value);
  if (input.coreCommit !== AI_HARNESS_STRICT_V2_COMMIT) fail("unexpected Core commit");
  const digest = createHash("sha256").update(input.schemaBytes).digest("hex");
  if (digest !== input.expectedSchemaSha256) fail("schema digest mismatch");
}

/**
 * The scanner's canonical compatibility gate. Callers cannot select a different
 * Core schema digest or commit: an unknown, old, or changed Core artifact fails.
 */
export function verifyAiHarnessStrictV2Contract(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes("coreCommit") || !keys.includes("schemaBytes"))
    fail("input fields");
  verifyCoreDecisionSchemaLockV2({
    coreCommit: ownData(value, "coreCommit"),
    schemaBytes: ownData(value, "schemaBytes"),
    expectedSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  });
}
