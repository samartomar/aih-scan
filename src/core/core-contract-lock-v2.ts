import { createHash } from "node:crypto";

export const AI_HARNESS_STRICT_V2_COMMIT = "74ddf3439df47a947a6f7a022515099602702ac8";
export const AI_HARNESS_DECISION_V2_SCHEMA_SHA256 =
  "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff";
export const AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256 =
  "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc";

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
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
    fail(`${key} must be own enumerable data`);
  return descriptor.value;
}
function exactOwnDataFields(value: object, fields: readonly string[], label: string): void {
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  )
    fail(`${label} fields`);
  for (const field of fields) ownData(value, field);
}

function parseInput(value: unknown): SchemaLockInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  exactOwnDataFields(value, ["coreCommit", "schemaBytes", "expectedSchemaSha256"], "input");
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
  exactOwnDataFields(value, ["coreCommit", "schemaBytes"], "input");
  verifyCoreDecisionSchemaLockV2({
    coreCommit: ownData(value, "coreCommit"),
    schemaBytes: ownData(value, "schemaBytes"),
    expectedSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  });
}

/** Validates the exact Core-owned organization-evidence schema required by Scanner projection. */
export function verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1(value: unknown): void {
  const input = parseInput(value);
  if (input.coreCommit !== AI_HARNESS_STRICT_V2_COMMIT) fail("unexpected Core commit");
  if (input.expectedSchemaSha256 !== AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256)
    fail("unexpected organization evidence schema digest");
  const digest = createHash("sha256").update(input.schemaBytes).digest("hex");
  if (digest !== input.expectedSchemaSha256) fail("schema digest mismatch");
}

/**
 * Locks both Core artifacts used by Scanner: its existing V2 decision contract
 * and the Core-owned organization-evidence envelope consumed after verification.
 */
export function verifyAiHarnessCoreEvidenceContractV1(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  exactOwnDataFields(
    value,
    ["coreCommit", "decisionSchemaBytes", "organizationEvidenceEnvelopeSchemaBytes"],
    "input",
  );
  const coreCommit = ownData(value, "coreCommit");
  verifyCoreDecisionSchemaLockV2({
    coreCommit,
    schemaBytes: ownData(value, "decisionSchemaBytes"),
    expectedSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  });
  verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
    coreCommit,
    schemaBytes: ownData(value, "organizationEvidenceEnvelopeSchemaBytes"),
    expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  });
}
