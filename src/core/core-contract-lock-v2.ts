import { createHash } from "node:crypto";

/**
 * Which Core contracts this Scanner accepts, as a declared SET rather than one value.
 *
 * Core's governance-decision schema changed additively between these two commits, so a
 * single pinned digest made the gate pass forever against one old Core while newer Core
 * artifacts were unrecognised. Re-pinning to the new digest alone would have silently
 * stopped accepting evidence that is still valid, so both are accepted and the newest is
 * the value a fresh candidate declares.
 *
 * Newest last. Accepting a digest is not approving a Core release: it states only that
 * Scanner knows this contract and can read evidence produced against it.
 */
export const AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED = [
  "6130dd837b8e8bd41e999fb40733e0e460e69720",
  "c31741602b3dbd5f228dafe00591e5679c782878",
] as const;
export const AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED = [
  "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
  "7fdf101568cd7caa28516d0be37704c0dfd51198bc54d41d65829abbe77547cc",
] as const;

/** The default emitted values: the newest accepted pair. */
export const AI_HARNESS_STRICT_V2_COMMIT: string = AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED[1];
export const AI_HARNESS_DECISION_V2_SCHEMA_SHA256: string =
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED[1];

/** Unchanged at every accepted Core commit, so it stays a single pinned digest. */
export const AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256 =
  "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc";

/** True only for a Core commit this Scanner declares it can read evidence against. */
export function isAcceptedAiHarnessStrictV2CommitV2(value: unknown): boolean {
  return (
    typeof value === "string" &&
    (AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED as readonly string[]).includes(value)
  );
}

/** True only for a Core decision-schema digest this Scanner declares it can read. */
export function isAcceptedCoreDecisionSchemaSha256V2(value: unknown): boolean {
  return (
    typeof value === "string" &&
    (AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED as readonly string[]).includes(value)
  );
}

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

/**
 * Validates a caller-declared immutable schema lock without performing I/O.
 *
 * A commit outside the accepted set is `"unexpected Core commit"`; a digest outside the
 * accepted set, or bytes that do not hash to the declared digest, is
 * `"schema digest mismatch"`. Membership is not a range: a third value is refused.
 */
export function verifyCoreDecisionSchemaLockV2(value: unknown): void {
  const input = parseInput(value);
  if (!isAcceptedAiHarnessStrictV2CommitV2(input.coreCommit)) fail("unexpected Core commit");
  if (!isAcceptedCoreDecisionSchemaSha256V2(input.expectedSchemaSha256))
    fail("schema digest mismatch");
  const digest = createHash("sha256").update(input.schemaBytes).digest("hex");
  if (digest !== input.expectedSchemaSha256) fail("schema digest mismatch");
}

function observedSchemaSha256(schemaBytes: unknown): string {
  if (
    (!Buffer.isBuffer(schemaBytes) && !(schemaBytes instanceof Uint8Array)) ||
    schemaBytes.byteLength === 0 ||
    schemaBytes.byteLength > 2 * 1024 * 1024
  )
    fail("input values");
  return createHash("sha256").update(schemaBytes).digest("hex");
}

/**
 * The scanner's canonical compatibility gate. Callers cannot select a Core schema
 * digest or commit: the digest is observed from the supplied bytes and both it and the
 * commit must be members of the accepted sets, so an unknown or changed Core artifact
 * fails while an older accepted Core still passes.
 */
export function verifyAiHarnessStrictV2Contract(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  exactOwnDataFields(value, ["coreCommit", "schemaBytes"], "input");
  const schemaBytes = ownData(value, "schemaBytes");
  verifyCoreDecisionSchemaLockV2({
    coreCommit: ownData(value, "coreCommit"),
    schemaBytes,
    expectedSchemaSha256: observedSchemaSha256(schemaBytes),
  });
}

/** Validates the exact Core-owned organization-evidence schema required by Scanner projection. */
export function verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1(value: unknown): void {
  const input = parseInput(value);
  if (!isAcceptedAiHarnessStrictV2CommitV2(input.coreCommit)) fail("unexpected Core commit");
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
  const decisionSchemaBytes = ownData(value, "decisionSchemaBytes");
  verifyCoreDecisionSchemaLockV2({
    coreCommit,
    schemaBytes: decisionSchemaBytes,
    expectedSchemaSha256: observedSchemaSha256(decisionSchemaBytes),
  });
  verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
    coreCommit,
    schemaBytes: ownData(value, "organizationEvidenceEnvelopeSchemaBytes"),
    expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  });
}
