import { base64Decode, canonicalBytes } from "../assessment/json.js";
import { assertWellFormedNfcV1 } from "../assessment/strict-json.js";
import type { AssociationReason } from "./types.js";

export const artifactLimits = {
  artifact: 96 * 1024 * 1024,
  report: 16 * 1024 * 1024,
  annex: 16 * 1024 * 1024,
  decoded: 64 * 1024 * 1024,
  statement: 128 * 1024,
  attestation: 1024 * 1024,
  certificate: 32 * 1024,
  signature: 1024,
  trust: 1024 * 1024,
} as const;
export type ConstructionCode =
  | "invalid-input"
  | "resource-limit"
  | "unsupported-artifact"
  | "already-attested"
  | "signing-failed";
export class ArtifactError extends Error {
  constructor(
    public readonly code: ConstructionCode,
    public readonly reason: AssociationReason = "malformed",
  ) {
    super(`Scan artifact ${code}.`);
    this.name = "ArtifactError";
  }
}
export function invalid(reason: AssociationReason = "malformed"): never {
  throw new ArtifactError("invalid-input", reason);
}
export function limited(): never {
  throw new ArtifactError("resource-limit", "resource-limit");
}
export function unsupported(): never {
  throw new ArtifactError("unsupported-artifact", "unsupported-artifact");
}
export function object(
  value: unknown,
  required: string[],
  optional: string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) invalid();
  if (Object.getOwnPropertySymbols(value).length !== 0) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.values(descriptors).some(
      (descriptor) => !Object.hasOwn(descriptor, "value") || !descriptor.enumerable,
    )
  )
    invalid();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    required.some((key) => !Object.hasOwn(record, key)) ||
    keys.some((key) => !required.includes(key) && !optional.includes(key))
  )
    invalid();
  return record;
}
export function array(value: unknown, maximum = Number.MAX_SAFE_INTEGER): unknown[] {
  if (!Array.isArray(value)) invalid();
  if (value.length > maximum) limited();
  if (
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).length !== value.length + 1) invalid();
  for (let index = 0; index < value.length; index++) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) invalid();
  }
  return value;
}
export function text(value: unknown, maximum = 256, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) invalid();
  assertWellFormedNfcV1(value, "artifact string");
  if (new TextEncoder().encode(value).length > maximum) limited();
  return value;
}
export function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    Object.is(value, -0)
  )
    invalid();
  if (value > maximum) limited();
  return value;
}
export function digest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) invalid();
  return value;
}
export function validScanId(value: unknown): string {
  if (typeof value !== "string" || !/^scan:sha256:[0-9a-f]{64}$/.test(value)) invalid();
  return value;
}
export function decoded(value: unknown, maximum: number, exact?: number): Uint8Array {
  const raw = text(value, Math.ceil(maximum / 3) * 4, true);
  // The decoder verifies canonical padding and unused bits before allocation.
  const bytes = base64Decode(raw, maximum);
  if (exact !== undefined && bytes.length !== exact) invalid();
  return bytes;
}
export function boundedJson(value: unknown, maximum: number): void {
  if (canonicalBytes(value).length > maximum) limited();
}
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
export function uint64(value: unknown, dateSeconds = false): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) invalid();
  const number = BigInt(value);
  if (number > 18446744073709551615n) invalid();
  // Upstream takes strings for indices; integrated time enters Date arithmetic.
  if (dateSeconds && (number > BigInt(Number.MAX_SAFE_INTEGER) / 1000n || number > 8640000000000n))
    invalid();
  return value;
}
