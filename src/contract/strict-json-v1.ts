import { createHash } from "node:crypto";
import { canonicalStrictJsonBytesV1 as portableCanonicalBytes } from "../assessment/strict-json.js";

export * from "../assessment/strict-json.js";
export function canonicalStrictJsonBytesV1(value: unknown): Buffer {
  return Buffer.from(portableCanonicalBytes(value));
}
export function canonicalStrictJsonSha256V1(value: unknown): string {
  return createHash("sha256").update(canonicalStrictJsonBytesV1(value)).digest("hex");
}
