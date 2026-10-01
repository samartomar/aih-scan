import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  decodeStrictUtf8V1,
  parseStrictJsonV1,
  StrictJsonBoundErrorV1,
} from "./strict-json.js";

export class ContractError extends TypeError {
  constructor(
    readonly code: "invalid-input" | "resource-limit",
    message: string,
  ) {
    super(message);
  }
}
export function fail(message: string): never {
  throw new ContractError("invalid-input", message);
}
export function hasControl(value: string, includeSpace = false): boolean {
  return [...value].some(
    (character) =>
      character.charCodeAt(0) <= (includeSpace ? 32 : 31) || character.charCodeAt(0) === 127,
  );
}
export function bound(ok: boolean, label: string, limit: number): void {
  if (!ok) throw new ContractError("resource-limit", `${label} exceeds limit ${limit}`);
}
export function assertControlJson(value: unknown): void {
  const pending: { value: unknown; depth: number; exit?: boolean }[] = [{ value, depth: 0 }],
    active = new WeakSet<object>();
  while (pending.length) {
    const item = pending.pop()!;
    if (
      typeof item.value === "number" &&
      (!Number.isSafeInteger(item.value) || item.value < 0 || Object.is(item.value, -0))
    )
      fail("Control numbers must be nonnegative safe integers");
    if (item.value === null || typeof item.value !== "object") continue;
    if (item.exit) {
      active.delete(item.value);
      continue;
    }
    bound(item.depth < 512, "JSON nesting", 512);
    if (active.has(item.value)) fail("Control JSON cannot contain cycles");
    active.add(item.value);
    pending.push({ ...item, exit: true });
    for (const key of Object.keys(item.value)) {
      const descriptor = Object.getOwnPropertyDescriptor(item.value, key);
      if (!descriptor || !("value" in descriptor))
        fail("Control JSON requires own data properties");
      pending.push({ value: descriptor.value, depth: item.depth + 1 });
    }
  }
  assertStrictJsonValueV1(value, "control JSON");
}
export function canonicalBytes(value: unknown): Uint8Array {
  assertControlJson(value);
  return canonicalStrictJsonBytesV1(value);
}
export function strictParse(bytes: Uint8Array, label: string, maxBytes: number): unknown {
  if (!(bytes instanceof Uint8Array)) fail(`${label} must be bytes`);
  bound(bytes.byteLength <= maxBytes, label, maxBytes);
  let value: unknown;
  try {
    value = parseStrictJsonV1(decodeStrictUtf8V1(bytes, label), label);
  } catch (error) {
    if (error instanceof StrictJsonBoundErrorV1)
      throw new ContractError("resource-limit", `JSON number token exceeds limit ${error.limit}`);
    throw error;
  }
  assertControlJson(value);
  return value;
}
export async function sha256(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", copy);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
export async function scanIdFor(bytes: Uint8Array): Promise<`scan:sha256:${string}`> {
  const prefix = new TextEncoder().encode("aih.scan.report.v1\0");
  const input = new Uint8Array(prefix.length + bytes.length);
  input.set(prefix);
  input.set(bytes, prefix.length);
  return `scan:sha256:${await sha256(input)}`;
}
export async function observationIdFor(body: unknown): Promise<`observation:sha256:${string}`> {
  const prefix = new TextEncoder().encode("aih.scan.observation.v1\0"),
    bytes = canonicalBytes(body);
  const input = new Uint8Array(prefix.length + bytes.length);
  input.set(prefix);
  input.set(bytes, prefix.length);
  return `observation:sha256:${await sha256(input)}`;
}
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export function base64Encode(bytes: Uint8Array): string {
  const chunks: string[] = [];
  for (let start = 0; start < bytes.length; start += 12288) {
    let chunk = "";
    for (let at = start; at < Math.min(bytes.length, start + 12288); at += 3) {
      const a = bytes[at] ?? 0,
        b = bytes[at + 1] ?? 0,
        c = bytes[at + 2] ?? 0;
      chunk +=
        alphabet[a >> 2] +
        alphabet[((a & 3) << 4) | (b >> 4)]! +
        (at + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : "=") +
        (at + 2 < bytes.length ? alphabet[c & 63] : "=");
    }
    chunks.push(chunk);
  }
  return chunks.join("");
}
export function base64Decode(text: string, maxBytes: number): Uint8Array {
  if (typeof text !== "string") fail("Base64 must be a string");
  bound(text.length <= Math.ceil(maxBytes / 3) * 4, "base64 decoded bytes", maxBytes);
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  if (text.length % 4 !== 0 || (text.length === 0 && padding !== 0)) fail("Noncanonical base64");
  for (let at = 0; at < text.length; at++) {
    if (at >= text.length - padding) {
      if (text[at] !== "=") fail("Noncanonical base64 padding");
    } else if (alphabet.indexOf(text[at]!) < 0) fail("Noncanonical base64 alphabet");
  }
  if (
    (padding === 2 && (alphabet.indexOf(text[text.length - 3]!) & 15) !== 0) ||
    (padding === 1 && (alphabet.indexOf(text[text.length - 2]!) & 3) !== 0)
  )
    fail("Noncanonical base64 pad bits");
  const length = (text.length / 4) * 3 - padding;
  bound(length <= maxBytes, "base64 decoded bytes", maxBytes);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (let at = 0; at < text.length; at += 4) {
    const a = alphabet.indexOf(text[at]!),
      b = alphabet.indexOf(text[at + 1]!),
      c = alphabet.indexOf(text[at + 2]!),
      d = alphabet.indexOf(text[at + 3]!);
    bytes[offset++] = (a << 2) | (b >> 4);
    if (offset < length) bytes[offset++] = ((b & 15) << 4) | (c >> 2);
    if (offset < length) bytes[offset++] = ((c & 3) << 6) | d;
  }
  return bytes;
}
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, at) => byte === right[at]);
}
export function errorDiagnostic(error: unknown): { code: string; detail: string } {
  return {
    code: error instanceof ContractError ? error.code : "invalid-input",
    detail:
      error instanceof ContractError
        ? error.message
        : "The supplied data violates the supported contract or resource bounds.",
  };
}
