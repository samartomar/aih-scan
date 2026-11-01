/**
 * Portable byte helpers for the offline Sigstore verifier (no Node globals, no atob/btoa).
 */

/** An evidence or proof failure; the public verifier maps it to a returned result. */
export class EvidenceError extends Error {
  constructor(
    readonly reason: "invalid-signature" | "unsupported-profile" | "unsupported-algorithm",
    detail: string,
  ) {
    super(detail);
  }
}

export const fail = (detail: string): never => {
  throw new EvidenceError("invalid-signature", detail);
};

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const DECODE = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));
const URL_SAFE = new Map<string, number>([
  ["-", 62],
  ["_", 63],
]);

/**
 * Decodes standard base64 (padding optional, also accepting the URL-safe alphabet as protobuf
 * JSON does). Returns undefined for anything else, including whitespace.
 */
export function base64Decode(value: unknown, maxBytes = 16 * 1024 * 1024): Uint8Array | undefined {
  if (typeof value !== "string") return undefined;
  let text = value;
  while (text.endsWith("=")) text = text.slice(0, -1);
  if (value.length - text.length > 2 || text.length % 4 === 1) return undefined;
  if ((text.length * 3) / 4 > maxBytes) return undefined;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const character of text) {
    const sextet = DECODE.get(character) ?? URL_SAFE.get(character);
    if (sextet === undefined) return undefined;
    buffer = (buffer << 6) | sextet;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) return undefined;
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index] as number;
    const b = bytes[index + 1];
    const c = bytes[index + 2];
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += ALPHABET[(triple >> 18) & 63];
    out += ALPHABET[(triple >> 12) & 63];
    out += b === undefined ? "=" : ALPHABET[(triple >> 6) & 63];
    out += c === undefined ? "=" : ALPHABET[triple & 63];
  }
  return out;
}

export function hexOf(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function hexDecode(value: unknown): Uint8Array | undefined {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value))
    return undefined;
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1)
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return out;
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= (left[index] as number) ^ (right[index] as number);
  return difference === 0;
}

const encoder = new TextEncoder();
export const utf8 = (value: string): Uint8Array => encoder.encode(value);
const strictDecoder = new TextDecoder("utf-8", { fatal: true });
export function utf8Text(bytes: Uint8Array): string | undefined {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return undefined;
  }
}

/** Decodes the first PEM CERTIFICATE block, or undefined. */
export function pemCertificate(text: string): Uint8Array | undefined {
  const match =
    /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+?)\r?\n?-----END CERTIFICATE-----\r?\n?$/.exec(
      text,
    );
  if (match === null) return undefined;
  return base64Decode((match[1] as string).replace(/\r?\n/g, ""));
}

/** Big-endian unsigned integer of up to 8 bytes. */
export function uintOf(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
