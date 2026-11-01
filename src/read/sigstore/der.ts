/**
 * Minimal strict DER reader (definite lengths only) for the offline Sigstore verifier.
 * Adapted in spirit from @sigstore/core's ASN.1 reader (Apache-2.0, The Sigstore Authors),
 * rewritten over Uint8Array.
 */
import { concat, fail } from "./bytes.js";

export interface Der {
  /** The full identifier octet (class, constructed bit and low tag number). */
  readonly tag: number;
  /** The element's complete encoding (tag, length and value). */
  readonly raw: Uint8Array;
  /** The content octets. */
  readonly value: Uint8Array;
  /** Children when constructed. */
  readonly children: readonly Der[];
}

export const TAG = Object.freeze({
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  utf8String: 0x0c,
  printableString: 0x13,
  ia5String: 0x16,
  utcTime: 0x17,
  generalizedTime: 0x18,
  sequence: 0x30,
  set: 0x31,
});

const MAX_DEPTH = 32;

function parseAt(bytes: Uint8Array, offset: number, depth: number): { node: Der; end: number } {
  if (depth > MAX_DEPTH) fail("ASN.1 nesting is too deep");
  if (offset + 2 > bytes.length) fail("truncated ASN.1");
  const tag = bytes[offset] as number;
  if ((tag & 0x1f) === 0x1f) fail("high ASN.1 tag numbers are not supported");
  let length = bytes[offset + 1] as number;
  let cursor = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) fail("unsupported ASN.1 length");
    if (cursor + count > bytes.length) fail("truncated ASN.1 length");
    length = 0;
    for (let index = 0; index < count; index += 1)
      length = length * 256 + (bytes[cursor + index] as number);
    if (length < 128 || (count > 1 && bytes[cursor] === 0)) fail("non-minimal ASN.1 length");
    cursor += count;
  }
  const end = cursor + length;
  if (end > bytes.length) fail("truncated ASN.1 value");
  const value = bytes.subarray(cursor, end);
  const children: Der[] = [];
  if (tag & 0x20) {
    let inner = 0;
    while (inner < value.length) {
      const child = parseAt(value, inner, depth + 1);
      children.push(child.node);
      inner = child.end;
    }
  }
  return {
    node: Object.freeze({ tag, raw: bytes.subarray(offset, end), value, children }),
    end,
  };
}

/** Parses exactly one DER element covering all of `bytes`. */
export function parseDer(bytes: Uint8Array): Der {
  const { node, end } = parseAt(bytes, 0, 0);
  if (end !== bytes.length) fail("trailing bytes after ASN.1");
  return node;
}

export function expectTag(node: Der | undefined, tag: number, label: string): Der {
  if (node === undefined || node.tag !== tag) return fail(`malformed ${label}`);
  return node;
}

export function oidOf(node: Der | undefined): string {
  const value = expectTag(node, TAG.oid, "object identifier").value;
  if (value.length === 0) fail("empty object identifier");
  const first = value[0] as number;
  const arcs: number[] = [
    first < 80 ? Math.floor(first / 40) : 2,
    first < 80 ? first % 40 : first - 80,
  ];
  let current = 0;
  for (let index = 1; index < value.length; index += 1) {
    const byte = value[index] as number;
    current = current * 128 + (byte & 0x7f);
    if (current > Number.MAX_SAFE_INTEGER) fail("object identifier arc is too large");
    if ((byte & 0x80) === 0) {
      arcs.push(current);
      current = 0;
    }
  }
  if ((value[value.length - 1] as number) & 0x80) fail("truncated object identifier");
  return arcs.join(".");
}

/** Unsigned value of a DER INTEGER (leading zero removed). */
export function integerBytes(node: Der | undefined): Uint8Array {
  const value = expectTag(node, TAG.integer, "integer").value;
  if (value.length === 0) fail("empty integer");
  return value[0] === 0 && value.length > 1 ? value.subarray(1) : value;
}

export function smallInteger(node: Der | undefined): number {
  const value = integerBytes(node);
  if (value.length > 6) fail("integer is too large");
  let out = 0;
  for (const byte of value) out = out * 256 + byte;
  return out;
}

/** Content of a BIT STRING with no unused bits. */
export function bitStringBytes(node: Der | undefined): Uint8Array {
  const value = expectTag(node, TAG.bitString, "bit string").value;
  if (value.length === 0 || value[0] !== 0) fail("bit string has unused bits");
  return value.subarray(1);
}

const TIME = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/;

/** Milliseconds since the epoch of a UTCTime or GeneralizedTime. */
export function timeOf(node: Der | undefined): number {
  if (node === undefined || (node.tag !== TAG.utcTime && node.tag !== TAG.generalizedTime))
    return fail("malformed time");
  const text = String.fromCharCode(...node.value);
  const match = TIME.exec(text);
  if (match === null) return fail("malformed time");
  const [, y, mo, d, h, mi, s, fraction] = match;
  let year = Number(y);
  if (node.tag === TAG.utcTime) {
    if ((y as string).length !== 2 || fraction !== undefined) fail("malformed UTCTime");
    year += year >= 50 ? 1900 : 2000;
  } else if ((y as string).length !== 4) fail("malformed GeneralizedTime");
  const millis = fraction === undefined ? 0 : Math.floor(Number(`0.${fraction}`) * 1000);
  const time = Date.UTC(year, Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), millis);
  const check = new Date(time);
  if (check.getUTCDate() !== Number(d) || check.getUTCMonth() !== Number(mo) - 1)
    fail("invalid date");
  return time;
}

/** Re-encodes a constructed element with the given children (used to drop the SCT extension). */
export function encode(tag: number, ...content: Uint8Array[]): Uint8Array {
  const value = concat(...content);
  const length = value.length;
  let header: number[];
  if (length < 128) header = [tag, length];
  else if (length < 256) header = [tag, 0x81, length];
  else if (length < 65536) header = [tag, 0x82, length >> 8, length & 0xff];
  else header = [tag, 0x83, length >> 16, (length >> 8) & 0xff, length & 0xff];
  return concat(Uint8Array.from(header), value);
}
