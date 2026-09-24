import { createHash } from "node:crypto";

export function codeUnitCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

const object = (value: unknown): value is object => typeof value === "object" && value !== null;
const hasControl = (value: string) =>
  [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
const own = (value: object, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor))
    throw new TypeError("canonical JSON requires own data properties");
  return descriptor.value;
};

export function assertWellFormedNfcV1(value: string, label: string, requireNfc = true): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new TypeError(`${label} contains malformed Unicode`);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff)
      throw new TypeError(`${label} contains malformed Unicode`);
  }
  if (requireNfc && value.normalize("NFC") !== value)
    throw new TypeError(`${label} must already be NFC`);
}

export function assertStrictJsonValueV1<T>(
  value: T,
  label: string,
  requireNfc = true,
  active = new WeakSet<object>(),
): T {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    assertWellFormedNfcV1(value, label, requireNfc);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0))
      throw new TypeError(`${label} numbers must be finite and not negative zero`);
    return value;
  }
  if (!object(value)) throw new TypeError(`${label} does not support ${typeof value}`);
  if (active.has(value)) throw new TypeError(`${label} must not contain a cycle`);
  active.add(value);
  if (Object.getOwnPropertySymbols(value).length > 0)
    throw new TypeError(`${label} must not contain symbol properties`);
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      Object.keys(value).some((key) => !/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)
    )
      throw new TypeError(`${label} has an unsupported array shape`);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor))
        throw new TypeError(`${label} arrays must not contain holes/accessors`);
      assertStrictJsonValueV1(descriptor.value, `${label}[${String(index)}]`, requireNfc, active);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      throw new TypeError(`${label} has an unsupported object prototype`);
    for (const key of Object.keys(value)) {
      assertWellFormedNfcV1(key, `${label} key`, requireNfc);
      assertStrictJsonValueV1(own(value, key), `${label}.${key}`, requireNfc, active);
    }
  }
  active.delete(value);
  return value;
}

export function deepFreezeStrictJsonV1<T>(value: T, seen = new WeakSet<object>()): T {
  if (!object(value) || seen.has(value)) return value;
  seen.add(value);
  for (const key of Object.keys(value)) deepFreezeStrictJsonV1(own(value, key), seen);
  return Object.freeze(value);
}

/** The deepest array/object nesting a strict JSON text may use. */
export const STRICT_JSON_MAX_DEPTH_V1 = 512;

const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * S2h: the text of analyzer bytes, only when they are well-formed UTF-8. A lossy decode would
 * repair an invalid sequence to U+FFFD; this throws instead. A leading BOM is kept, so the
 * strict parser refuses it rather than a decoder silently dropping it.
 */
export function decodeStrictUtf8V1(bytes: Uint8Array, label: string): string {
  try {
    return UTF8_FATAL.decode(bytes);
  } catch {
    throw new TypeError(`${label} is not well-formed UTF-8`);
  }
}

const NUMBER = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/y;
const ESCAPES: Readonly<Record<string, string>> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

/**
 * S2h (review of S2g): one RFC 8259 parser for every JSON text Scan reads, above all analyzer
 * output. `JSON.parse` keeps the last of two equal keys, so a later `executionSuccessful` or
 * `properties` could hide a failure or erase a forged key. This parser refuses, at any depth:
 * a repeated key (compared after unescaping); any byte outside the one JSON value (a BOM,
 * trailing data, a second value); whitespace other than space, tab, LF and CR; a control
 * character inside a string; an invalid escape; a number `JSON.parse` would change (overflow
 * to infinity, underflow of a non-zero literal to zero, an integer literal beyond the safe
 * integer range) or negative zero; malformed Unicode; nesting deeper than
 * {@link STRICT_JSON_MAX_DEPTH_V1}. A `__proto__` key is kept as an own data property, never a
 * prototype. Strings and keys must be NFC unless `requireNfc` is `false`.
 */
export function parseStrictJsonV1(
  text: string,
  label: string,
  options: Readonly<{ requireNfc?: boolean }> = {},
): unknown {
  const requireNfc = options.requireNfc ?? true;
  assertWellFormedNfcV1(text, `${label} JSON text`, requireNfc);
  let at = 0;
  const invalid = (reason: string): never => {
    throw new TypeError(`invalid JSON ${label}: ${reason} at offset ${String(at)}`);
  };
  const space = () => {
    for (let code = text.charCodeAt(at); ; code = text.charCodeAt(at)) {
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) at += 1;
      else return;
    }
  };
  const string = (): string => {
    at += 1;
    let value = "";
    let start = at;
    for (;;) {
      if (at >= text.length) return invalid("an unterminated string");
      const code = text.charCodeAt(at);
      if (code === 0x22) {
        value += text.slice(start, at);
        at += 1;
        return value;
      }
      if (code < 0x20) return invalid("a control character in a string");
      if (code !== 0x5c) {
        at += 1;
        continue;
      }
      value += text.slice(start, at);
      const escaped = text[at + 1] ?? "";
      if (escaped === "u") {
        const hex = text.slice(at + 2, at + 6);
        if (!/^[0-9A-Fa-f]{4}$/.test(hex)) return invalid("an invalid \\u escape");
        value += String.fromCharCode(Number.parseInt(hex, 16));
        at += 6;
      } else {
        const decoded = ESCAPES[escaped];
        if (decoded === undefined) return invalid("an invalid escape");
        value += decoded;
        at += 2;
      }
      start = at;
    }
  };
  const number = (): number => {
    NUMBER.lastIndex = at;
    const match = NUMBER.exec(text);
    if (match === null) return invalid("an unexpected character");
    const lexeme = match[0];
    const value = Number(lexeme);
    if (!Number.isFinite(value)) return invalid("a number beyond the double range");
    if (value === 0 && /[1-9]/.test(lexeme.split(/[eE]/)[0] ?? ""))
      return invalid("a non-zero number that underflows to zero");
    if (match[1] === undefined && match[2] === undefined && !Number.isSafeInteger(value))
      return invalid("an integer beyond the safe integer range");
    at += lexeme.length;
    return value;
  };
  const literal = (word: string, value: boolean | null): boolean | null => {
    if (text.startsWith(word, at)) {
      at += word.length;
      return value;
    }
    return invalid("an unexpected character");
  };
  const value = (depth: number): unknown => {
    space();
    const code = text.charCodeAt(at);
    if (code === 0x7b || code === 0x5b) {
      if (depth >= STRICT_JSON_MAX_DEPTH_V1) return invalid("nesting beyond the bound");
      return code === 0x7b ? objectValue(depth + 1) : arrayValue(depth + 1);
    }
    if (code === 0x22) return string();
    if (code === 0x74) return literal("true", true);
    if (code === 0x66) return literal("false", false);
    if (code === 0x6e) return literal("null", null);
    if (Number.isNaN(code)) return invalid("an unexpected end of text");
    return number();
  };
  const objectValue = (depth: number): Record<string, unknown> => {
    at += 1;
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    space();
    if (text.charCodeAt(at) === 0x7d) {
      at += 1;
      return result;
    }
    for (;;) {
      space();
      if (text.charCodeAt(at) !== 0x22) return invalid("an object key that is not a string");
      const key = string();
      if (keys.has(key)) throw new TypeError(`${label} has a duplicate JSON object key: ${key}`);
      keys.add(key);
      space();
      if (text.charCodeAt(at) !== 0x3a) return invalid("a missing ':'");
      at += 1;
      // Defined, never assigned: a "__proto__" key stays own data instead of a prototype.
      Object.defineProperty(result, key, {
        value: value(depth),
        writable: true,
        enumerable: true,
        configurable: true,
      });
      space();
      const next = text.charCodeAt(at);
      at += 1;
      if (next === 0x7d) return result;
      if (next !== 0x2c) {
        at -= 1;
        return invalid("a missing ',' or '}'");
      }
    }
  };
  const arrayValue = (depth: number): unknown[] => {
    at += 1;
    const result: unknown[] = [];
    space();
    if (text.charCodeAt(at) === 0x5d) {
      at += 1;
      return result;
    }
    for (;;) {
      result.push(value(depth));
      space();
      const next = text.charCodeAt(at);
      at += 1;
      if (next === 0x5d) return result;
      if (next !== 0x2c) {
        at -= 1;
        return invalid("a missing ',' or ']'");
      }
    }
  };
  const parsed = value(0);
  space();
  if (at !== text.length) invalid("data after the JSON value");
  return assertStrictJsonValueV1(parsed, label, requireNfc);
}

/** {@link parseStrictJsonV1} of a text whose root must be an object. */
export function parseStrictJsonObjectV1(
  text: string,
  label: string,
  options: Readonly<{ requireNfc?: boolean }> = {},
): Record<string, unknown> {
  const parsed = parseStrictJsonV1(text, label, options);
  if (!object(parsed) || Array.isArray(parsed))
    throw new TypeError(`${label} JSON root must be an object`);
  return parsed as Record<string, unknown>;
}

function canonical(value: unknown): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  )
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (object(value))
    return `{${Object.keys(value)
      .sort(codeUnitCompare)
      .map((key) => `${JSON.stringify(key)}:${canonical(own(value, key))}`)
      .join(",")}}`;
  throw new TypeError("unsupported canonical JSON");
}
export function canonicalStrictJsonBytesV1(value: unknown): Buffer {
  assertStrictJsonValueV1(value, "canonical JSON");
  return Buffer.from(canonical(value), "utf8");
}
export function canonicalStrictJsonSha256V1(value: unknown): string {
  return createHash("sha256").update(canonicalStrictJsonBytesV1(value)).digest("hex");
}
export function assertSafeRelativePosixPathV1(path: string, label: string): string {
  assertWellFormedNfcV1(path, label);
  if (
    !path ||
    path.startsWith("/") ||
    /^[A-Za-z]:/.test(path) ||
    /[\\%?#:]/.test(path) ||
    hasControl(path) ||
    path.endsWith("/") ||
    path.split("/").some((part) => !part || part === "." || part === "..")
  )
    throw new TypeError(`${label} must be a safe relative POSIX path`);
  return path;
}
