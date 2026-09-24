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

/** S2i: how the double a JSON number text names would differ from the text's value. */
export type StrictJsonNumberLossV1 = "overflow" | "underflow" | "rounded" | "negative-zero";

/**
 * S2i (review of S2h): the typed refusal of a JSON number text whose exact decimal value no
 * double carries without loss, whatever its spelling. It is a `TypeError`, so every caller
 * that maps a malformed analyzer text to a failure maps this one too.
 */
export class StrictJsonNumberErrorV1 extends TypeError {
  readonly lexeme: string;
  readonly loss: StrictJsonNumberLossV1;
  constructor(message: string, lexeme: string, loss: StrictJsonNumberLossV1) {
    super(message);
    this.name = "StrictJsonNumberErrorV1";
    this.lexeme = lexeme;
    this.loss = loss;
  }
}

/**
 * The exact value of a decimal number text (a JSON lexeme, or a JavaScript number's own
 * spelling): its sign, its significant digits without a leading or trailing zero (none for
 * zero) and the power of ten they are scaled by. Every spelling of one value gives one decimal.
 */
type ExactDecimal = Readonly<{ negative: boolean; digits: string; exponent: number }>;

function exactDecimal(text: string): ExactDecimal {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/u.exec(text);
  if (match === null) throw new TypeError(`not a decimal number: ${text}`);
  const [, sign, whole = "", fraction = "", scale = "0"] = match;
  const all = `${whole}${fraction}`.replace(/^0+/u, "");
  const digits = all.replace(/0+$/u, "");
  const exponent =
    digits === "" ? 0 : Number.parseInt(scale, 10) - fraction.length + (all.length - digits.length);
  return { negative: sign === "-", digits, exponent };
}

const sameDecimal = (left: ExactDecimal, right: ExactDecimal) =>
  left.negative === right.negative &&
  left.digits === right.digits &&
  left.exponent === right.exponent;

/** The exact decimal value of a finite double that is not an integer. */
function exactDecimalOfFraction(value: number): ExactDecimal {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  const biased = Number((bits >> 52n) & 0x7ffn);
  const fraction = bits & 0xfffffffffffffn;
  // value = mantissa * 2^-shift = mantissa * 5^shift * 10^-shift, with shift > 0 here.
  const mantissa = biased === 0 ? fraction : fraction | (1n << 52n);
  const shift = 1075 - (biased === 0 ? 1 : biased);
  const decimal = exactDecimal((mantissa * 5n ** BigInt(shift)).toString());
  return { negative: value < 0, digits: decimal.digits, exponent: decimal.exponent - shift };
}

/**
 * S2i (review of S2h): the one number policy of {@link parseStrictJsonV1}. It decides on the
 * text's exact decimal value, never on its spelling (a fraction, an exponent, leading or
 * trailing zeros), and accepts the double only when it carries that value without loss:
 * - an integer value must be exactly the double (compared as a `BigInt`), so
 *   9007199254740992 is accepted in every spelling and 9007199254740993 is refused in every
 *   spelling, as is `1e23`, which no double holds;
 * - any other value must be exactly the double, or the double's shortest round-trip decimal
 *   (`0.1`), so re-serializing the parsed number names the value the text named;
 * - overflow to infinity, a non-zero value underflowing to zero, and negative zero are
 *   refused too.
 * Returns the loss, or `undefined` when there is none.
 */
function numberLossV1(lexeme: string, value: number): StrictJsonNumberLossV1 | undefined {
  // The common case: a plain integer of at most 15 digits is always exactly a double.
  if (/^-?(?:0|[1-9]\d{0,14})$/u.test(lexeme)) return lexeme === "-0" ? "negative-zero" : undefined;
  const decimal = exactDecimal(lexeme);
  if (decimal.digits === "") return decimal.negative ? "negative-zero" : undefined;
  if (!Number.isFinite(value)) return "overflow";
  if (value === 0) return "underflow";
  if (decimal.exponent >= 0) {
    // An integer value: every integer of the safe range is exactly a double.
    if (Number.isSafeInteger(value)) return undefined;
    if (!Number.isInteger(value)) return "rounded";
    const magnitude = BigInt(decimal.digits) * 10n ** BigInt(decimal.exponent);
    return BigInt(value) === (decimal.negative ? -magnitude : magnitude) ? undefined : "rounded";
  }
  if (Number.isInteger(value)) return "rounded";
  if (sameDecimal(decimal, exactDecimal(String(value)))) return undefined;
  return sameDecimal(decimal, exactDecimalOfFraction(value)) ? undefined : "rounded";
}

const NUMBER_LOSS_V1: Readonly<Record<StrictJsonNumberLossV1, string>> = {
  overflow: "a number beyond the double range",
  underflow: "a non-zero number that underflows to zero",
  rounded: "a number no double holds exactly",
  "negative-zero": "negative zero",
};

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
 * character inside a string; an invalid escape; a number no double carries without loss, in
 * any spelling (S2i: {@link numberLossV1}, a typed {@link StrictJsonNumberErrorV1});
 * malformed Unicode; nesting deeper than
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
    const loss = numberLossV1(lexeme, value);
    if (loss !== undefined) {
      const shown = lexeme.length > 64 ? `${lexeme.slice(0, 64)}…` : lexeme;
      throw new StrictJsonNumberErrorV1(
        `invalid JSON ${label}: ${NUMBER_LOSS_V1[loss]} (${shown}) at offset ${String(at)}`,
        lexeme,
        loss,
      );
    }
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
