import { createHash } from "node:crypto";
import {
  type Node as JsonNode,
  type ParseError,
  parse,
  parseTree,
  printParseErrorCode,
} from "jsonc-parser";

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

function duplicateKeys(node: JsonNode): void {
  if (node.type === "object") {
    const keys = new Set<string>();
    for (const property of node.children ?? []) {
      const key = property.children?.[0]?.value;
      if (typeof key === "string") {
        if (keys.has(key)) throw new TypeError(`duplicate JSON object key: ${key}`);
        keys.add(key);
      }
      const child = property.children?.[1];
      if (child !== undefined) duplicateKeys(child);
    }
  } else if (node.type === "array") for (const child of node.children ?? []) duplicateKeys(child);
}

export function parseStrictJsonObjectV1(text: string, label: string): Record<string, unknown> {
  assertWellFormedNfcV1(text, `${label} JSON text`);
  const options = { allowTrailingComma: false, disallowComments: true } as const;
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, options);
  if (errors.length > 0 || tree === undefined)
    throw new TypeError(
      `invalid JSON ${label}: ${errors.map((e) => printParseErrorCode(e.error)).join(",")}`,
    );
  if (tree.type !== "object") throw new TypeError(`${label} JSON root must be an object`);
  duplicateKeys(tree);
  const parseErrors: ParseError[] = [];
  const parsed = parse(text, parseErrors, options);
  if (parseErrors.length > 0 || !object(parsed) || Array.isArray(parsed))
    throw new TypeError(`invalid JSON ${label}`);
  return assertStrictJsonValueV1(parsed, label) as Record<string, unknown>;
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
