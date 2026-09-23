/**
 * Shared by every phase of `tools/capture-catalog-item.mjs`: the refusal type, digests,
 * canonical JSON, bounded input readers and the constants more than one phase checks.
 * Nothing here performs a phase; it only names what a phase refuses and how it reads.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

export const DETECTOR_ID = /^detector\.[a-z0-9][a-z0-9.-]*$/;
export const DIGEST = /^sha256:[0-9a-f]{64}$/;
export const ADAPTER_CAPABILITY = "cisco-oci-v1";
/** The skill entry the scanner loads from the capture root; never renamed or generated. */
export const SKILL_ENTRY = "SKILL.md";
export const SOURCE_CLOSURE_RECORD_PROTOCOL = "CatalogSourceClosureCaptureRecordV1";
/** Bounds on the source closure a package may serve and on one of its files. */
export const MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024;

export class Refusal extends Error {}
/** Every refusal names the missing or unacceptable input. Nothing is substituted. */
export const refuse = (reason) => {
  throw new Refusal(reason);
};

export const reasonOf = (error) => (error instanceof Error ? error.message : String(error));
export const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

/* ---------- canonical JSON, mirroring @aihq/scan's own rules ---------- */

export const own = (value, key) => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) refuse("canonical JSON own data");
  return descriptor.value;
};
const canonicalText = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(",")}]`;
  if (typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalText(own(value, key))}`)
      .join(",")}}`;
  return refuse("canonical JSON value");
};
export const canonicalBytes = (value) => Buffer.from(canonicalText(value), "utf8");

/* ---------- bounded input readers ---------- */

export function regularBytes(path, label, minimum, maximum) {
  if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0"))
    refuse(`${label} must be an absolute path`);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    refuse(`${label} is missing: ${path}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1)
    refuse(`${label} must be a regular unlinked file: ${path}`);
  if (stat.size < minimum || stat.size > maximum)
    refuse(`${label} must be between ${minimum} and ${maximum} bytes: ${path}`);
  const bytes = readFileSync(path);
  if (bytes.length !== stat.size) refuse(`${label} changed while reading: ${path}`);
  return bytes;
}

export function textFile(path, label, minimum, maximum) {
  const bytes = regularBytes(path, label, minimum, maximum);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) refuse(`${label} must be UTF-8: ${path}`);
  return text;
}

export function jsonFile(path, label, minimum, maximum) {
  const text = textFile(path, label, minimum, maximum);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    refuse(`${label} must be JSON: ${path}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    refuse(`${label} must be a JSON object: ${path}`);
  return parsed;
}

/** No Git repository may contain the consumer install or the produced run. */
export function assertOutsideGitRepository(path, label) {
  let current = resolve(path);
  for (;;) {
    if (existsSync(join(current, ".git"))) refuse(`${label} must be outside every Git repository`);
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function exactKeys(value, fields, label) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    refuse(`${label} fields`);
}
