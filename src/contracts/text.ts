/**
 * Untrusted-text handling shared by readers and the CLI. Control (Cc), format (Cf: bidirectional
 * controls, zero-width characters, tags) and line/paragraph separator characters are removed;
 * the rest is cut to a code-point limit.
 */
const UNSAFE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

export function isWellFormedText(value: string): boolean {
  LONE_SURROGATE.lastIndex = 0;
  const bad = LONE_SURROGATE.test(value);
  LONE_SURROGATE.lastIndex = 0;
  return !bad;
}

export function hasUnsafeCharacters(value: string): boolean {
  UNSAFE.lastIndex = 0;
  const found = UNSAFE.test(value);
  UNSAFE.lastIndex = 0;
  return found;
}

export function sanitizeText(value: string, maxCodePoints: number): string {
  const wellFormed = value.replace(LONE_SURROGATE, "\uFFFD");
  const visible = wellFormed.replace(UNSAFE, "");
  const points = [...visible];
  return points.length > maxCodePoints ? points.slice(0, maxCodePoints).join("") : visible;
}

export function codePointLength(value: string): number {
  return [...value].length;
}

/**
 * The item-relative path rule shared by producer and readers: non-empty POSIX segments,
 * no `.`/`..`, no leading slash, drive letter, backslash, URL scheme or unsafe characters,
 * well-formed Unicode, within the length limit.
 */
export function pathProblem(
  path: unknown,
  maxLength: number,
  maxDepth: number,
): string | undefined {
  if (typeof path !== "string" || path.length === 0) return "path must be a non-empty string";
  if (!isWellFormedText(path)) return "path is not valid text";
  if (hasUnsafeCharacters(path))
    return "path contains control, bidirectional or zero-width characters";
  if (codePointLength(path) > maxLength) return "path-length";
  if (path.includes("\\")) return "path must use forward slashes";
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path)) return "path must be relative";
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)) return "path must not be a URL";
  const segments = path.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === ".."))
    return "path must not contain empty, . or .. segments";
  if (segments.length - 1 > maxDepth) return "depth";
  return undefined;
}

/** True for a Uint8Array from any realm (instanceof fails across browser frames or VM contexts). */
export function isBytes(value: unknown): value is Uint8Array {
  return (
    ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === "[object Uint8Array]"
  );
}
