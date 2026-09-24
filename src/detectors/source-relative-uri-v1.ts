/**
 * The complete C2a §1.4 artifact-URI rule for analyzer SARIF: a
 * source-relative POSIX path with no leading `/`, no drive letter, no scheme
 * (any `name:` prefix, `file:` included), no backslash, and no empty, `.` or
 * `..` segment. Core fails the whole detector on any other URI, so every
 * analyzer engine checks its FINAL URI with this predicate and writes its
 * documented fallback name instead. (The whole-URI `.` that Snyk emits is its
 * fallback, not a path, and is not accepted here.)
 */
export function isSourceRelativeArtifactUriV1(uri: string): boolean {
  if (uri.length === 0 || uri.includes("\\")) return false;
  if (uri.startsWith("/") || /^[A-Za-z]:/.test(uri)) return false;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)) return false;
  return !uri
    .split("/")
    .some((segment) => segment.length === 0 || segment === "." || segment === "..");
}
