/** Pure assertions shared by the installed parity proof and its regression tests. */
export const coreRanSemgrep = (core) =>
  core?.parsedJson === true &&
  /(^|\s)semgrep=core-legacy(,|\.|$)/.test(core.executorsLine ?? "") &&
  core.semgrepDetector?.verdict === "pass" &&
  /Semgrep static scan completed/.test(core.semgrepDetector.detail ?? "");

/** Match a finding only to a file in this fixture and from this side's known source root. */
export function normaliseFindingPath(uri, files, originRoot) {
  const unknown = { path: uri ?? null, accepted: false };
  if (typeof uri !== "string" || typeof originRoot !== "string") return unknown;
  let path = uri;
  if (uri.startsWith("file:")) {
    if (!uri.startsWith("file:///") || uri.includes("?") || uri.includes("#")) return unknown;
    try {
      // Keep lexical dot segments visible for the safety check below; URL() normalizes them.
      path = decodeURIComponent(uri.slice("file://".length));
    } catch {
      return unknown;
    }
  }
  if (path.includes("\\") || path.includes("\0")) return unknown;
  const root = originRoot.replace(/\/+$/, "");
  if (path.startsWith("/")) {
    if (!path.startsWith(`${root}/`)) return unknown;
    path = path.slice(root.length + 1);
  }
  if (path.split("/").some((part) => part === "" || part === "." || part === ".."))
    return unknown;
  return files.includes(path) ? { path, accepted: true } : unknown;
}

/** Empty input must be a typed pre-execution refusal from a successful child. */
export const scanRefusedForEmpty = (scan) =>
  scan?.exit === 0 &&
  scan.childError === null &&
  scan.summary?.outcome === "refused" &&
  scan.summary.reason === "subject-requirement-unmet" &&
  scan.summary.executionProfileId === null;

export function compareFindingKeys(coreKeys, scanKeys, allPathsRecognised = true) {
  const unmatched = (left, right) => {
    const remaining = new Map();
    for (const key of right) remaining.set(key, (remaining.get(key) ?? 0) + 1);
    return left.filter((key) => {
      const count = remaining.get(key) ?? 0;
      if (count === 0) return true;
      remaining.set(key, count - 1);
      return false;
    });
  };
  const onlyCore = unmatched(coreKeys, scanKeys);
  const onlyScan = unmatched(scanKeys, coreKeys);
  return {
    onlyCore,
    onlyScan,
    identical: allPathsRecognised && onlyCore.length === 0 && onlyScan.length === 0,
  };
}
