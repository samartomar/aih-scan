/**
 * Completion evidence v1 (C2a §1.6) as the installed proofs check it, independently of Scan's
 * own code: the child extracts each SARIF run's first invocation, and the parent recomputes
 * subject-files-v1 from the fixture files on disk and compares.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** Source text for the proof child: every run's first invocation, as the proof reads it. */
export const COMPLETION_EXTRACT_SOURCE = `const completionOf = (bytes) => {
  try {
    const log = JSON.parse(Buffer.from(bytes).toString("utf8"));
    return (Array.isArray(log.runs) ? log.runs : []).map((run) => {
      const first = Array.isArray(run?.invocations) ? run.invocations[0] : undefined;
      return { executionSuccessful: first?.executionSuccessful ?? null, evidence: first?.properties?.aihScanCompletionV1 ?? null };
    });
  } catch {
    return null;
  }
};`;

/** The detectors whose capability completes on an empty source (C2a §1.6). */
const EMPTY_COMPLETES = new Set([
  "detector.semgrep",
  "detector.skillspector",
  "detector.snyk-agent-scan",
  "detector.aih-trust-lint",
  "detector.aih-binding-gate",
]);

/** Every file under `root` by POSIX path, links followed, in code-unit order. */
function diskFiles(root, prefix = "") {
  const found = [];
  for (const name of readdirSync(prefix === "" ? root : join(root, ...prefix.split("/")))) {
    const path = prefix === "" ? name : `${prefix}/${name}`;
    const stat = statSync(join(root, ...path.split("/")));
    if (stat.isDirectory()) found.push(...diskFiles(root, path));
    else if (stat.isFile()) found.push(path);
  }
  return found.sort();
}

const outsideGit = (path) => path !== ".git" && !path.startsWith(".git/");

/** The files a detector received, per the C2a §1.6 table, read from disk. */
export function subjectPaths({ detectorId, subjectKind, root, selected, detectorOptions }) {
  const all = diskFiles(root);
  if (detectorId === "detector.semgrep" || detectorId === "detector.skillspector") return all;
  if (detectorId === "detector.snyk-agent-scan") return all.filter(outsideGit);
  if (detectorId === "detector.cisco" && subjectKind === "skill-directory") return all.filter(outsideGit);
  if (detectorId === "detector.cisco") {
    const jobs = selected.flatMap((path) =>
      path === "SKILL.md" ? [""] : path.endsWith("/SKILL.md") ? [path.slice(0, -"SKILL.md".length)] : [],
    );
    return all.filter((path) => outsideGit(path) && jobs.some((job) => job === "" || path.startsWith(job)));
  }
  if (detectorId === "detector.cisco-mcp-scanner")
    return [...new Set(detectorOptions?.mcpConfigPaths ?? [])]
      .filter((path) => existsSync(join(root, ...path.split("/"))) && statSync(join(root, ...path.split("/"))).isFile())
      .sort();
  return [...new Set(selected)].sort();
}

/** subject-files-v1 over files read from disk. */
export function subjectDigest(root, paths) {
  const ordered = [...new Set(paths)].sort();
  const framed = ordered.map(
    (path) => `${path}\u0000${createHash("sha256").update(readFileSync(join(root, ...path.split("/")))).digest("hex")}\n`,
  );
  return {
    subjectTreeSha256: createHash("sha256").update(framed.join(""), "utf8").digest("hex"),
    analyzedFileCount: ordered.length,
  };
}

/**
 * Why a succeeded log's completion evidence is wrong, or `undefined` when every run carries
 * `executionSuccessful: true` and the same evidence, equal to the expectation.
 */
export function completionProblem(runs, expected) {
  if (!Array.isArray(runs) || runs.length === 0) return "no SARIF run to carry completion evidence";
  if (runs.some((run) => run.executionSuccessful !== true)) return "a run's first invocation is not executionSuccessful: true";
  const first = JSON.stringify(runs[0].evidence);
  if (runs[0].evidence === null) return "a run carries no aihScanCompletionV1";
  if (runs.some((run) => JSON.stringify(run.evidence) !== first)) return "the runs carry different evidence";
  const digest = subjectDigest(expected.root, expected.paths);
  const want = {
    detectorId: expected.detectorId,
    subjectTreeSha256: digest.subjectTreeSha256,
    analyzedFileCount: digest.analyzedFileCount,
    analyzer: { version: expected.version, lockSha256: expected.lockSha256 },
  };
  // Key order is not part of the contract; every key and value is.
  const sorted = (value) =>
    value !== null && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]))
      : value;
  const got = runs[0].evidence;
  if (JSON.stringify(sorted(got)) !== JSON.stringify(sorted(want)))
    return `evidence ${JSON.stringify(got)} is not the expected ${JSON.stringify(want)}`;
  if (want.analyzedFileCount === 0 && !EMPTY_COMPLETES.has(expected.detectorId))
    return `${expected.detectorId} reported zero analyzed files`;
  return undefined;
}
