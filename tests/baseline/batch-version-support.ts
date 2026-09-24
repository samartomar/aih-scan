import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** The bundled lock each uv-backed analyzer's batch profile (`linux-namespace-uv-v1`) installs. */
const BATCH_LOCK_PROJECTS: Readonly<Record<string, string>> = {
  semgrep: "semgrep",
  cisco: "cisco-skill-scanner",
};

/** The sha256 of a bundled analyzer lock, read from disk with plain node:crypto. */
export function bundledLockSha256(project: string): string {
  return createHash("sha256")
    .update(readFileSync(join("tools", "baseline-analyzers", project, "uv.lock")))
    .digest("hex");
}

/**
 * A fake analyzer version consistent with the lock of the profile the batch runs (S2k): a
 * uv-backed analyzer's ends `+uvlock.<first 12 hex of the lock>`, any other has no suffix.
 */
export function batchAnalyzerVersion(analyzer: string, base = `${analyzer}.0123456789ab`): string {
  const project = BATCH_LOCK_PROJECTS[analyzer];
  return project === undefined ? base : `${base}+uvlock.${bundledLockSha256(project).slice(0, 12)}`;
}
