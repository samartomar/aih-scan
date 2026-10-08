// Best-effort custody of original failure bytes, never a publication candidate.
// Splitting by source preserves valid siblings even when aggregate transport
// admission refuses. Every absent/refused original is explicit in the root index.
import { appendFileSync, existsSync, lstatSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  canonicalBytes,
  readRegular,
  roster,
  sha256,
  targetDirectory,
} from "../refresh/contracts.mjs";

const MiB = 1024 * 1024;
export const failureArchiveCeiling = 256 * MiB;
const rootLimits = {
  "manifest.json": 2 * MiB,
  "inventory.json": 128 * MiB,
  "custody.json": 2 * MiB,
  "scanner.tgz": 64 * MiB,
  "consumer-package-lock.json": 8 * MiB,
};
const targetLimits = {
  "result.json": 128 * MiB,
  "artifact.json": 96 * MiB,
  "statement.json": 128 * 1024,
  "candidate.json": 2 * MiB,
};
function boundedOriginal(root, path, limit) {
  const pieces = path.split("/");
  let current = root;
  const rootState = lstatSync(root);
  if (!rootState.isDirectory() || rootState.isSymbolicLink())
    throw new Error("Unsafe original root");
  for (const piece of pieces.slice(0, -1)) {
    current = join(current, piece);
    const state = lstatSync(current);
    if (!state.isDirectory() || state.isSymbolicLink()) throw new Error("Unsafe original parent");
  }
  return readRegular(join(root, path), limit);
}
export function retainFailureEvidence({ candidate, frozen, output, runId = null }) {
  if (runId !== null && !/^[1-9][0-9]{0,15}$/.test(runId))
    throw new Error("Invalid failure run identity");
  mkdirSync(output, { mode: 0o700 });
  mkdirSync(join(output, "root"), { mode: 0o700 });
  mkdirSync(join(output, "targets"), { mode: 0o700 });
  const index = {
    schema: "urn:aihq:scan:nonpublishable-failure-evidence:1.0.0",
    publishable: false,
    phase: "candidate-production",
    reason: "producer-or-preparation-or-transport-failure-or-cancellation",
    runId,
    root: [],
    targets: [],
  };
  function retain(roots, path, destination, limit) {
    let present = false;
    for (const root of roots) {
      if (!existsSync(root) || !existsSync(join(root, path))) continue;
      present = true;
      try {
        const bytes = boundedOriginal(root, path, limit);
        writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
        return { path, status: "retained", byteLength: bytes.length, sha256: sha256(bytes) };
      } catch {
        return { path, status: "refused", reason: "unsafe-original-or-file-bound-exceeded" };
      }
    }
    return { path, status: present ? "refused" : "absent" };
  }
  for (const [name, limit] of Object.entries(rootLimits))
    index.root.push(retain([candidate, frozen], name, join(output, "root", name), limit));
  for (const repository of roster) {
    const directory = targetDirectory(repository);
    mkdirSync(join(output, "targets", directory), { mode: 0o700 });
    const files = Object.entries(targetLimits).map(([name, limit]) =>
      retain(
        [candidate],
        `targets/${directory}/${name}`,
        join(output, "targets", directory, name),
        limit,
      ),
    );
    index.targets.push({ repository, files });
  }
  writeFileSync(join(output, "root", "failure.json"), canonicalBytes(index), {
    flag: "wx",
    mode: 0o600,
  });
  // Upper bounds include every possible retained file plus ZIP metadata slack.
  const rootMaximum = Object.values(rootLimits).reduce((sum, size) => sum + size, 0) + 2 * MiB;
  const targetMaximum = Object.values(targetLimits).reduce((sum, size) => sum + size, 0);
  if (
    rootMaximum + 65536 + 6 * 1024 > failureArchiveCeiling ||
    targetMaximum + 65536 + 4 * 1024 > failureArchiveCeiling
  )
    throw new Error("Failure evidence archive bounds invalid");
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `root=true\n${index.targets.map((row, i) => `target_${i}=${row.files.some((file) => file.status === "retained")}`).join("\n")}\n`,
    );
  return index;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 5)
      throw new Error("Expected candidate, frozen and exclusive failure output");
    const index = retainFailureEvidence({
      candidate: process.argv[2],
      frozen: process.argv[3],
      output: process.argv[4],
      runId: process.env.GITHUB_RUN_ID ?? null,
    });
    process.stdout.write(
      `${JSON.stringify({ event: "scan-refresh-failure-evidence.retained", phase: index.phase, runId: index.runId, publishable: false, retainedTargets: index.targets.filter((row) => row.files.some((file) => file.status === "retained")).length })}\n`,
    );
  } catch {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh-failure-evidence.refused", phase: "candidate-production", reason: "failure-evidence-custody-refused", publishable: false })}\n`,
    );
    process.exitCode = 2;
  }
}
