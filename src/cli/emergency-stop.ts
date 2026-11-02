import { chmodSync, lstatSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

/**
 * What a forced stop must still undo: running process trees Scan started and temporary folders
 * Scan created. Each owner registers while the resource exists and releases it when its own
 * cleanup ran; `stopNowSync` handles whatever is still registered, synchronously, so it can run
 * right before `process.exit`.
 */
const killers = new Set<() => void>();
const roots = new Set<string>();

/** Registers a synchronous forced stop for a running process tree; returns its release. */
export function trackProcessTree(kill: () => void): () => void {
  killers.add(kill);
  return () => void killers.delete(kill);
}

/** Registers a Scan-created temporary folder; returns its release. */
export function trackTemporaryRoot(path: string): () => void {
  roots.add(path);
  return () => void roots.delete(path);
}

/** Makes every folder under `root` writable again (read-only working copies), never following links. */
function unlock(root: string): void {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(root);
  } catch {
    return;
  }
  if (!stat.isDirectory()) return;
  try {
    chmodSync(root, 0o700);
    for (const name of readdirSync(root)) unlock(join(root, name));
  } catch {
    // Best effort; the removal below reports nothing either way.
  }
}

/** Force-stops every tracked process tree, then removes every tracked temporary folder. */
export function stopNowSync(): void {
  for (const kill of [...killers]) {
    try {
      kill();
    } catch {
      // Already gone.
    }
  }
  killers.clear();
  for (const root of [...roots]) {
    try {
      rmSync(root, { recursive: true, force: true });
    } catch {
      unlock(root);
      try {
        rmSync(root, { recursive: true, force: true });
      } catch {
        // Best effort at exit.
      }
    }
  }
  roots.clear();
}
