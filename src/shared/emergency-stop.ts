import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
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

export interface TemporaryRoot {
  readonly path: string;
  /**
   * Removes the folder, retrying transient locks, then stops tracking it. Throws when it cannot
   * be removed; the folder then stays tracked for the forced stop. Later calls do nothing.
   */
  dispose(): void;
}

/** Creates a new private temporary folder under `parent` and tracks it until it is disposed. */
export function createTemporaryRoot(prefix: string, parent: string = tmpdir()): TemporaryRoot {
  const path = mkdtempSync(join(parent, prefix));
  const release = trackTemporaryRoot(path);
  let disposed = false;
  return Object.freeze({
    path,
    dispose() {
      if (disposed) return;
      rmSync(path, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      disposed = true;
      release();
    },
  });
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
