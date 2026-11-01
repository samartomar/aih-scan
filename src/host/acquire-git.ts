import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GitSourceRefusal, parseGitRef, resolveGitSource } from "../cli/git-source.js";
import { limits } from "../contracts/limits.js";
import { ContractError } from "../shared/json.js";
import { gitTransportLimit, startGitFetchRelay } from "./git-fetch-relay.js";
import { GitContainmentError, runPinnedGit } from "./git-runner.js";
import { inventoryProblem } from "./inventory.js";
import type { FolderRefusalReason, SnapshotFile } from "./snapshot.js";

export interface GitSourceRequest {
  readonly repo: string;
  readonly ref?: string;
  /** Only files at or under this repository-relative path are read. */
  readonly path?: string;
}

export type AcquisitionReason =
  | FolderRefusalReason
  | "source-unavailable"
  | "source-integrity"
  | "commit-unreachable"
  | "path-not-found";

export type GitAcquisition =
  | Readonly<{
      status: "ok";
      commit: string;
      ref?: string;
      /** Repository-relative paths, modes from the Git tree, exact blob bytes. */
      files: readonly SnapshotFile[];
    }>
  | Readonly<{ status: "refused"; reason: AcquisitionReason; detail: string }>
  | Readonly<{ status: "invalid"; reason: "ref"; detail: string }>
  | Readonly<{ status: "cancelled"; reason: "cancelled"; detail: string }>;

class Refused extends Error {
  constructor(
    readonly reason: AcquisitionReason,
    detail: string,
  ) {
    super(detail);
  }
}

const unavailable =
  "the Git repository is unavailable, requires credentials, or could not be fetched";
/** Above this many blob bytes, blobs are read one by one instead of in one batch. */
const BATCH_BYTES = 64 * 1024 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });
const sha1 = (type: string, bytes: Uint8Array) =>
  createHash("sha1").update(`${type} ${bytes.length}\0`).update(bytes).digest("hex");
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

interface TreeRow {
  readonly mode: string;
  readonly type: string;
  readonly oid: string;
  readonly size: number;
  readonly path: string;
}

/** `ls-tree -r -l -z` rows: `<mode> <type> <oid> <size>\t<path>\0`; sizes are `-` for non-blobs. */
function treeRows(bytes: Uint8Array): TreeRow[] {
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new Refused("invalid-name", "a repository path is not valid text");
  }
  return text
    .split("\0")
    .filter(Boolean)
    .map((row) => {
      const match = /^(\d{6}) (blob|tree|commit) ([0-9a-f]{40}) +(-|\d+)\t([\s\S]+)$/.exec(row);
      if (match === null)
        throw new Refused("source-integrity", "the Git tree listing is malformed");
      return {
        mode: match[1] as string,
        type: match[2] as string,
        oid: match[3] as string,
        size: match[4] === "-" ? 0 : Number(match[4]),
        path: match[5] as string,
      };
    });
}

/** `cat-file --batch` output: `<oid> <type> <size>\n<bytes>\n` per object. */
function batchObjects(bytes: Uint8Array): Map<string, Uint8Array> {
  const objects = new Map<string, Uint8Array>();
  let offset = 0;
  while (offset < bytes.length) {
    const end = bytes.indexOf(0x0a, offset);
    if (end < 0) throw new Refused("source-integrity", "the Git object listing is malformed");
    const header = /^([0-9a-f]{40}) (\w+) (\d+)$/.exec(
      new TextDecoder().decode(bytes.subarray(offset, end)),
    );
    if (header === null)
      throw new Refused("source-integrity", "the Git object listing is malformed");
    const size = Number(header[3]);
    const start = end + 1;
    if (start + size + 1 > bytes.length || bytes[start + size] !== 0x0a)
      throw new Refused("source-integrity", "the Git object listing is truncated");
    if (header[2] === "blob") objects.set(header[1] as string, bytes.subarray(start, start + size));
    offset = start + size + 1;
  }
  return objects;
}

const within = (path: string, prefix: string | undefined) =>
  prefix === undefined || path === prefix || path.startsWith(`${prefix}/`);

/**
 * Acquires one public Git commit over HTTPS with Scan's locked-down Git (no credential helpers,
 * askpass, hooks, redirects or ambient configuration; transport bounded by a relay pinned to the
 * repository host). A named ref is resolved to its full commit first; a full commit given as the
 * ref must be reachable from an advertised branch or tag. Only blobs at or under `path` are read,
 * each verified against its Git object id; links and submodules are refused, as are inventories
 * over the published limits. The private Git directory is always removed. The fetch happens
 * before any scan; nothing in the repository is run.
 */
export async function acquireGit(
  source: GitSourceRequest,
  signal: AbortSignal,
): Promise<GitAcquisition> {
  const parsed = parseGitRef(source.ref);
  if (!parsed.ok) return Object.freeze({ status: "invalid", reason: "ref", detail: parsed.detail });
  const stage = mkdtempSync(join(tmpdir(), "aih-scan-git-"));
  try {
    let resolved: { commit: string; ref?: string };
    try {
      resolved = await resolveGitSource(source.repo, parsed.request, signal);
    } catch (error) {
      if (signal.aborted) throw error;
      throw new Refused(
        "source-unavailable",
        error instanceof GitSourceRefusal ? error.message : unavailable,
      );
    }
    const commit = resolved.commit;
    const hooks = join(stage, "empty-hooks");
    const work = join(stage, "git");
    mkdirSync(hooks);
    mkdirSync(work);
    const git = (argv: string[], max?: number) => runPinnedGit(argv, work, { signal }, hooks, max);
    await git(["init", "--quiet", `--template=${hooks}`]);
    const relay = await startGitFetchRelay(
      source.repo,
      gitTransportLimit(limits.input.sourceBytes, limits.input.files),
      signal,
    );
    const remote = (argv: string[], max?: number) =>
      runPinnedGit(
        ["-c", `http.proxy=${relay.proxy}`, "-c", "credential.helper=", ...argv],
        work,
        { signal: AbortSignal.any([signal, relay.limitSignal]) },
        hooks,
        max,
      );
    try {
      if (parsed.request.kind === "commit") {
        // A commit named only by its id must belong to this repository (forks can share objects).
        const tips = decoder.decode(
          await remote(["ls-remote", "--refs", source.repo, "refs/heads/*", "refs/tags/*"]),
        );
        if (!tips.split("\n").some((line) => line.startsWith(`${commit}\t`))) {
          await remote([
            "fetch",
            "--quiet",
            "--no-tags",
            source.repo,
            "+refs/heads/*:refs/remotes/named/*",
            "+refs/tags/*:refs/tags/*",
          ]);
          const ancestry = decoder.decode(await git(["rev-list", "--all"]));
          if (!ancestry.split("\n").includes(commit))
            throw new Refused(
              "commit-unreachable",
              "the commit is not reachable from any branch or tag of the repository",
            );
        }
      }
      await remote(["fetch", "--quiet", "--no-tags", "--depth=1", source.repo, commit]);
    } finally {
      await relay.close();
    }
    relay.assertWithinBounds();
    if (decoder.decode(await git(["rev-parse", `${commit}^{commit}`])).trim() !== commit)
      throw new Refused("source-integrity", "Git did not produce the requested commit");
    const rows = treeRows(await git(["ls-tree", "-r", "-l", "-z", commit]));
    const selected = rows.filter((row) => within(row.path, source.path));
    if (source.path !== undefined && selected.length === 0)
      throw new Refused("path-not-found", "the path does not exist at that commit");
    for (const row of selected) {
      if (row.mode === "120000")
        throw new Refused("link", `${JSON.stringify(row.path).slice(0, 200)} is a symbolic link`);
      if (row.type !== "blob" || (row.mode !== "100644" && row.mode !== "100755"))
        throw new Refused(
          "special-file",
          `${JSON.stringify(row.path).slice(0, 200)} is not a regular file (submodule or unsupported entry)`,
        );
    }
    const problem = inventoryProblem(selected);
    if (problem !== undefined) throw new Refused(problem.reason, problem.detail);
    const total = selected.reduce((sum, row) => sum + row.size, 0);
    let objects: Map<string, Uint8Array>;
    if (total <= BATCH_BYTES) {
      objects = batchObjects(
        await git(
          ["cat-file", "--batch-all-objects", "--batch"],
          total + rows.length * 128 + 16 * 1024 * 1024,
        ),
      );
    } else {
      objects = new Map();
      for (const row of selected)
        if (!objects.has(row.oid))
          objects.set(row.oid, await git(["cat-file", "blob", row.oid], row.size));
    }
    const files: SnapshotFile[] = [];
    for (const row of selected) {
      const bytes = objects.get(row.oid);
      if (bytes === undefined || bytes.length !== row.size || sha1("blob", bytes) !== row.oid)
        throw new Refused("source-integrity", "a Git blob does not match its object id");
      files.push(
        Object.freeze({
          path: row.path,
          mode: row.mode as "100644" | "100755",
          bytes: new Uint8Array(bytes),
          sha256: sha256(bytes),
        }),
      );
    }
    files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return Object.freeze({
      status: "ok" as const,
      commit,
      ...(resolved.ref === undefined ? {} : { ref: resolved.ref }),
      files: Object.freeze(files),
    });
  } catch (error) {
    if (signal.aborted)
      return Object.freeze({ status: "cancelled", reason: "cancelled", detail: "cancelled" });
    if (error instanceof Refused)
      return Object.freeze({ status: "refused", reason: error.reason, detail: error.message });
    if (error instanceof GitContainmentError)
      return Object.freeze({
        status: "refused",
        reason: "source-unavailable",
        detail: "Git process cleanup could not be confirmed",
      });
    if (error instanceof ContractError && error.code === "resource-limit")
      return Object.freeze({
        status: "refused",
        reason: "source-size",
        detail: "the Git transfer exceeded its byte budget",
      });
    // Git's own messages may repeat the URL; only fixed text is returned.
    return Object.freeze({ status: "refused", reason: "source-unavailable", detail: unavailable });
  } finally {
    rmSync(stage, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}
