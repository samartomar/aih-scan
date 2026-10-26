import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  rmSync,
  type Stats,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { readSourceEntryNamesV1 } from "../observation/source-entry-name-v1.js";
import { type GitFetchRelay, gitTransportLimit, startGitFetchRelay } from "./git-fetch-relay.js";
import { GitContainmentError, runPinnedGit as git } from "./git-runner.js";
import { bound, ContractError, canonicalBytes, fail, hasControl } from "./json.js";
import { acquireNpm } from "./npm-source.js";
import { validateEntries } from "./report.js";
import { pathShape } from "./shapes.js";
import { decodeStrictUtf8V1 } from "./strict-json.js";
import type { Capture, CaptureEntry, Diagnostic, Limits, ScanRequest, Selection } from "./types.js";
import { schemasV2 } from "./types.js";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const posix = (root: string, path: string) => relative(root, path).split(sep).join("/");
const sameIdentity = (a: Stats, b: Stats) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeMs === b.mtimeMs &&
  a.ctimeMs === b.ctimeMs &&
  a.mode === b.mode;
function contained(root: string, target: string): string {
  const child = relative(root, target);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child))
    fail("Source link must remain inside the captured root");
  const path = child.split(sep).join("/");
  pathShape.parse(path);
  if (path === ".git" || path.startsWith(".git/"))
    fail("Source links cannot import omitted root Git metadata");
  return path;
}
/** Adapted stable descriptor reads from SourceObservationSealV1. The bytes hashed are the bytes copied. */
function readStable(
  path: string,
  expected: Stats,
  maxBytes: number,
  capturedBytes = 0,
): Uint8Array {
  bound(
    expected.size <= maxBytes - capturedBytes,
    "maxSourceBytes",
    maxBytes,
    capturedBytes + expected.size,
  );
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(expected, before))
      fail("Source file identity changed before capture");
    const bytes = new Uint8Array(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail("Source file read ended early");
      offset += count;
    }
    if (!sameIdentity(before, fstatSync(descriptor)) || !sameIdentity(before, lstatSync(path)))
      fail("Source file identity changed during capture");
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
function captureTree(
  root: string,
  limits: Limits,
  snapshotRoot?: string,
  signal?: AbortSignal,
  profile: Capture["profile"] = "aih-source-capture-1",
  gitModes?: ReadonlyMap<string, boolean>,
): Capture {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("Source must be a real directory");
  const realRoot = realpathSync.native(root),
    entries: CaptureEntry[] = [];
  const state = (path: string, stat: Stats) =>
    profile === "aih-source-capture-1"
      ? {}
      : {
          executable:
            gitModes?.get(path) ??
            (process.platform === "win32" ? ("unknown" as const) : (stat.mode & 0o111) !== 0),
        };
  let total = 0;
  const copyFile = (path: string, stat: Stats, outputPath: string) => {
    if (stat.nlink !== 1) fail("Hard-linked source files are not supported");
    const bytes = readStable(path, stat, limits.maxSourceBytes, total);
    total += bytes.length;
    if (snapshotRoot) {
      const output = join(snapshotRoot, outputPath);
      mkdirSync(dirname(output), { recursive: true });
      if (profile === "aih-source-capture-2") {
        writeFileSync(output, bytes, { flag: "wx", mode: stat.mode & 0o777 });
        chmodSync(output, stat.mode & 0o777);
      } else {
        // Legacy observation inputs omit modes: preserve their original normalized snapshot.
        writeFileSync(output, bytes, { flag: "wx" });
      }
    }
    return { sha256: hash(bytes), byteLength: bytes.length, ...state(outputPath, stat) };
  };
  const visit = (directory: string) => {
    if (signal?.aborted) fail("Source capture was cancelled");
    const before = lstatSync(directory),
      parent = posix(root, directory);
    const names = readSourceEntryNamesV1(directory, parent, {
      maximum: limits.maxSourceEntries + 1,
      onBound: () => {
        bound(
          false,
          "maxSourceEntries",
          limits.maxSourceEntries,
          `at least ${limits.maxSourceEntries + 1}`,
        );
        return fail("Source entry bound");
      },
    }).sort();
    for (const name of names) {
      if (directory === root && name === ".git") continue;
      bound(
        entries.length < limits.maxSourceEntries,
        "maxSourceEntries",
        limits.maxSourceEntries,
        entries.length + 1,
      );
      const absolute = join(directory, name),
        path = posix(root, absolute);
      pathShape.parse(path);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        let real: string;
        try {
          real = realpathSync.native(absolute);
        } catch {
          fail("Source contains a broken link");
        }
        const target = contained(realRoot, real!),
          targetStat = statSync(real!);
        if (targetStat.isFile()) {
          // The target's regular path is separately copied. Preserve link identity in the snapshot.
          const bytes = readStable(real!, targetStat, limits.maxSourceBytes, total);
          if (targetStat.nlink !== 1) fail("Hard-linked source targets are not supported");
          total += bytes.length;
          entries.push({
            kind: "file-link",
            path,
            target,
            sha256: hash(bytes),
            byteLength: bytes.length,
            ...state(target, targetStat),
          });
        } else if (targetStat.isDirectory()) entries.push({ kind: "directory-link", path, target });
        else fail("Source link target type is unsupported");
        if (snapshotRoot) {
          const output = join(snapshotRoot, path);
          mkdirSync(dirname(output), { recursive: true });
          symlinkSync(
            relative(dirname(output), join(snapshotRoot, target)),
            output,
            targetStat.isDirectory() ? "dir" : "file",
          );
        }
        if (!sameIdentity(stat, lstatSync(absolute)) || realpathSync.native(absolute) !== real!)
          fail("Source link changed during capture");
      } else if (stat.isDirectory()) {
        entries.push({ kind: "directory", path });
        if (snapshotRoot) mkdirSync(join(snapshotRoot, path), { recursive: true });
        visit(absolute);
      } else if (stat.isFile())
        entries.push({ kind: "file", path, ...copyFile(absolute, stat, path) });
      else fail("Unsupported source entry kind");
    }
    const after = lstatSync(directory);
    if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after))
      fail("Source directory changed during capture");
  };
  visit(root);
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  validateEntries(entries, limits.maxSourceEntries, limits.maxSourceBytes);
  return {
    profile,
    entries,
    captureSha256: hash(
      canonicalBytes({
        domain: profile === "aih-source-capture-1" ? "aih.scan.capture.v1" : "aih.scan.capture.v2",
        profile,
        entries,
      }),
    ),
  };
}
export interface CapturedSource {
  source: ScanRequest["source"];
  root: string;
  capture: Capture;
  selection: Selection;
  reachability: "reachable" | "unchecked" | null;
  diagnostics: Diagnostic[];
  cleanup(): void;
  assertUnchanged(): void;
}
export interface CaptureOptions {
  signal?: AbortSignal;
  gitCredentials?: { username: string; password: string };
}
/** All remote operations share one acquisition-wide transport budget. */
async function gitWithRelay(
  argv: string[],
  acquired: string,
  options: CaptureOptions,
  hooks: string,
  relay: GitFetchRelay,
): Promise<Uint8Array> {
  try {
    const bytes = await git(
      [
        "-c",
        `http.proxy=${relay.proxy}`,
        "-c",
        "fetch.unpackLimit=1",
        "-c",
        "transfer.unpackLimit=1",
        ...argv,
      ],
      acquired,
      {
        ...options,
        signal: options.signal
          ? AbortSignal.any([options.signal, relay.limitSignal])
          : relay.limitSignal,
      },
      hooks,
    );
    relay.assertWithinBounds();
    return bytes;
  } catch (error) {
    if (!(error instanceof GitContainmentError)) relay.assertWithinBounds();
    throw error;
  }
}

function repositoryRefs(bytes: Uint8Array, imported = false): string[] {
  const text = decodeStrictUtf8V1(bytes, "Repository refs").trim();
  const rows = text ? text.split("\n") : [];
  const names = new Set<string>();
  return rows
    .map((row) => {
      const normalized = imported ? row.replace("\trefs/remotes/named/", "\trefs/heads/") : row;
      const match = /^([0-9a-f]{40})\t(refs\/(?:heads|tags)\/[^\s]+)$/.exec(normalized);
      if (!match || names.has(match[2]!)) fail("Repository refs are malformed or repeated");
      names.add(match![2]!);
      return normalized;
    })
    .sort();
}

export async function captureSource(
  request: ScanRequest,
  limits: Limits,
  options: CaptureOptions,
): Promise<CapturedSource> {
  let step = "prepare temporary capture";
  let stage: string | undefined;
  try {
    stage = mkdtempSync(join(tmpdir(), "aih-scan-assessment-"));
    const snapshotRoot = join(stage, "snapshot");
    mkdirSync(snapshotRoot);
    const profile =
      request.schema === schemasV2.request ? "aih-source-capture-2" : "aih-source-capture-1";
    const gitModes = new Map<string, boolean>();
    const diagnostics: Diagnostic[] = [];
    let sourceRoot: string;
    let reachability: CapturedSource["reachability"] =
      request.source.kind === "git" ? "unchecked" : null;
    let resolvedSource = request.source;
    if (request.source.kind === "npm") {
      step = "acquire npm archive";
      sourceRoot = join(stage, "material");
      const acquired = await acquireNpm(request.source, sourceRoot, limits, options.signal);
      resolvedSource = acquired.source;
      for (const [path, mode] of acquired.modes) gitModes.set(path, mode);
    } else if (request.source.kind === "local") sourceRoot = resolve(request.source.path);
    else {
      const acquired = join(stage, "git"),
        hooks = join(stage, "empty-hooks"),
        material = join(stage, "material");
      mkdirSync(acquired);
      mkdirSync(hooks);
      mkdirSync(material);
      step = "git init";
      await git(["init", "--quiet", `--template=${hooks}`], acquired, options, hooks);
      step = "start fetch relay";
      const relay = await startGitFetchRelay(
        request.source.repository,
        gitTransportLimit(limits.maxSourceBytes, limits.maxSourceEntries),
        options.signal,
      );
      const remote = (argv: string[]) => gitWithRelay(argv, acquired, options, hooks, relay);
      let acquisitionError: unknown;
      try {
        // Only advertised branches and tags can establish named-repository membership.
        // Compare imported refs as Git may exit zero after rejecting shallow remote refs.
        let reachabilityCheckCompleted = false;
        step = "check repository reachability";
        try {
          const advertised = repositoryRefs(
            await remote([
              "ls-remote",
              "--refs",
              request.source.repository,
              "refs/heads/*",
              "refs/tags/*",
            ]),
          );
          await remote([
            "fetch",
            "--quiet",
            "--no-tags",
            request.source.repository,
            "+refs/heads/*:refs/remotes/named/*",
            "+refs/tags/*:refs/tags/*",
          ]);
          const imported = repositoryRefs(
            await git(
              [
                "for-each-ref",
                "--format=%(objectname)\t%(refname)",
                "refs/remotes/named/",
                "refs/tags/",
              ],
              acquired,
              options,
              hooks,
            ),
            true,
          );
          if (
            advertised.length !== imported.length ||
            advertised.some((row, index) => row !== imported[index])
          )
            fail("Repository refs were not completely imported or changed during the check");
          if (
            decodeStrictUtf8V1(
              await git(["rev-parse", "--is-shallow-repository"], acquired, options, hooks, 16),
              "Repository shallow state",
            ).trim() !== "false"
          )
            fail("Repository ancestry is shallow or unknown");
          const ancestry = decodeStrictUtf8V1(
            await git(["rev-list", "--all"], acquired, options, hooks),
            "Repository ancestry",
          );
          const commits = ancestry.trim() ? ancestry.trim().split("\n") : [];
          if (commits.some((commit) => !/^[0-9a-f]{40}$/.test(commit)))
            fail("Repository ancestry is malformed");
          reachability = commits.includes(request.source.commit) ? "reachable" : "unchecked";
          reachabilityCheckCompleted = true;
        } catch (error) {
          // An unavailable check proves neither membership nor non-membership. Exhausted
          // shared transport, containment failure and cancellation still stop acquisition.
          if (
            error instanceof GitContainmentError ||
            options.signal?.aborted ||
            relay.limitSignal.aborted
          )
            throw error;
          diagnostics.push({
            code: "git-reachability-unchecked",
            detail: `Git capture step check repository reachability: ${
              error instanceof ContractError
                ? error.message
                : "Repository ancestry check unavailable"
            }`,
          });
        }
        if (reachabilityCheckCompleted && reachability !== "reachable")
          throw new ContractError(
            "git-commit-unreachable",
            "Pinned commit is not reachable from any branch or tag of the named repository",
          );
        step = "git fetch";
        await remote([
          "fetch",
          "--quiet",
          "--no-tags",
          "--depth=1",
          request.source.repository,
          request.source.commit,
        ]);
      } catch (error) {
        acquisitionError = error;
        throw error;
      } finally {
        await relay.close();
        if (!(acquisitionError instanceof GitContainmentError)) relay.assertWithinBounds();
      }
      step = "verify commit";
      if (
        decodeStrictUtf8V1(
          await git(["rev-parse", `${request.source.commit}^{commit}`], acquired, options, hooks),
          "Git commit",
        ).trim() !== request.source.commit
      )
        fail("Git acquisition did not produce the pinned commit");
      step = "read commit object";
      const commitBytes = await git(
        ["cat-file", "commit", request.source.commit],
        acquired,
        options,
        hooks,
        1024 * 1024,
      );
      if (
        createHash("sha1")
          .update(`commit ${commitBytes.length}\0`)
          .update(commitBytes)
          .digest("hex") !== request.source.commit
      )
        fail("Git commit object does not match the requested identity");
      step = "read tree";
      const tree = decodeStrictUtf8V1(
        await git(["ls-tree", "-r", "-t", "-z", request.source.commit], acquired, options, hooks),
        "Git tree",
      );
      step = "validate tree";
      const members = tree
        .split("\0")
        .filter(Boolean)
        .map((row) => {
          const match = /^(\d{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/.exec(row);
          if (!match) fail("Git tree is malformed");
          bound(
            new TextEncoder().encode(match![4]!).length <= 4096,
            "sourcePathBytes",
            4096,
            new TextEncoder().encode(match![4]!).length,
          );
          const path = pathShape.parse(match![4]);
          if (path === ".git" || path.startsWith(".git/"))
            fail("Git tree contains reserved root metadata");
          return { mode: match![1]!, type: match![2]!, oid: match![3]!, path };
        });
      bound(
        members.length <= limits.maxSourceEntries,
        "maxSourceEntries",
        limits.maxSourceEntries,
        members.length,
      );
      const membersByPath = new Map(members.map((member) => [member.path, member]));
      let bytesTotal = 0;
      for (const member of members) {
        step = "materialize tree";
        const output = join(material, member.path);
        if (member.mode === "040000" && member.type === "tree") {
          mkdirSync(output, { recursive: true });
          continue;
        }
        if (!["100644", "100755", "120000"].includes(member.mode) || member.type !== "blob")
          fail("Pinned Git contains an unsupported tree entry or submodule");
        step = "read blob size";
        const sizeText = decodeStrictUtf8V1(
          await git(["cat-file", "-s", member.oid], acquired, options, hooks, 64),
          "Git blob size",
        ).trim();
        if (!/^(0|[1-9]\d*)$/.test(sizeText)) fail("Git blob size is invalid");
        const size = Number(sizeText);
        bound(
          Number.isSafeInteger(size) && size <= limits.maxSourceBytes - bytesTotal,
          "maxSourceBytes",
          limits.maxSourceBytes,
          bytesTotal + size,
        );
        bytesTotal += size;
        step = "read blob";
        const bytes = await git(["cat-file", "blob", member.oid], acquired, options, hooks, size);
        step = "verify blob";
        if (bytes.length !== size) fail("Git blob length disagrees with pinned object");
        const gitBlobHash = createHash("sha1").update(`blob ${size}\0`).update(bytes).digest("hex");
        if (gitBlobHash !== member.oid) fail("Git blob differs from the pinned tree object");
        step = "materialize tree";
        mkdirSync(dirname(output), { recursive: true });
        if (member.mode === "120000") {
          const target = decodeStrictUtf8V1(bytes, "Git link target");
          if (
            hasControl(target) ||
            target.includes("\\") ||
            isAbsolute(target) ||
            /^[A-Za-z]:/.test(target)
          )
            fail("Git link target is unsupported");
          // Check components before lexical '..' removal: traversing a link changes its meaning.
          const parts = member.path.split("/");
          parts.pop();
          const components = target.split("/");
          for (const [index, component] of components.entries()) {
            if (!component || component === ".") continue;
            if (component === "..") {
              if (!parts.length) fail("Git link target escapes pinned material");
              parts.pop();
            } else {
              parts.push(component);
              const traversed = membersByPath.get(parts.join("/"));
              if (!traversed || traversed.mode === "120000")
                fail("Git link target traverses a link or absent entry");
              if (index < components.length - 1 && traversed.type !== "tree")
                fail("Git link target traverses a non-directory entry");
            }
          }
          const containedTarget = contained(material, resolve(dirname(output), target));
          const targetEntry = membersByPath.get(containedTarget);
          if (!targetEntry) fail("Git link target is absent from pinned material");
          symlinkSync(
            relative(dirname(output), join(material, containedTarget)),
            output,
            targetEntry.type === "tree" ? "dir" : "file",
          );
        } else {
          writeFileSync(output, bytes, {
            flag: "wx",
            mode: member.mode === "100755" ? 0o700 : 0o600,
          });
          chmodSync(output, member.mode === "100755" ? 0o700 : 0o600);
        }
      }
      for (const member of members) {
        if (member.mode === "100755" || member.mode === "100644")
          gitModes.set(member.path, member.mode === "100755");
      }
      sourceRoot = material;
    }
    const sourceModes = request.source.kind !== "local" ? gitModes : undefined;
    const snapshotModes = process.platform === "win32" ? sourceModes : undefined;
    step = "capture snapshot";
    const capture = captureTree(
      sourceRoot,
      limits,
      snapshotRoot,
      options.signal,
      profile,
      sourceModes,
    );
    step = "verify snapshot";
    // Re-read the original and the private snapshot before trusting the source identity.
    if (
      captureTree(sourceRoot, limits, undefined, options.signal, profile, sourceModes)
        .captureSha256 !== capture.captureSha256 ||
      captureTree(snapshotRoot, limits, undefined, options.signal, profile, snapshotModes)
        .captureSha256 !== capture.captureSha256
    )
      fail("Source changed while its snapshot was captured");
    step = "resolve selection";
    const files = capture.entries.filter((entry) => "sha256" in entry).map((entry) => entry.path),
      byPath = new Set(files);
    const paths = request.selection.paths === "all" ? files : [...request.selection.paths].sort(),
      excludedPaths = [...request.selection.excludedPaths].sort();
    if (paths.length === 0 && files.length > 0)
      fail("Nonempty captured sources require a nonempty file selection");
    for (const path of paths)
      if (!byPath.has(path)) fail("Selected path is absent from captured files");
    for (const path of excludedPaths)
      if (!paths.includes(path)) fail("An exclusion is absent from the resolved selection");
    return {
      source: resolvedSource,
      root: snapshotRoot,
      reachability,
      diagnostics,
      capture,
      selection: { paths, excludedPaths },
      cleanup: () => {
        try {
          rmSync(stage!, { recursive: true, force: true });
        } catch (error) {
          if (request.source.kind !== "local")
            throw new ContractError(
              request.source.kind === "git" ? "git-containment-failed" : "npm-containment-failed",
              `${request.source.kind === "git" ? "Git" : "npm"} capture step cleanup: temporary capture could not be removed`,
            );
          throw error;
        }
      },
      assertUnchanged: () => {
        if (
          captureTree(snapshotRoot, limits, undefined, undefined, profile, snapshotModes)
            .captureSha256 !== capture.captureSha256
        )
          fail("Detector input snapshot lost its source binding");
      },
    };
  } catch (error) {
    try {
      if (stage) rmSync(stage, { recursive: true, force: true });
    } catch {
      if (request.source.kind !== "local")
        throw new ContractError(
          request.source.kind === "git" ? "git-containment-failed" : "npm-containment-failed",
          `${request.source.kind === "git" ? "Git" : "npm"} capture step cleanup: temporary capture could not be removed after ${step}`,
        );
      throw error;
    }
    if (request.source.kind === "git") {
      const code =
        error instanceof ContractError && error.code !== "invalid-input"
          ? error.code
          : "git-acquisition-failed";
      // Contract messages are code-owned; raw filesystem/Git messages may contain secrets.
      const errno =
        error &&
        typeof error === "object" &&
        "code" in error &&
        typeof error.code === "string" &&
        ["EACCES", "EPERM", "ENOENT", "ENOSPC", "EROFS", "EMFILE", "ENFILE"].includes(error.code)
          ? ` (${error.code})`
          : "";
      const detail =
        error instanceof ContractError
          ? error.message
          : `Capture I/O or source validation failed${errno}`;
      throw new ContractError(code, `Git capture step ${step}: ${detail}`);
    }
    throw error;
  }
}
