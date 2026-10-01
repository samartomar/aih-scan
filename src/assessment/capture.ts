import { createHash } from "node:crypto";
import {
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
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnBoundedV1 } from "../cli/process-runner.js";
import { readSourceEntryNamesV1 } from "../observation/source-entry-name-v1.js";
import { base64Decode, bound, canonicalBytes, fail, hasControl, strictParse } from "./json.js";
import { validateEntries } from "./report.js";
import { pathShape } from "./shapes.js";
import { decodeStrictUtf8V1 } from "./strict-json.js";
import type { Capture, CaptureEntry, Limits, ScanRequest, Selection } from "./types.js";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const posix = (root: string, path: string) => relative(root, path).split(sep).join("/");
const sameIdentity = (a: Stats, b: Stats) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeMs === b.mtimeMs &&
  a.ctimeMs === b.ctimeMs;
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
function readStable(path: string, expected: Stats, maxBytes: number): Uint8Array {
  bound(expected.size <= maxBytes, "source bytes", maxBytes);
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
): Capture {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("Source must be a real directory");
  const realRoot = realpathSync.native(root),
    entries: CaptureEntry[] = [];
  let total = 0;
  const copyFile = (path: string, stat: Stats, outputPath: string) => {
    if (stat.nlink !== 1) fail("Hard-linked source files are not supported");
    const bytes = readStable(path, stat, limits.maxSourceBytes - total);
    total += bytes.length;
    if (snapshotRoot) {
      const output = join(snapshotRoot, outputPath);
      mkdirSync(dirname(output), { recursive: true });
      writeFileSync(output, bytes, { flag: "wx" });
    }
    return { sha256: hash(bytes), byteLength: bytes.length };
  };
  const visit = (directory: string) => {
    if (signal?.aborted) fail("Source capture was cancelled");
    const before = lstatSync(directory),
      parent = posix(root, directory);
    const names = readSourceEntryNamesV1(directory, parent, {
      maximum: limits.maxSourceEntries + 1,
      onBound: () => {
        bound(false, "source entries", limits.maxSourceEntries);
        return fail("Source entry bound");
      },
    }).sort();
    for (const name of names) {
      if (directory === root && name === ".git") continue;
      bound(entries.length < limits.maxSourceEntries, "source entries", limits.maxSourceEntries);
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
          const bytes = readStable(real!, targetStat, limits.maxSourceBytes - total);
          if (targetStat.nlink !== 1) fail("Hard-linked source targets are not supported");
          total += bytes.length;
          entries.push({
            kind: "file-link",
            path,
            target,
            sha256: hash(bytes),
            byteLength: bytes.length,
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
    profile: "aih-source-capture-1",
    entries,
    captureSha256: hash(
      canonicalBytes({ domain: "aih.scan.capture.v1", profile: "aih-source-capture-1", entries }),
    ),
  };
}
export interface CapturedSource {
  root: string;
  capture: Capture;
  selection: Selection;
  cleanup(): void;
  assertUnchanged(): void;
}
export interface CaptureOptions {
  signal?: AbortSignal;
  gitCredentials?: { username: string; password: string };
}
async function git(
  argv: string[],
  cwd: string,
  options: CaptureOptions,
  hooks: string,
  maxBytes = 16 * 1024 * 1024,
): Promise<Uint8Array> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
  Object.assign(env, {
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
  });
  if (options.gitCredentials) {
    const { username, password } = options.gitCredentials;
    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 4096 ||
      password.length > 4096 ||
      hasControl(username + password)
    )
      fail("Explicit Git credentials are malformed");
    const repository = argv.find((value) => value.startsWith("https://"));
    if (repository)
      Object.assign(env, {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: `http.${new URL(repository).origin}/.extraHeader`,
        GIT_CONFIG_VALUE_0: `Authorization: Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`,
      });
  }
  const strings: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) if (value !== undefined) strings[key] = value;
  const moduleFile = fileURLToPath(import.meta.url),
    helper = join(dirname(moduleFile), `git-command${extname(moduleFile)}`);
  const gitArgs = [
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "http.sslVerify=true",
    "-c",
    `core.hooksPath=${hooks}`,
    "-c",
    "core.autocrlf=false",
    ...argv,
  ];
  const output = await spawnBoundedV1(
    [process.execPath, helper, JSON.stringify(gitArgs), String(maxBytes)],
    {
      cwd,
      env: strings,
      signal: options.signal,
      timeoutMs: 600000,
      maxStdoutBytes: Math.ceil(maxBytes / 3) * 4 + 64,
      maxStderrBytes: 65536,
      containProcessTree: true,
    },
  );
  if (output.code !== 0 || output.truncated || output.termination || output.stdoutMalformedUtf8)
    fail("Pinned Git acquisition failed or could not confirm process cleanup");
  const value = strictParse(
    new TextEncoder().encode(output.stdout),
    "Git transport",
    Math.ceil(maxBytes / 3) * 4 + 64,
  );
  if (
    typeof value !== "object" ||
    value === null ||
    !("bytesBase64" in value) ||
    typeof value.bytesBase64 !== "string" ||
    Object.keys(value).length !== 1
  )
    fail("Git transport returned malformed bytes");
  return base64Decode(value.bytesBase64, maxBytes);
}
export async function captureSource(
  request: ScanRequest,
  limits: Limits,
  options: CaptureOptions,
): Promise<CapturedSource> {
  const stage = mkdtempSync(join(tmpdir(), "aih-scan-assessment-")),
    snapshotRoot = join(stage, "snapshot");
  mkdirSync(snapshotRoot);
  try {
    let sourceRoot: string;
    if (request.source.kind === "local") sourceRoot = resolve(request.source.path);
    else {
      const acquired = join(stage, "git"),
        hooks = join(stage, "empty-hooks"),
        material = join(stage, "material");
      mkdirSync(acquired);
      mkdirSync(hooks);
      mkdirSync(material);
      await git(["init", "--quiet", `--template=${hooks}`], acquired, options, hooks);
      await git(
        [
          "fetch",
          "--quiet",
          "--no-tags",
          "--depth=1",
          request.source.repository,
          request.source.commit,
        ],
        acquired,
        options,
        hooks,
      );
      if (
        decodeStrictUtf8V1(
          await git(["rev-parse", `${request.source.commit}^{commit}`], acquired, options, hooks),
          "Git commit",
        ).trim() !== request.source.commit
      )
        fail("Git acquisition did not produce the pinned commit");
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
      const tree = decodeStrictUtf8V1(
        await git(["ls-tree", "-r", "-t", "-z", request.source.commit], acquired, options, hooks),
        "Git tree",
      );
      const members = tree
        .split("\0")
        .filter(Boolean)
        .map((row) => {
          const match = /^(\d{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/.exec(row);
          if (!match) fail("Git tree is malformed");
          const path = pathShape.parse(match![4]);
          if (path === ".git" || path.startsWith(".git/"))
            fail("Git tree contains reserved root metadata");
          return { mode: match![1]!, type: match![2]!, oid: match![3]!, path };
        });
      bound(members.length <= limits.maxSourceEntries, "source entries", limits.maxSourceEntries);
      let bytesTotal = 0;
      for (const member of members) {
        const output = join(material, member.path);
        if (member.mode === "040000" && member.type === "tree") {
          mkdirSync(output, { recursive: true });
          continue;
        }
        if (!["100644", "100755", "120000"].includes(member.mode) || member.type !== "blob")
          fail("Pinned Git contains an unsupported tree entry or submodule");
        const sizeText = decodeStrictUtf8V1(
          await git(["cat-file", "-s", member.oid], acquired, options, hooks, 64),
          "Git blob size",
        ).trim();
        if (!/^(0|[1-9]\d*)$/.test(sizeText)) fail("Git blob size is invalid");
        const size = Number(sizeText);
        bound(
          Number.isSafeInteger(size) && size <= limits.maxSourceBytes - bytesTotal,
          "source bytes",
          limits.maxSourceBytes,
        );
        bytesTotal += size;
        const bytes = await git(["cat-file", "blob", member.oid], acquired, options, hooks, size);
        if (bytes.length !== size) fail("Git blob length disagrees with pinned object");
        const gitBlobHash = createHash("sha1").update(`blob ${size}\0`).update(bytes).digest("hex");
        if (gitBlobHash !== member.oid) fail("Git blob differs from the pinned tree object");
        mkdirSync(dirname(output), { recursive: true });
        if (member.mode === "120000") {
          const target = decodeStrictUtf8V1(bytes, "Git link target");
          if (target.includes("\0") || isAbsolute(target) || /^[A-Za-z]:/.test(target))
            fail("Git link target is unsupported");
          const containedTarget = contained(material, resolve(dirname(output), target));
          const targetEntry = members.find((entry) => entry.path === containedTarget);
          if (!targetEntry) fail("Git link target is absent from pinned material");
          symlinkSync(
            relative(dirname(output), join(material, containedTarget)),
            output,
            targetEntry.type === "tree" ? "dir" : "file",
          );
        } else
          writeFileSync(output, bytes, {
            flag: "wx",
            mode: member.mode === "100755" ? 0o700 : 0o600,
          });
      }
      sourceRoot = material;
    }
    const capture = captureTree(sourceRoot, limits, snapshotRoot, options.signal);
    // Re-read the original and the private snapshot before trusting the source identity.
    if (
      captureTree(sourceRoot, limits, undefined, options.signal).captureSha256 !==
        capture.captureSha256 ||
      captureTree(snapshotRoot, limits, undefined, options.signal).captureSha256 !==
        capture.captureSha256
    )
      fail("Source changed while its snapshot was captured");
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
      root: snapshotRoot,
      capture,
      selection: { paths, excludedPaths },
      cleanup: () => rmSync(stage, { recursive: true, force: true }),
      assertUnchanged: () => {
        if (captureTree(snapshotRoot, limits).captureSha256 !== capture.captureSha256)
          fail("Detector input snapshot lost its source binding");
      },
    };
  } catch (error) {
    rmSync(stage, { recursive: true, force: true });
    throw error;
  }
}
