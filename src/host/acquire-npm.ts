import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { limits } from "../contracts/limits.js";
import type { AcquisitionReason } from "./acquire-git.js";
import { inventoryProblem, isGitMetadata } from "./inventory.js";
import type { SnapshotFile } from "./snapshot.js";

export type NpmAcquisition =
  | Readonly<{
      status: "ok";
      /** Name and version from the package.json inside the tarball. */
      package: string;
      version: string;
      tarballSha256: string;
      /** Package-relative paths (the archive's single top folder removed). */
      files: readonly SnapshotFile[];
    }>
  | Readonly<{ status: "refused"; reason: AcquisitionReason | "not-a-package"; detail: string }>
  | Readonly<{ status: "cancelled"; reason: "cancelled"; detail: string }>;

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

class Refused extends Error {
  constructor(
    readonly reason: AcquisitionReason | "not-a-package",
    detail: string,
  ) {
    super(detail);
  }
}

/** The compressed archive may not exceed the source size plus per-entry header room. */
const ARCHIVE_BYTES = limits.input.sourceBytes + limits.input.files * 1024 + 2048;
const REGISTRY = "https://registry.npmjs.org";
const DEADLINE_MS = 600_000;
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const shown = (path: string) => JSON.stringify(path).slice(0, 200);

function credentialFreeHttps(value: unknown): string {
  if (typeof value !== "string")
    throw new Refused("source-unavailable", "npm metadata has no tarball address");
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Refused("source-unavailable", "npm metadata names an invalid tarball address");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash)
    throw new Refused(
      "source-unavailable",
      "npm tarballs are fetched only over credential-free https",
    );
  return value;
}

/** One bounded, credential-free HTTPS read; redirects are refused. */
async function download(
  fetcher: FetchLike,
  url: string,
  maximum: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  let response: Response;
  try {
    response = await fetcher(url, { signal, redirect: "error", credentials: "omit" });
  } catch {
    signal.throwIfAborted();
    throw new Refused("source-unavailable", "the npm registry could not be reached");
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new Refused("source-unavailable", `the npm registry answered ${response.status}`);
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Refused("source-unavailable", "the npm response has no body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      total += value.byteLength;
      if (total > maximum)
        throw new Refused("source-size", `the npm download exceeds ${maximum} bytes`);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return new Uint8Array(Buffer.concat(chunks, total));
}

interface Member {
  readonly path: string;
  readonly mode: number;
  readonly bytes: Uint8Array;
}

function field(bytes: Uint8Array): string {
  const end = bytes.indexOf(0);
  const content = end < 0 ? bytes : bytes.subarray(0, end);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(content);
  } catch {
    throw new Refused("invalid-name", "a tarball entry name is not valid text");
  }
}

function octal(bytes: Uint8Array): number {
  const value = Buffer.from(bytes)
    .toString("ascii")
    .replace(/[\0 ]+$/g, "")
    .replace(/^ +/, "");
  if (!/^[0-7]+$/.test(value)) throw new Refused("source-integrity", "a tarball header is invalid");
  return Number.parseInt(value, 8);
}

/**
 * PAX extended header records, `<length> <key>=<value>\n`, where the length counts bytes. Only
 * `path` is honoured. A `size` record would make npm's extractor read a different amount of data
 * than the ustar header states, so it is refused rather than ignored.
 */
function paxPath(bytes: Uint8Array): string | undefined {
  const invalid = () => new Refused("source-integrity", "a tarball extended header is invalid");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let offset = 0;
  let path: string | undefined;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    if (space < 0) throw invalid();
    const digits = Buffer.from(bytes.subarray(offset, space)).toString("ascii");
    const length = /^[1-9][0-9]*$/.test(digits) ? Number(digits) : Number.NaN;
    if (!Number.isSafeInteger(length) || offset + length > bytes.length) throw invalid();
    if (bytes[offset + length - 1] !== 0x0a) throw invalid();
    let record: string;
    try {
      record = decoder.decode(bytes.subarray(space + 1, offset + length - 1));
    } catch {
      throw invalid();
    }
    const equals = record.indexOf("=");
    if (equals <= 0) throw invalid();
    const key = record.slice(0, equals);
    if (key === "size")
      throw new Refused("source-integrity", "a tarball extended header overrides an entry size");
    if (key === "path") path = record.slice(equals + 1);
    offset += length;
  }
  return path;
}

/**
 * Reads a gzipped tar as inert data: only regular files (and folders) inside one top folder,
 * by the same path and size limits as a folder. Symbolic links, hard links, devices and every
 * other entry type are refused; nothing is written to disk and nothing is run.
 */
function unpack(archive: Uint8Array, signal: AbortSignal): Member[] {
  const expanded = limits.input.sourceBytes + limits.input.files * 1024 + 4096;
  let tar: Buffer;
  try {
    tar = gunzipSync(archive, { maxOutputLength: expanded });
  } catch (error) {
    if ((error as { code?: string }).code === "ERR_BUFFER_TOO_LARGE")
      throw new Refused("source-size", `the expanded tarball exceeds ${expanded} bytes`);
    throw new Refused("source-integrity", "the tarball is not a complete gzip stream");
  }
  const members: Member[] = [];
  let offset = 0;
  let nextPath: string | undefined;
  let ended = false;
  while (offset + 512 <= tar.length) {
    signal.throwIfAborted();
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      // npm's extractor reads on past a single zero block, so everything after the end marker
      // must be zero too; otherwise Scan and npm would see different files.
      if (!tar.subarray(offset).every((byte) => byte === 0))
        throw new Refused("source-integrity", "the tarball has entries after its end marker");
      ended = true;
      break;
    }
    let checksum = 0;
    for (let index = 0; index < 512; index += 1)
      checksum += index >= 148 && index < 156 ? 32 : (header[index] as number);
    if (checksum !== octal(header.subarray(148, 156)))
      throw new Refused("source-integrity", "a tarball header checksum does not match");
    if (!field(header.subarray(257, 263)).startsWith("ustar"))
      throw new Refused("source-integrity", "the tarball is not ustar");
    const type = String.fromCharCode(header[156] || 48);
    const size = octal(header.subarray(124, 136));
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    if (next > tar.length) throw new Refused("source-integrity", "a tarball entry is truncated");
    const data = tar.subarray(offset + 512, offset + 512 + size);
    const prefix = field(header.subarray(345, 500));
    const name = nextPath ?? `${prefix ? `${prefix}/` : ""}${field(header.subarray(0, 100))}`;
    offset = next;
    if (type === "x") {
      nextPath = paxPath(data);
      continue;
    }
    if (type === "g") {
      paxPath(data); // a global header's path is ignored, as npm does; a size is refused
      continue;
    }
    nextPath = undefined;
    if (type === "5") continue;
    if (type === "2") throw new Refused("link", `${shown(name)} is a symbolic link`);
    if (type === "1") throw new Refused("hard-link", `${shown(name)} is a hard link`);
    if (type !== "0") throw new Refused("special-file", `${shown(name)} is not a regular file`);
    members.push({ path: name, mode: octal(header.subarray(100, 108)), bytes: data });
  }
  if (!ended) throw new Refused("source-integrity", "the tarball has no end marker");
  const tops = new Set(members.map((member) => member.path.split("/")[0]));
  const top = [...tops][0];
  if (tops.size !== 1 || top === undefined || members.some((m) => !m.path.startsWith(`${top}/`)))
    throw new Refused("escaping-path", "tarball entries must sit inside one top folder");
  return members.map((member) => ({ ...member, path: member.path.slice(top.length + 1) }));
}

function fromArchive(archive: Uint8Array, signal: AbortSignal) {
  const members = unpack(archive, signal).filter((member) => !isGitMetadata(member.path));
  const problem = inventoryProblem(
    members.map((member) => ({ path: member.path, size: member.bytes.length })),
  );
  if (problem !== undefined) throw new Refused(problem.reason, problem.detail);
  const files = members
    .map((member) =>
      Object.freeze({
        path: member.path,
        mode: (member.mode & 0o111) !== 0 ? ("100755" as const) : ("100644" as const),
        bytes: new Uint8Array(member.bytes),
        sha256: sha256(member.bytes),
      }),
    )
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const manifest = files.find((file) => file.path === "package.json");
  let identity: { name?: unknown; version?: unknown } | undefined;
  try {
    identity =
      manifest && JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifest.bytes));
  } catch {
    identity = undefined;
  }
  if (typeof identity?.name !== "string" || typeof identity.version !== "string")
    throw new Refused(
      "not-a-package",
      "the tarball has no package.json naming a package and version",
    );
  return { files, name: identity.name, version: identity.version };
}

async function guarded(
  signal: AbortSignal,
  body: (signal: AbortSignal) => Promise<NpmAcquisition>,
): Promise<NpmAcquisition> {
  const combined = AbortSignal.any([signal, AbortSignal.timeout(DEADLINE_MS)]);
  try {
    return await body(combined);
  } catch (error) {
    if (signal.aborted)
      return Object.freeze({ status: "cancelled", reason: "cancelled", detail: "cancelled" });
    if (error instanceof Refused)
      return Object.freeze({ status: "refused", reason: error.reason, detail: error.message });
    if (combined.aborted)
      return Object.freeze({
        status: "refused",
        reason: "source-unavailable",
        detail: `npm acquisition exceeded its ${DEADLINE_MS} ms deadline`,
      });
    return Object.freeze({
      status: "refused",
      reason: "source-unavailable",
      detail: "the npm package could not be acquired",
    });
  }
}

/**
 * Acquires one exact public npm version: registry metadata (exact name and version), then the
 * tarball, verified against the registry's sha512 integrity before it is read as inert files.
 * No npm client, install, lifecycle script or server start ever runs. Fetches happen before the
 * scan; the package.json inside must name the requested package and version.
 */
export function acquireNpm(
  source: Readonly<{ package: string; version: string }>,
  signal: AbortSignal,
  fetcher: FetchLike = (url, init) => fetch(url, init),
): Promise<NpmAcquisition> {
  return guarded(signal, async (combined) => {
    const name = source.package.replace("/", "%2f");
    const metadataBytes = await download(
      fetcher,
      `${REGISTRY}/${name}/${encodeURIComponent(source.version)}`,
      4 * 1024 * 1024,
      combined,
    );
    let metadata: {
      name?: unknown;
      version?: unknown;
      dist?: { tarball?: unknown; integrity?: unknown };
    };
    try {
      metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(metadataBytes));
    } catch {
      throw new Refused("source-unavailable", "the npm registry metadata is not JSON");
    }
    if (metadata?.name !== source.package || metadata.version !== source.version)
      throw new Refused("source-integrity", "the npm metadata names another package or version");
    const integrity = metadata.dist?.integrity;
    if (typeof integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity))
      throw new Refused("source-integrity", "the npm metadata has no sha512 integrity");
    const archive = await download(
      fetcher,
      credentialFreeHttps(metadata.dist?.tarball),
      ARCHIVE_BYTES,
      combined,
    );
    if (`sha512-${createHash("sha512").update(archive).digest("base64")}` !== integrity)
      throw new Refused("source-integrity", "the tarball does not match the registry integrity");
    const read = fromArchive(archive, combined);
    if (read.name !== source.package || read.version !== source.version)
      throw new Refused(
        "source-integrity",
        "the tarball's package.json names another package or version",
      );
    return Object.freeze({
      status: "ok" as const,
      package: read.name,
      version: read.version,
      tarballSha256: sha256(archive),
      files: Object.freeze(read.files),
    });
  });
}

/** Reads a downloaded package tarball from disk as inert files; nothing is fetched. */
export function readNpmFile(path: string, signal: AbortSignal): Promise<NpmAcquisition> {
  return guarded(signal, async (combined) => {
    let archive: Uint8Array;
    let descriptor: number | undefined;
    try {
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Refused("link", "the tarball path is a link");
      if (!stat.isFile())
        throw new Refused("special-file", "the tarball path is not a regular file");
      if (stat.size > ARCHIVE_BYTES)
        throw new Refused("source-size", `the tarball exceeds ${ARCHIVE_BYTES} bytes`);
      descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      archive = new Uint8Array(fstatSync(descriptor).size);
      let offset = 0;
      while (offset < archive.length) {
        const count = readSync(descriptor, archive, offset, archive.length - offset, offset);
        if (count <= 0) throw new Refused("changed", "the tarball changed while it was read");
        offset += count;
      }
    } catch (error) {
      if (error instanceof Refused) throw error;
      throw new Refused("unreadable", "the tarball could not be read");
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
    const read = fromArchive(archive, combined);
    return Object.freeze({
      status: "ok" as const,
      package: read.name,
      version: read.version,
      tarballSha256: sha256(archive),
      files: Object.freeze(read.files),
    });
  });
}
