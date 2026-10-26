import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative } from "node:path";
import { gunzipSync } from "node:zlib";
import { bound, ContractError, hasControl, strictParse } from "./json.js";
import { pathShape, repositoryShape } from "./shapes.js";
import { decodeStrictUtf8V1 } from "./strict-json.js";
import type { Limits, NpmSource } from "./types.js";

function refuse(detail: string): never {
  throw new ContractError("npm-acquisition-failed", detail);
}
function containment(detail: string): never {
  throw new ContractError("npm-containment-failed", detail);
}
const integrityPattern = /^sha512-[A-Za-z0-9+/]{86}==$/;

/** One finite, credential-free HTTPS read; no ambient npm configuration or redirects. */
async function download(url: string, maximum: number, signal: AbortSignal): Promise<Buffer> {
  if (!repositoryShape.safeParse(url).success)
    refuse("npm acquisition requires a credential-free HTTPS URL without a query or fragment");
  signal.throwIfAborted();
  const response = await fetch(url, { signal, redirect: "error", credentials: "omit" });
  const reader = response.body?.getReader();
  if (!reader) refuse("npm acquisition response has no body");
  try {
    if (!response.ok) refuse("npm acquisition response was unsuccessful");
    const length = response.headers.get("content-length");
    if (length !== null) {
      if (!/^\d+$/.test(length)) refuse("npm acquisition response length is invalid");
      bound(BigInt(length) <= BigInt(maximum), "npmDownloadBytes", maximum, length);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      total += value.byteLength;
      bound(total <= maximum, "npmDownloadBytes", maximum, total);
      chunks.push(value);
    }
    return Buffer.concat(chunks, total);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

interface Member {
  path: string;
  mode: number;
  type: string;
  link: string;
  bytes: Buffer;
}
function unpack(
  archive: Buffer,
  root: string,
  limits: Limits,
  signal: AbortSignal,
): Map<string, boolean> {
  // Header/padding overhead is separately bounded, including empty-entry attacks.
  const maximum = limits.maxSourceBytes + limits.maxSourceEntries * 1024 + 2048;
  let tar: Buffer;
  try {
    tar = gunzipSync(archive, { maxOutputLength: maximum });
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ERR_BUFFER_TOO_LARGE"
    )
      bound(false, "npmExpandedArchiveBytes", maximum, `more than ${maximum}`);
    return refuse("npm archive must be a complete bounded gzip stream");
  }
  const text = (bytes: Buffer) => {
    const end = bytes.indexOf(0);
    const content = end < 0 ? bytes : bytes.subarray(0, end);
    if (end >= 0 && bytes.subarray(end).some((byte) => byte !== 0))
      refuse("npm tar field has trailing data");
    return decodeStrictUtf8V1(content, "npm tar field");
  };
  const octal = (bytes: Buffer) => {
    const value = bytes
      .toString("ascii")
      .replace(/[\0 ]+$/g, "")
      .replace(/^ +/, "");
    if (!/^[0-7]+$/.test(value)) refuse("npm tar numeric field is invalid");
    const number = Number.parseInt(value, 8);
    if (!Number.isSafeInteger(number)) refuse("npm tar numeric field exceeds safe range");
    return number;
  };
  const members = new Map<string, Member>();
  let offset = 0,
    total = 0,
    ended = false;
  while (offset + 512 <= tar.length) {
    signal.throwIfAborted();
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (tar.length - offset < 1024 || tar.subarray(offset).some((byte) => byte !== 0))
        refuse("npm tar end marker is invalid");
      ended = true;
      break;
    }
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i]!;
    if (checksum !== octal(header.subarray(148, 156))) refuse("npm tar header checksum mismatch");
    if (text(header.subarray(257, 263)) !== "ustar") refuse("npm tar requires ustar headers");
    const prefix = text(header.subarray(345, 500));
    const name = `${prefix ? `${prefix}/` : ""}${text(header.subarray(0, 100))}`;
    const type = String.fromCharCode(header[156] || 48);
    if (!["0", "2", "5"].includes(type))
      containment(
        "npm tar contains an unsupported entry type (including hard links or extended headers)",
      );
    const size = octal(header.subarray(124, 136));
    const mode = octal(header.subarray(100, 108));
    const link = text(header.subarray(157, 257));
    const end = offset + 512 + size;
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    if (next > tar.length || (type !== "0" && size !== 0))
      refuse("npm tar entry is truncated or has invalid data");
    const normalized = type === "5" ? name.replace(/\/$/, "") : name;
    if (normalized === "package" && type === "5") {
      offset = next;
      continue;
    }
    if (!normalized.startsWith("package/"))
      containment("npm tar entries must be inside the package root");
    const path = normalized.slice(8);
    if (!pathShape.safeParse(path).success || path === ".git" || path.startsWith(".git/"))
      containment("npm tar entry path is unsafe or reserved");
    if (members.has(path)) containment("npm tar repeats an entry path");
    bound(
      members.size < limits.maxSourceEntries,
      "maxSourceEntries",
      limits.maxSourceEntries,
      members.size + 1,
    );
    total += size;
    bound(total <= limits.maxSourceBytes, "maxSourceBytes", limits.maxSourceBytes, total);
    members.set(path, { path, mode, type, link, bytes: tar.subarray(offset + 512, end) });
    offset = next;
  }
  if (!ended) refuse("npm tar is missing its end marker");
  // Validate the complete namespace before any write. Implicit parents are ordinary directories.
  const directories = new Set<string>();
  for (const member of members.values()) {
    let parent = posix.dirname(member.path);
    while (parent !== ".") {
      const entry = members.get(parent);
      if (entry && entry.type !== "5") containment("npm tar entry traverses a file or link");
      directories.add(parent);
      parent = posix.dirname(parent);
    }
    if (member.type === "5") directories.add(member.path);
  }
  const count = directories.size + [...members.values()].filter((m) => m.type !== "5").length;
  bound(count <= limits.maxSourceEntries, "maxSourceEntries", limits.maxSourceEntries, count);
  const linkTargets = new Map<string, string>();
  for (const member of members.values()) {
    if (member.type !== "2") continue;
    if (
      !member.link ||
      member.link.startsWith("/") ||
      member.link.includes("\\") ||
      member.link.includes(":") ||
      hasControl(member.link)
    )
      containment("npm tar link target is unsafe");
    const parts = member.path.split("/");
    parts.pop();
    const components = member.link.split("/");
    for (const [index, component] of components.entries()) {
      if (!component || component === ".") continue;
      if (component === "..") {
        if (!parts.length) containment("npm tar link escapes the package root");
        parts.pop();
      } else {
        parts.push(component);
        const path = parts.join("/"),
          entry = members.get(path);
        if (entry?.type === "2" || (!entry && !directories.has(path)))
          containment("npm tar link traverses a link or absent entry");
        if (index < components.length - 1 && !directories.has(path))
          containment("npm tar link traverses a file");
      }
    }
    const target = parts.join("/");
    if (!pathShape.safeParse(target).success || (!members.has(target) && !directories.has(target)))
      containment("npm tar link target is absent or unsafe");
    linkTargets.set(member.path, target);
  }
  mkdirSync(root);
  for (const directory of [...directories].sort())
    mkdirSync(join(root, directory), { recursive: true });
  const modes = new Map<string, boolean>();
  for (const member of members.values()) {
    if (member.type !== "0") continue;
    const executable = (member.mode & 0o111) !== 0;
    const path = join(root, member.path),
      mode = executable ? 0o700 : 0o600;
    writeFileSync(path, member.bytes, { flag: "wx", mode });
    chmodSync(path, mode);
    modes.set(member.path, executable);
  }
  for (const [path, target] of linkTargets)
    symlinkSync(
      relative(dirname(join(root, path)), join(root, target)),
      join(root, path),
      directories.has(target) ? "dir" : "file",
    );
  return modes;
}

/** Resolves only exact coordinates, pins the compressed bytes, then materializes inert files. */
export async function acquireNpm(
  source: NpmSource,
  root: string,
  limits: Limits,
  callerSignal?: AbortSignal,
): Promise<{ source: NpmSource; modes: Map<string, boolean> }> {
  const timeout = AbortSignal.timeout(30000);
  const signal = callerSignal ? AbortSignal.any([timeout, callerSignal]) : timeout;
  try {
    let archive = source.archive;
    if (!archive && "package" in source) {
      const url = `https://registry.npmjs.org/${encodeURIComponent(source.package)}/${encodeURIComponent(source.version)}`;
      const metadata = strictParse(
        await download(url, 1024 * 1024, signal),
        "npm version metadata",
        1024 * 1024,
      ) as { name?: unknown; version?: unknown; dist?: { tarball?: unknown; integrity?: unknown } };
      if (
        !metadata ||
        metadata.name !== source.package ||
        metadata.version !== source.version ||
        !metadata.dist ||
        typeof metadata.dist.tarball !== "string" ||
        typeof metadata.dist.integrity !== "string"
      )
        refuse("npm metadata does not identify the requested exact package version and archive");
      archive = { url: metadata.dist.tarball, integrity: metadata.dist.integrity };
    }
    if (!archive || !integrityPattern.test(archive.integrity))
      refuse("npm archive requires a single sha512 integrity pin");
    const maximum = limits.maxSourceBytes + limits.maxSourceEntries * 1024 + 2048;
    const bytes = await download(archive.url, maximum, signal);
    const actual = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    if (actual !== archive.integrity)
      throw new ContractError(
        "npm-integrity-mismatch",
        "npm archive bytes do not match the sha512 integrity pin",
      );
    const modes = unpack(bytes, root, limits, signal);
    if ("package" in source) {
      if (!modes.has("package.json"))
        refuse("npm coordinates require a regular captured package.json");
      const manifest = strictParse(
        readFileSync(join(root, "package.json")),
        "npm package manifest",
        limits.maxSourceBytes,
      ) as { name?: unknown; version?: unknown };
      if (!manifest || manifest.name !== source.package || manifest.version !== source.version)
        refuse("npm archive package.json does not match the requested exact package version");
    }
    return { source: { ...source, archive }, modes };
  } catch (error) {
    if (error instanceof ContractError) throw error;
    if (signal.aborted) refuse("npm acquisition was cancelled or exceeded its 30000ms deadline");
    // Never echo network, archive, or filesystem messages supplied outside this module.
    refuse("npm acquisition or materialization failed");
  }
}
