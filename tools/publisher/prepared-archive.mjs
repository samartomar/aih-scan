// Bounded regular-file-only tar transport for reviewed prepared candidates. No archive code runs.
import { createHash } from "node:crypto";
import { lookup } from "node:dns";
import { chmodSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { isIP } from "node:net";
import { dirname, join } from "node:path";

export const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const need = (condition, message) => { if (!condition) throw new Error(message); };
export const plainText = (value) => [...value].every((character) => character.codePointAt(0) >= 32 && character.codePointAt(0) !== 127);
export function safePath(value) {
  need(typeof value === "string" && value.length > 0 && plainText(value) && !/[\\:]/u.test(value), "Invalid relative path");
  need(!value.startsWith("/") && value.split("/").every((part) => part !== "" && part !== "." && part !== ".." && part !== ".git"), "Unsafe relative path");
  return value;
}
const octal = (bytes) => {
  const text = bytes.toString("ascii").replace(/\0.*$/s, "").trim();
  need(/^[0-7]+$/.test(text), "Invalid tar number");
  const value = Number.parseInt(text, 8);
  need(Number.isSafeInteger(value) && value >= 0, "Invalid tar number");
  return value;
};
const tarText = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, bytes.indexOf(0) < 0 ? bytes.length : bytes.indexOf(0)));
export function readArchive(bytes) {
  need(bytes.length <= MAX_ARCHIVE_BYTES && bytes.length % 512 === 0, "Archive exceeds bounds or is truncated");
  const entries = new Map();
  for (let offset = 0; offset < bytes.length; ) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      need(bytes.length - offset >= 1024 && bytes.subarray(offset).every((byte) => byte === 0), "Missing or unexpected data after tar terminator");
      return entries;
    }
    const expected = octal(header.subarray(148, 156));
    const checked = Buffer.from(header); checked.fill(32, 148, 156);
    need(checked.reduce((sum, byte) => sum + byte, 0) === expected, "Tar checksum mismatch");
    const prefix = tarText(header.subarray(345, 500)), name = tarText(header.subarray(0, 100));
    const type = header[156];
    need(type === 0 || type === 48 || type === 53, "Archive links and special entries are refused");
    const path = safePath(`${prefix ? `${prefix}/` : ""}${name}`.replace(/\/$/, ""));
    need(!entries.has(path), "Duplicate archive path");
    const size = octal(header.subarray(124, 136));
    need(offset + 512 + size <= bytes.length, "Truncated archive entry");
    need(type !== 53 || size === 0, "Invalid archive directory");
    entries.set(path, { type: type === 53 ? "directory" : "file", mode: octal(header.subarray(100, 108)), bytes: bytes.subarray(offset + 512, offset + 512 + size) });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error("Missing tar terminator");
}
export function extractArchive(bytes, out) {
  const entries = readArchive(bytes);
  // Validate ancestor types before writing any supplied path.
  for (const [path] of entries) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index++) need(entries.get(parts.slice(0, index).join("/"))?.type !== "file", "Archive file is a parent directory");
  }
  mkdirSync(out); // An existing destination, including a link, is refused.
  for (const [path, entry] of entries) {
    const target = join(out, ...path.split("/"));
    if (entry.type === "directory") { mkdirSync(target, { recursive: true }); continue; }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, entry.bytes, { flag: "wx", mode: entry.mode & 0o111 ? 0o755 : 0o644 });
    if (process.platform !== "win32") chmodSync(target, entry.mode & 0o111 ? 0o755 : 0o644);
  }
}
export function writeArchive(entries, out) {
  const chunks = [];
  let length = 1024;
  const number = (header, value, at, width) => header.write(`${value.toString(8).padStart(width - 1, "0")}\0`, at, width, "ascii");
  for (const entry of [...entries].sort((a, b) => a.path < b.path ? -1 : 1)) {
    safePath(entry.path);
    const encoded = Buffer.from(entry.path);
    let name = entry.path, prefix = "";
    if (encoded.length > 100) {
      const split = entry.path.lastIndexOf("/");
      prefix = entry.path.slice(0, split); name = entry.path.slice(split + 1);
    }
    need(Buffer.byteLength(name) <= 100 && Buffer.byteLength(prefix) <= 155, "Path cannot be represented by the bounded ustar transport");
    const bytes = entry.bytes ?? readFileSync(entry.file);
    length += 512 + Math.ceil(bytes.length / 512) * 512;
    need(length <= MAX_ARCHIVE_BYTES, "Candidate archive exceeds 512 MiB; select an explicit smaller batch");
    const header = Buffer.alloc(512);
    header.write(name); header.write(prefix, 345); header.write("ustar\0", 257); header.write("00", 263);
    number(header, entry.mode === "100755" ? 0o755 : 0o644, 100, 8);
    number(header, 0, 108, 8); number(header, 0, 116, 8); number(header, bytes.length, 124, 12); number(header, 0, 136, 12);
    header[156] = 48; header.fill(32, 148, 156);
    number(header, header.reduce((sum, byte) => sum + byte, 0), 148, 8);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  writeFileSync(out, Buffer.concat(chunks), { flag: "wx" });
  return { sha256: digest(readFileSync(out)), bytes: length };
}
const publicAddress = (address) => {
  if (address.includes(":")) return /^[23][0-9a-f]{3}:/i.test(address); // Globally routed IPv6 only; no mapped/private forms.
  const [a, b, c] = address.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && (b === 168 || b === 0 || b === 2)) && !(a === 100 && b >= 64 && b <= 127) && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) && !(a === 203 && b === 0 && c === 113);
};
export async function downloadArchive(descriptor, out) {
  const url = new URL(descriptor.url);
  need(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && (url.port === "" || url.port === "443"), "Import needs a public terminal HTTPS URL without credentials or query parameters");
  need(Array.isArray(descriptor.allowedHosts) && descriptor.allowedHosts.includes(url.hostname), "Import host is not explicitly allowed");
  const literal = url.hostname.replace(/^\[|\]$/g, "");
  need(!isIP(literal) || publicAddress(literal), "Non-public import address refused");
  need(/^[0-9a-f]{64}$/.test(descriptor.sha256), "Invalid archive digest");
  const bytes = await new Promise((resolveBytes, reject) => {
    const child = request(url, { timeout: 120000, lookup(host, options, callback) {
      lookup(host, { all: true, verbatim: true }, (error, answers) => {
        if (error) { callback(error); return; }
        if (!answers.length || answers.some(({ address }) => !publicAddress(address))) { callback(new Error("Non-public import address refused")); return; }
        if (options.all) callback(null, answers); else callback(null, answers[0].address, answers[0].family);
      });
    } }, (response) => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error("Import response refused (redirects are not followed)")); return; }
      let size = 0; const chunks = [];
      response.on("data", (chunk) => { size += chunk.length; if (size > MAX_ARCHIVE_BYTES) response.destroy(new Error("Candidate archive exceeds 512 MiB")); else chunks.push(chunk); });
      response.once("error", reject); response.once("end", () => resolveBytes(Buffer.concat(chunks)));
    });
    child.once("timeout", () => child.destroy(new Error("Import download timed out"))); child.once("error", reject); child.end();
  });
  need(digest(bytes) === descriptor.sha256, "Import archive digest mismatch");
  need(lstatSync(dirname(out)).isDirectory(), "Import parent is not a directory");
  writeFileSync(out, bytes, { flag: "wx" });
}
