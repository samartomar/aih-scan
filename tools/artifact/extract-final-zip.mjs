import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { crc32, inflateRawSync } from "node:zlib";
import { parseJson } from "../refresh/contracts.mjs";
import { archiveCeiling } from "./check-refresh-run.mjs";
import { expandedCeiling } from "./refresh-publication.mjs";

export function extractFinalZip(bytes, output) {
  const refuse = () => {
    throw new Error("Final archive structure or expanded bound refused");
  };
  if (!Buffer.isBuffer(bytes) || bytes.length > archiveCeiling) refuse();
  let end = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 65557); at--)
    if (
      bytes.readUInt32LE(at) === 0x06054b50 &&
      at + 22 + bytes.readUInt16LE(at + 20) === bytes.length
    ) {
      end = at;
      break;
    }
  if (end < 0 || bytes.readUInt16LE(end + 4) !== 0 || bytes.readUInt16LE(end + 6) !== 0) refuse();
  const count = bytes.readUInt16LE(end + 10),
    size = bytes.readUInt32LE(end + 12),
    start = bytes.readUInt32LE(end + 16);
  if (count < 1 || count > 128 || count !== bytes.readUInt16LE(end + 8) || start + size !== end)
    refuse();
  const entries = [],
    names = new Set();
  let at = start,
    total = 0;
  for (let i = 0; i < count; i++) {
    if (at + 46 > end || bytes.readUInt32LE(at) !== 0x02014b50) refuse();
    const flags = bytes.readUInt16LE(at + 8),
      method = bytes.readUInt16LE(at + 10),
      compressed = bytes.readUInt32LE(at + 20),
      expanded = bytes.readUInt32LE(at + 24),
      nameLength = bytes.readUInt16LE(at + 28),
      extraLength = bytes.readUInt16LE(at + 30),
      commentLength = bytes.readUInt16LE(at + 32),
      offset = bytes.readUInt32LE(at + 42),
      mode = bytes.readUInt32LE(at + 38) >>> 16;
    if (
      flags & ~0x0808 ||
      ![0, 8].includes(method) ||
      expanded > 128 * 1024 * 1024 ||
      at + 46 + nameLength + extraLength + commentLength > end ||
      bytes.readUInt16LE(at + 34) !== 0
    )
      refuse();
    const name = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(at + 46, at + 46 + nameLength),
    );
    if (
      !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\/?$/.test(name) ||
      name.split("/").some((part) => part === "." || part === "..") ||
      names.has(name.toLowerCase())
    )
      refuse();
    names.add(name.toLowerCase());
    const directory = name.endsWith("/");
    if (mode && (mode & 0o170000) !== (directory ? 0o040000 : 0o100000)) refuse();
    if (directory && (expanded !== 0 || compressed !== 0)) refuse();
    let extra = at + 46 + nameLength;
    while (extra < at + 46 + nameLength + extraLength) {
      if (extra + 4 > at + 46 + nameLength + extraLength) refuse();
      const kind = bytes.readUInt16LE(extra),
        length = bytes.readUInt16LE(extra + 2);
      if (
        [0x0001, 0x000d, 0x756e].includes(kind) ||
        extra + 4 + length > at + 46 + nameLength + extraLength
      )
        refuse();
      extra += 4 + length;
    }
    total += expanded;
    if (total > expandedCeiling) refuse();
    if (
      offset + 30 > start ||
      bytes.readUInt32LE(offset) !== 0x04034b50 ||
      bytes.readUInt16LE(offset + 6) !== flags ||
      bytes.readUInt16LE(offset + 8) !== method
    )
      refuse();
    const localNameLength = bytes.readUInt16LE(offset + 26),
      localExtraLength = bytes.readUInt16LE(offset + 28),
      data = offset + 30 + localNameLength + localExtraLength;
    if (
      !bytes
        .subarray(offset + 30, offset + 30 + localNameLength)
        .equals(bytes.subarray(at + 46, at + 46 + nameLength)) ||
      data + compressed > start
    )
      refuse();
    if (
      !(flags & 8) &&
      (bytes.readUInt32LE(offset + 14) !== bytes.readUInt32LE(at + 16) ||
        bytes.readUInt32LE(offset + 18) !== compressed ||
        bytes.readUInt32LE(offset + 22) !== expanded)
    )
      refuse();
    let localExtra = offset + 30 + localNameLength;
    while (localExtra < data) {
      if (localExtra + 4 > data) refuse();
      const kind = bytes.readUInt16LE(localExtra),
        length = bytes.readUInt16LE(localExtra + 2);
      if ([0x0001, 0x000d, 0x756e].includes(kind) || localExtra + 4 + length > data) refuse();
      localExtra += 4 + length;
    }
    entries.push({
      name,
      directory,
      method,
      compressed,
      expanded,
      data,
      crc: bytes.readUInt32LE(at + 16),
    });
    at += 46 + nameLength + extraLength + commentLength;
  }
  if (at !== end) refuse();
  const decode = (entry) => {
    const compressed = bytes.subarray(entry.data, entry.data + entry.compressed);
    const result =
      entry.method === 0
        ? compressed
        : inflateRawSync(compressed, { maxOutputLength: Math.max(1, entry.expanded) });
    if (result.length !== entry.expanded || crc32(result) !== entry.crc) refuse();
    return result;
  };
  const receiptEntry = entries.find(
    (entry) => entry.name === "publication.json" && !entry.directory,
  );
  if (!receiptEntry || receiptEntry.expanded > 2097152) refuse();
  const receipt = parseJson(decode(receiptEntry), 2097152, true);
  if (!Array.isArray(receipt.assets) || receipt.assets.length > 63) refuse();
  const allowed = new Set(["publication.json", ...receipt.assets.map((asset) => asset.path)]),
    directories = new Set();
  if (allowed.size !== receipt.assets.length + 1) refuse();
  for (const path of allowed) {
    if (typeof path !== "string") refuse();
    const parts = path.split("/");
    parts.pop();
    while (parts.length) {
      directories.add(`${parts.join("/")}/`);
      parts.pop();
    }
  }
  const files = entries.filter((entry) => !entry.directory);
  if (
    files.length !== allowed.size ||
    files.some((entry) => !allowed.has(entry.name)) ||
    entries.some((entry) => entry.directory && !directories.has(entry.name))
  )
    refuse();
  for (const entry of files) {
    const parts = entry.name.split("/");
    parts.pop();
    while (parts.length) {
      if (names.has(parts.join("/").toLowerCase())) refuse();
      parts.pop();
    }
    decode(entry);
  }
  mkdirSync(output, { mode: 0o700 });
  for (const entry of files) {
    const path = join(output, entry.name);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, decode(entry), { flag: "wx", mode: 0o600 });
  }
  return { expandedBytes: total, files: files.length };
}
