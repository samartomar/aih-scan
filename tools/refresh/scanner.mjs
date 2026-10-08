import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readlinkSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { canonicalBytes, readRegular, sha256 } from "./contracts.mjs";

function treeDigest(root) {
  const hash = createHash("sha256");
  let count = 0,
    total = 0;
  const walk = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name),
        nameRelative = relative(root, path).split(sep).join("/"),
        stat = lstatSync(path);
      if (++count > 100000) throw new Error("Scanner installation entry budget exceeded");
      if (stat.isDirectory()) {
        hash.update(canonicalBytes({ kind: "directory", path: nameRelative }));
        walk(path);
      } else if (stat.isSymbolicLink()) {
        const target = readlinkSync(path),
          actual = realpathSync(path);
        if (!actual.startsWith(root + sep)) throw new Error("Scanner installation link escapes");
        hash.update(canonicalBytes({ kind: "link", path: nameRelative, target }));
      } else if (stat.isFile()) {
        const bytes = readRegular(path, 256 * 1024 * 1024 - total);
        total += bytes.length;
        hash.update(
          canonicalBytes({
            kind: "file",
            path: nameRelative,
            sha256: sha256(bytes),
            byteLength: bytes.length,
          }),
        );
      } else throw new Error("Unsupported scanner installation entry");
    }
  };
  walk(root);
  return hash.digest("hex");
}
function verifyPackedFiles(tarball, packageRoot) {
  const tar = gunzipSync(tarball, { maxOutputLength: 256 * 1024 * 1024 });
  let count = 0;
  const seen = new Set();
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    let checksum = 0;
    for (let index = 0; index < 512; index++)
      checksum += index >= 148 && index < 156 ? 32 : header[index];
    if (
      checksum !==
      Number.parseInt(header.subarray(148, 156).toString("ascii").replace(/\0.*$/, "").trim(), 8)
    )
      throw new Error("Invalid package tar checksum");
    const field = (start, end) => header.subarray(start, end).toString("utf8").replace(/\0.*$/, "");
    const prefix = field(345, 500),
      name = (prefix ? `${prefix}/` : "") + field(0, 100),
      sizeText = field(124, 136).trim(),
      type = field(156, 157);
    if (!/^[0-7]+$/.test(sizeText)) throw new Error("Invalid package tar size");
    const size = Number.parseInt(sizeText, 8),
      start = offset + 512,
      end = start + size;
    if (!Number.isSafeInteger(size) || end > tar.length || ++count > 100000)
      throw new Error("Invalid package tar bounds");
    if (type === "0" || type === "") {
      if (
        !name.startsWith("package/") ||
        name
          .slice(8)
          .split("/")
          .some((part) => !part || part === "." || part === "..") ||
        name.includes("\\") ||
        seen.has(name)
      )
        throw new Error("Invalid packed package path");
      seen.add(name);
      const actual = readRegular(join(packageRoot, name.slice(8)), 256 * 1024 * 1024);
      if (!actual.equals(tar.subarray(start, end)))
        throw new Error("Installed scanner differs from reviewed tarball");
    } else if (type !== "5") throw new Error("Unsupported package tar entry");
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!seen.has("package/package.json") || !seen.has("package/dist/public/host.js"))
    throw new Error("Scanner package entries missing");
}
export async function loadScanner(scannerTarball, scannerInstall, sourceCommit) {
  const install = resolve(scannerInstall),
    modules = join(install, "node_modules"),
    packageRoot = join(modules, "@aihq", "scan");
  if (lstatSync(packageRoot).isSymbolicLink() || !lstatSync(packageRoot).isDirectory())
    throw new Error("Scanner must be an installed packed directory");
  const bytes = readRegular(scannerTarball, 64 * 1024 * 1024);
  verifyPackedFiles(bytes, packageRoot);
  const installationSha256 = treeDigest(modules),
    require = createRequire(join(install, "package.json"));
  const packageManifest = JSON.parse(
    readRegular(require.resolve("@aihq/scan/package.json"), 1048576).toString("utf8"),
  );
  const publicEntry = (name) => {
    const entry = packageManifest.exports?.[`./${name}`]?.import;
    if (typeof entry !== "string" || !entry.startsWith("./") || entry.split("/").includes(".."))
      throw new Error("Public scanner export missing");
    return pathToFileURL(resolve(packageRoot, entry)).href;
  };
  const contracts = await import(publicEntry("contracts"));
  if (
    contracts.contractSupport?.package?.name !== packageManifest.name ||
    contracts.contractSupport?.package?.version !== packageManifest.version ||
    contracts.contractSupport?.package?.name !== "@aihq/scan" ||
    !contracts.contractSupport.contracts.some(
      (contract) => contract.id === "urn:aihq:scan:artifact:1.0.0",
    )
  )
    throw new Error("Scanner contract unsupported");
  const identity = {
    name: "@aihq/scan",
    version: contracts.contractSupport.package.version,
    sourceCommit,
    tarballSha256: sha256(bytes),
    installationSha256,
  };
  const host = await import(publicEntry("host")),
    read = await import(publicEntry("read"));
  return {
    identity,
    host,
    read,
    verifyUnchanged() {
      if (
        treeDigest(modules) !== installationSha256 ||
        sha256(readRegular(scannerTarball, 64 * 1024 * 1024)) !== identity.tarballSha256
      )
        throw new Error("Scanner installation changed during operation");
    },
  };
}
