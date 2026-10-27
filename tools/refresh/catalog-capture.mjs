// Data-only immutable transport. Never install, import or execute capture files.
import { lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ghApi } from "../artifact/gh-api.mjs";
import {
  canonicalBytes, captureCeiling, captureSelector, ceilings, descriptor, digest, object, parseJson, readRegular, sha256, validateFrozenCapture,
} from "./contracts.mjs";

const repository = "samartomar/aih-catalog";
const prefix = `repos/${repository}`;
const same = (a, b) => canonicalBytes(a).equals(canonicalBytes(b));

function decodeCapture(bytes, selector, limits) {
  if (bytes.length !== selector.byteLength || sha256(bytes) !== selector.sha256)
    throw new Error("Capture bytes differ from reviewed selector");
  const value = parseJson(bytes, selector.byteLength, true);
  object(value, ["schema", "inventory", "files"]);
  if (value.schema !== "urn:aihq:scan:catalog-capture:1.0.0" || !same(value.inventory, selector.inventory) ||
    !Array.isArray(value.files) || value.files.length > limits.maxSourceEntries)
    throw new Error("Capture inventory or schema differs");
  const files = value.files.map(file => {
    object(file, ["path", "sha256", "byteLength", "bytesBase64"]);
    const {bytesBase64, ...entry} = file;
    descriptor(entry);
    if (typeof bytesBase64 !== "string" || bytesBase64.length !== 4 * Math.ceil(entry.byteLength / 3))
      throw new Error("Invalid encoded capture length");
    const content = Buffer.from(bytesBase64, "base64");
    if (content.toString("base64") !== bytesBase64 || content.length !== entry.byteLength || sha256(content) !== entry.sha256)
      throw new Error("Capture file bytes differ");
    return {entry, content};
  });
  const frozen = validateFrozenCapture({...selector, files: files.map(file => file.entry)}, limits);
  const inventoryBytes = files.find(file => file.entry.path === selector.inventory.path).content;
  const required = inventoryDescriptors(inventoryBytes, selector.inventory);
  if (required.size !== files.length || files.some(file => !same(required.get(file.entry.path), file.entry)))
    throw new Error("Missing, extra or mismatched inventory material");
  return { frozen, files };
}

const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);

// Release 1.7 package members, as Catalog enumerates them: the single recipe or
// every transition-map recipe, then each material by its package path (legacy
// `path` or extended `packagePath`, never both). Map entries may reference only
// this item's content materials, so the closure carries every recipe input.
function members17(item) {
  if (Object.hasOwn(item, "recipe") === Object.hasOwn(item, "recipes"))
    throw new Error("Item must declare exactly one recipe or recipe map");
  const content = new Set();
  const materials = item.materials.map(member => {
    if (!isRecord(member) || Object.hasOwn(member, "path") === Object.hasOwn(member, "packagePath"))
      throw new Error("Material must declare exactly one package path");
    if (member.role !== "behaviour") content.add(member.id);
    return {...member, path: Object.hasOwn(member, "path") ? member.path : member.packagePath};
  });
  if (!Object.hasOwn(item, "recipes")) return [item.recipe ?? {}, ...materials];
  const map = item.recipes;
  if (!isRecord(map) || Object.keys(map).length === 0 || Object.keys(map).length > 64)
    throw new Error("Invalid recipe map");
  const recipes = Object.values(map);
  for (const entry of recipes)
    if (!isRecord(entry) || !Array.isArray(entry.materials) || entry.materials.some(id => !content.has(id)))
      throw new Error("Recipe map references undeclared material");
  return [...recipes, ...materials];
}

// Catalog pairs each baseline-bound release format with one inventory/projection.
// Release 1.6 (content-inventory 1.1.0) is not a supported capture input.
const inventoryVersions = Object.freeze([
  {release: "urn:aihq:catalog:release:1.5.0", inventory: "urn:aihq:catalog:content-inventory:1.0.0",
    projection: "urn:aihq:catalog:release-content:1.0.0", members: item => [item.recipe, ...item.materials].map(member => member ?? {})},
  {release: "urn:aihq:catalog:release:1.7.0", inventory: "urn:aihq:catalog:content-inventory:1.2.0",
    projection: "urn:aihq:catalog:release-content:1.2.0", members: members17},
]);

function inventoryDescriptors(inventoryBytes, inventoryDescriptor) {
  if (inventoryBytes.length > 16 * 1024 * 1024) throw new Error("Inventory bound exceeded");
  const text = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(inventoryBytes);
  // Inventory is Catalog canonical JSON plus LF. Unlike maintainer controls,
  // authored metadata may contain fractional or negative numbers. Round-trip
  // exact canonical bytes to refuse duplicate keys and lossy number spellings.
  const encode = (value, depth = 0) => {
    if (depth > 32) throw new Error("Inventory depth exceeded");
    if (typeof value === "string") {
      if (!value.isWellFormed() || value.normalize("NFC") !== value) throw new Error("Invalid inventory string");
      return JSON.stringify(value);
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || Object.is(value, -0) || (Number.isInteger(value) && !Number.isSafeInteger(value)))
        throw new Error("Invalid inventory number");
      return JSON.stringify(value);
    }
    if (value === null || typeof value === "boolean") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(item => encode(item, depth + 1)).join(",")}]`;
    return `{${Object.keys(value).sort().map(key => `${encode(key, depth + 1)}:${encode(value[key], depth + 1)}`).join(",")}}`;
  };
  const inventory = JSON.parse(text);
  if (`${encode(inventory)}\n` !== text) throw new Error("Inventory must retain canonical Catalog bytes");
  object(inventory, ["schema", "projection", "release"]);
  const version = inventoryVersions.find(entry => entry.inventory === inventory.schema);
  if (!version || inventory.projection !== version.projection ||
    inventory.release?.schema !== version.release ||
    inventory.release?.package?.name !== "@aihq/catalog" ||
    Object.hasOwn(inventory.release, "baseline") || !Array.isArray(inventory.release.items) ||
    inventory.release.items.length > 10000)
    throw new Error("Unsupported Catalog inventory");
  // This is byte closure, not a replacement for Catalog's semantic reader.
  const required = new Map([[inventoryDescriptor.path, inventoryDescriptor]]);
  for (const item of inventory.release.items) {
    if (!isRecord(item) || !Array.isArray(item.materials) || item.materials.length > 4096)
      throw new Error("Missing material declarations");
    for (const member of version.members(item)) {
      const entry = descriptor({path: member.path, sha256: member.sha256, byteLength: member.byteLength});
      if (required.has(entry.path) && !same(required.get(entry.path), entry))
        throw new Error("Conflicting inventory descriptors");
      required.set(entry.path, entry);
    }
  }
  return required;
}

// Offline preparation only. Root is explicitly selected by the maintainer, never
// supplied by the remote input. Every traversed component must be a real directory.
export function prepareCatalogCapture({root, inventoryPath, inventorySha256}) {
  const base = resolve(root);
  const read = (path, maximum) => {
    const pieces = path.split("/"); pieces.pop();
    let current = base;
    for (const piece of ["", ...pieces]) {
      current = join(current, piece);
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Linked capture directory refused");
    }
    return readRegular(join(base, path), maximum);
  };
  descriptor({path: inventoryPath, sha256: digest(inventorySha256), byteLength: 0});
  const inventoryBytes = read(inventoryPath, 16 * 1024 * 1024);
  if (sha256(inventoryBytes) !== inventorySha256) throw new Error("Reviewed inventory differs");
  const inventory = {path: inventoryPath, sha256: inventorySha256, byteLength: inventoryBytes.length};
  const required = [...inventoryDescriptors(inventoryBytes, inventory).values()].sort((a,b) => a.path < b.path ? -1 : 1);
  // Check path/count/length closure before opening declared files.
  const selector = {releaseId: "1", assetId: "1", sha256: "0".repeat(64), byteLength: 1, inventory};
  validateFrozenCapture({...selector, files: required}, ceilings);
  const files = required.map(entry => {
    const content = read(entry.path, entry.byteLength);
    if (content.length !== entry.byteLength || sha256(content) !== entry.sha256) throw new Error("Staged material differs");
    return {...entry, bytesBase64: content.toString("base64")};
  });
  const bytes = canonicalBytes({schema: "urn:aihq:scan:catalog-capture:1.0.0", inventory, files});
  if (bytes.length > captureCeiling) throw new Error("Encoded capture transport bound exceeded");
  decodeCapture(bytes, {...selector, byteLength: bytes.length, sha256: sha256(bytes)}, ceilings);
  return bytes;
}

export async function acquireCatalogCapture(target, limits, transport = ghApi()) {
  const selector = captureSelector(target.capture);
  const repo = await transport.json(prefix);
  if (repo?.full_name !== repository || repo.private !== false || repo.archived !== false || repo.owner?.id !== 9993940)
    throw new Error("Catalog repository identity differs");
  const tag = `catalog-capture-${selector.sha256}`;
  const release = await transport.json(`${prefix}/releases/${selector.releaseId}`);
  if (release?.id !== Number(selector.releaseId) || release.immutable !== true || release.draft !== false ||
    release.tag_name !== tag || release.target_commitish !== target.commit)
    throw new Error("Capture release is not the selected immutable source");
  const ref = await transport.json(`${prefix}/git/ref/tags/${tag}`);
  if (ref?.ref !== `refs/tags/${tag}` || ref.object?.type !== "commit" || ref.object.sha !== target.commit)
    throw new Error("Capture release tag differs from pinned source commit");
  const assets = await transport.json(`${prefix}/releases/${selector.releaseId}/assets?per_page=2`);
  if (!Array.isArray(assets) || assets.length !== 1) throw new Error("Capture release must have exactly one asset");
  const asset = assets[0];
  if (asset?.id !== Number(selector.assetId) || asset.name !== "catalog-capture.json" || asset.state !== "uploaded" ||
    asset.size !== selector.byteLength || asset.digest !== `sha256:${selector.sha256}` ||
    asset.url !== `https://api.github.com/${prefix}/releases/assets/${selector.assetId}`)
    throw new Error("Capture asset custody differs");
  const response = await transport.bytes(`${prefix}/releases/assets/${selector.assetId}`, {
    maximum: selector.byteLength, accept: "application/octet-stream", timeout: 120000,
  });
  if (response.status !== 200) throw new Error("Capture asset unavailable");
  const decoded = decodeCapture(response.bytes, selector, limits);
  if (target.capture.files && !same(target.capture, decoded.frozen)) throw new Error("Frozen capture changed");
  return decoded.frozen;
}

// Reacquire and recheck before creating a private owned root. No caller-supplied
// filesystem destination enters this boundary or the public capture input.
export async function materializeCatalogCapture(target, limits, transport = ghApi()) {
  let retained;
  const capture = await acquireCatalogCapture(target, limits, {
    json: (...args) => transport.json(...args),
    bytes: async (...args) => { const response = await transport.bytes(...args); retained = response.bytes; return response; },
  });
  const decoded = decodeCapture(retained, captureSelector(capture), limits);
  const root = mkdtempSync(join(tmpdir(), "aih-catalog-capture-"));
  try {
    for (const {entry, content} of decoded.files) {
      const path = join(root, entry.path);
      mkdirSync(dirname(path), {recursive: true, mode: 0o700});
      writeFileSync(path, content, {flag: "wx", mode: 0o600});
    }
    return {root, cleanup: () => rmSync(root, {recursive: true, force: true})};
  } catch (error) { rmSync(root, {recursive: true, force: true}); throw error; }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 6) throw new Error("Expected staged root, inventory relative path, inventory SHA256 and new output");
    const bytes = prepareCatalogCapture({root: process.argv[2], inventoryPath: process.argv[3], inventorySha256: process.argv[4]});
    writeFileSync(process.argv[5], bytes, {flag: "wx", mode: 0o600});
    process.stdout.write(`${JSON.stringify({event: "scan-catalog-capture.prepared", sha256: sha256(bytes), byteLength: bytes.length, tag: `catalog-capture-${sha256(bytes)}`})}\n`);
  } catch {
    process.stderr.write(`${JSON.stringify({event: "scan-catalog-capture.refused", reason: "inventory-or-material-or-output-refused"})}\n`);
    process.exitCode = 2;
  }
}
