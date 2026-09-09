import { lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { canonicalBaselineVetRequestV1Bytes, parseBaselineVetRequestV1Json } from "../dist/baseline/batch-v1.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "../dist/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../dist/observation/source-hash-v1.js";

const fail = (reason) => { throw new Error(`AIH delivery publication rejected: ${reason}`); };
const [materialDirectory, coreCommit, outputDirectory, ...extra] = process.argv.slice(2);
if (extra.length || !materialDirectory || !outputDirectory || !/^[a-f0-9]{40}$/.test(coreCommit ?? "")) fail("arguments");
const directory = (path) => {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("real directory required");
  return realpathSync(path);
};
const read = (path, max = 16 * 1024 * 1024) => {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > max) fail("bounded regular file required");
  const bytes = readFileSync(path);
  if (bytes.length !== stat.size) fail("file changed during read");
  return bytes;
};
const decode = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const root = directory(resolve(materialDirectory));
const manifestBytes = read(join(root, "materialization.json"), 65536);
const manifest = parseStrictJsonObjectV1(decode(manifestBytes), "AIH delivery materialization");
if (Object.keys(manifest).sort().join(",") !== "authority,coreCommit,requestSha256s,sourceRoot,sourceTreeSha256,version" ||
    manifest.version !== "aih-delivery-materialization/v1" || manifest.authority !== "none" ||
    manifest.coreCommit !== coreCommit || typeof manifest.sourceRoot !== "string" ||
    !isAbsolute(manifest.sourceRoot) || /[\r\n\0]/.test(manifest.sourceRoot) ||
    !/^[a-f0-9]{64}$/.test(manifest.sourceTreeSha256 ?? "") ||
    !Array.isArray(manifest.requestSha256s) || manifest.requestSha256s.length < 1 || manifest.requestSha256s.length > 1000 ||
    manifest.requestSha256s.some((value) => typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) ||
    new Set(manifest.requestSha256s).size !== manifest.requestSha256s.length) fail("manifest identity or schema");
if (!manifestBytes.equals(canonicalStrictJsonBytesV1(manifest))) fail("noncanonical manifest");
const requestedSource = resolve(manifest.sourceRoot);
if (dirname(requestedSource) !== root || !/^aih-scan-material-[A-Za-z0-9_-]+$/.test(basename(requestedSource))) fail("source root containment");
const source = directory(requestedSource);
if (source !== requestedSource || dirname(source) !== root) fail("resolved source root containment");
if (hashSourceTreeV1(source).treeSha256 !== manifest.sourceTreeSha256) fail("source tree digest");
const names = manifest.requestSha256s.map((_, index) => `batch-${String(index + 1).padStart(3, "0")}.request.json`);
const expectedNames = [...names, "coverage.json", "materialization.json", basename(source)].sort();
if (JSON.stringify(readdirSync(root).sort()) !== JSON.stringify(expectedNames)) fail("material directory layout");
read(join(root, "coverage.json")); // Core-owned metadata is never admission authority here.
const componentIds = new Set();
const requests = names.map((name, index) => {
  const bytes = read(join(root, name));
  const request = parseBaselineVetRequestV1Json(decode(bytes));
  if (!bytes.equals(canonicalBaselineVetRequestV1Bytes(request))) fail("noncanonical request");
  if (request.requestSha256 !== manifest.requestSha256s[index] || request.source.id !== "aih" ||
      request.source.owner !== "samartomar" || request.source.repository !== "ai-harness" ||
      request.source.pinnedCommit !== coreCommit || request.source.treeSha256 !== manifest.sourceTreeSha256) fail("request identity");
  for (const component of request.components) {
    if (componentIds.has(component.id)) fail("duplicate component");
    componentIds.add(component.id);
    if (hashComponentTreeV1(source, component.paths).treeSha256 !== component.treeSha256) fail("component digest");
  }
  return bytes;
});
// Only emit after every request and the actual generated source tree have been checked.
mkdirSync(outputDirectory, { recursive: false });
requests.forEach((bytes, index) => writeFileSync(join(outputDirectory, names[index]), bytes, { flag: "wx", mode: 0o600 }));
process.stdout.write(`${source}\n`);
