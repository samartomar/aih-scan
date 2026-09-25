import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalBaselineVetRequestV1Bytes, parseBaselineVetRequestV1Json } from "../dist/baseline/batch-v1.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "../dist/contract/strict-json-v1.js";

// Maintainer input is data only. Never load code or dependencies from its origin.
// Usage: <set.json> <sha256> <source-id> <owner/repository> <commit> <output-dir> [--overlap <mode>]
// Modes (Core T1's vocabulary): disjoint (the default) refuses a path shared or nested across
// components; compiler-catalog allows that across components and, as Core T1 does, refuses it
// inside one component.
const args = process.argv.slice(2);
let overlap = "disjoint";
if (args.length === 8 && args[6] === "--overlap") overlap = args.splice(6, 2)[1];
const [file, digest, sourceId, repository, commit, output, ...extra] = args;
const fail = (reason) => { throw new Error(`publication request set rejected: ${reason}`); };
if (extra.length || (overlap !== "disjoint" && overlap !== "compiler-catalog") || !file || !output || !/^[0-9a-f]{64}$/.test(digest ?? "") ||
    !/^[a-z0-9][a-z0-9:._-]{0,127}$/.test(sourceId ?? "") ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "") ||
    !/^[0-9a-f]{40}$/.test(commit ?? "")) fail("arguments");
const stat = lstatSync(file);
if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > 16 * 1024 * 1024)
  fail("bounded regular input file required");
const bytes = readFileSync(file);
if (bytes.length !== stat.size || createHash("sha256").update(bytes).digest("hex") !== digest) fail("digest mismatch");
const set = parseStrictJsonObjectV1(new TextDecoder("utf-8", { fatal: true }).decode(bytes), "publication request set");
if (Object.keys(set).sort().join(",") !== "protocol,requests" || set.protocol !== "BaselinePublicationRequestSetV1" ||
    !Array.isArray(set.requests) || set.requests.length < 1 || set.requests.length > 1000) fail("closed request set schema");
const requests = set.requests.map((value) => parseBaselineVetRequestV1Json(canonicalStrictJsonBytesV1(value).toString("utf8")));
const requestIds = new Set();
const componentIds = new Set();
const paths = [];
const treeSha256 = requests[0].source.treeSha256;
for (const request of requests) {
  if (request.source.id !== sourceId || `${request.source.owner}/${request.source.repository}` !== repository ||
      request.source.pinnedCommit !== commit || request.source.treeSha256 !== treeSha256) fail("source identity");
  if (requestIds.has(request.requestSha256)) fail("duplicate request");
  requestIds.add(request.requestSha256);
  for (const component of request.components) {
    if (componentIds.has(component.id)) fail("duplicate component");
    componentIds.add(component.id);
    for (const path of component.paths) paths.push({ path, component: component.id });
  }
}
paths.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
if (overlap === "disjoint") {
  const owners = new Map();
  for (const { path, component } of paths) {
    const segments = path.split("/");
    for (let index = 1; index <= segments.length; index++) {
      const owner = owners.get(segments.slice(0, index).join("/"));
      if (owner !== undefined && owner !== component) fail("overlapping component paths");
    }
    owners.set(path, component);
  }
} else {
  const within = new Map();
  for (const { path, component } of paths) {
    const seen = within.get(component) ?? new Set();
    const segments = path.split("/");
    for (let index = 1; index <= segments.length; index++)
      if (seen.has(segments.slice(0, index).join("/"))) fail(`overlapping paths within component ${component}`);
    seen.add(path);
    within.set(component, seen);
  }
}
// Validate the entire set before creating any output. Existing output fails closed.
mkdirSync(output, { recursive: false });
for (const [index, request] of requests.entries()) {
  writeFileSync(join(output, `batch-${String(index + 1).padStart(3, "0")}.request.json`),
    canonicalBaselineVetRequestV1Bytes(request), { flag: "wx", mode: 0o600 });
}
console.log(`Verified independent publication request set: ${requests.length} requests`);
