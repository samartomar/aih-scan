// Loads the built portable entries (@aihq/scan/contracts and /read) in a realm with only
// browser-like globals — no process, Buffer, require, fs, subprocesses or fetch — refusing every
// Node built-in import, and exercises the readers against the shared corpus.
// Usage: node --experimental-vm-modules portable-realm-v1.mjs <dist-dir> <corpus-dir>
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createContext, runInContext, SourceTextModule } from "node:vm";
import { webcrypto } from "node:crypto";

const [dist, corpus] = process.argv.slice(2);
const context = createContext({ TextEncoder, TextDecoder, crypto: webcrypto, atob, btoa, URL });
for (const name of ["process", "Buffer", "require", "fetch", "setImmediate"])
  assert.equal(runInContext(`typeof ${name}`, context), "undefined", name);
const modules = new Map();
const moduleFor = (url) => {
  if (modules.has(url)) return modules.get(url);
  const module = new SourceTextModule(readFileSync(fileURLToPath(url), "utf8"), { context, identifier: url });
  modules.set(url, module);
  return module;
};
const link = (specifier, referencing) => {
  if (isBuiltin(specifier)) throw new Error(`portable entry imported a host module: ${specifier}`);
  if (!specifier.startsWith("./") && !specifier.startsWith("../")) throw new Error(`unexpected dependency: ${specifier}`);
  return moduleFor(new URL(specifier, referencing.identifier).href);
};
const load = async (entry) => {
  const module = moduleFor(pathToFileURL(join(dist, "public", entry)).href);
  await module.link(link);
  await module.evaluate();
  return module.namespace;
};
const contracts = await load("contracts.js");
const read = await load("read.js");

const bytesIn = (bytes) => {
  context.b64 = Buffer.from(bytes).toString("base64");
  return runInContext("Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))", context);
};
const file = (...parts) => readFileSync(join(corpus, ...parts));
for (const name of ["risky", "clean", "not-assessed"]) {
  const summaryBytes = bytesIn(file(name, "summary.json"));
  const summary = read.readSummary(summaryBytes);
  assert.equal(summary.status, "ok", name);
  for (const entry of summary.summary.sarif) {
    const findings = await read.readFindings(summary.summary, bytesIn(file(name, entry.path)), summary.summary.scanKey);
    assert.equal(findings.status, "ok", `${name} findings`);
    if (name === "risky") assert.ok(findings.findings.some((f) => f.code === "trust.prompt-injection"));
  }
  const content = JSON.parse(file(name, "content.json").toString("utf8"));
  context.contentJson = JSON.stringify(content);
  const files = runInContext(
    "Object.entries(JSON.parse(contentJson)).map(([path, f]) => ({ path, mode: f.mode, bytes: new TextEncoder().encode(f.text) }))",
    context,
  );
  const match = await read.matchScan(summary.summary, files);
  assert.equal(match.status, "ok", JSON.stringify(match));
  assert.equal(match.matches, true, `${name} matches`);
  assert.equal(match.signer, null);
  assert.equal(match.scanKey, summary.summary.scanKey);
  const changed = runInContext("(files) => files.map((f, i) => i === 0 ? { ...f, bytes: new TextEncoder().encode('changed') } : f)", context)(files);
  assert.equal((await read.matchScan(summary.summary, changed)).matches, false);
}
// Malformed and unsupported inputs are returned results.
assert.equal(read.readSummary(bytesIn(Buffer.from("{"))).status, "invalid");
const unsupported = JSON.parse(file("clean", "summary.json").toString("utf8"));
unsupported.format = "aih-scan-summary/2";
assert.equal(read.readSummary(bytesIn(Buffer.from(JSON.stringify(unsupported)))).status, "unsupported-version");
const clean = read.readSummary(bytesIn(file("clean", "summary.json"))).summary;
const mismatch = await read.readFindings(clean, bytesIn(file("risky", "sarif", readFileSync(join(corpus, "risky", "summary.json"), "utf8").match(/sarif\/([0-9a-f]{64})\.sarif/)[0].slice(6))), clean.scanKey);
assert.equal(mismatch.message, "Findings don't match this scan");
// Contracts data and functions run in the realm.
assert.equal(contracts.formats.summary, "aih-scan-summary/1");
assert.equal(contracts.scoreFindings([{ tool: "t", ruleId: "r", code: "trust.malicious-code", severity: "HIGH", confidence: 0.9, part: "code", path: "a", line: 1 }]).score, 29);
assert.equal(
  await contracts.scanKeyOf([{ path: ".mcp.json", mode: "100644", bytes: runInContext("new TextEncoder().encode('{\"mcpServers\":{\"remote\":{\"url\":\"https://mcp.example.com/sse\"}}}\\n')", context) }]),
  "git-sha1:23f948e8a00fa0cb22c78c7c51eeb6f0a6f7cb44",
);
assert.equal(contracts.validateRequest({ format: "aih-scan-request/9" }).status, "unsupported-version");
process.stdout.write("portable-realm-ok\n");
