// Copied into an isolated installed consumer by package-install-v2.test.ts.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, webcrypto } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule } from "node:vm";
import { contractSupport } from "@aihq/scan/contracts";
import { readArtifact, readReport } from "@aihq/scan/read";
import {
  authenticateArtifact,
  prepareArtifact,
  runScan,
  signArtifact,
} from "@aihq/scan/host";

const manifest = JSON.parse(readFileSync("node_modules/@aihq/scan/package.json", "utf8"));
assert.deepEqual(contractSupport.package, { name: manifest.name, version: manifest.version });
assert.equal(contractSupport.schema, "urn:aihq:package-support:1.0.0");
assert.equal(contractSupport.contracts.length, 5);
for (const name of ["request", "run-result", "report", "artifact", "evidence-association"]) {
  const schema = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.json`)), "utf8"));
  assert.equal(schema.$id, `urn:aihq:scan:${name}:1.0.0`);
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(contractSupport.contracts.find(entry => entry.id === schema.$id), {
    id: schema.$id,
    role: { request: "accepts", "run-result": "produces", report: "both", artifact: "both", "evidence-association": "accepts" }[name],
    schemaExport: `@aihq/scan/schemas/${name}/1.0.0.json`,
  });
}
const examples = JSON.parse(readFileSync("node_modules/@aihq/scan/schemas/examples/1.0.0.json", "utf8")).examples;
assert.equal(examples.length, 5);
const canonicalExampleBytes = (value) => {
  const encode = item => Array.isArray(item) ? `[${item.map(encode).join(",")}]`
    : item !== null && typeof item === "object"
      ? `{${Object.keys(item).sort().map(key => `${JSON.stringify(key)}:${encode(item[key])}`).join(",")}}`
      : JSON.stringify(item);
  return new TextEncoder().encode(encode(value));
};
for (const [format, reader] of [["report", readReport], ["artifact", readArtifact]]) {
  const example = examples.find(entry => entry.format === `urn:aihq:scan:${format}:1.0.0`);
  assert.equal((await reader(canonicalExampleBytes(example.valid))).status, "read");
  assert.equal((await reader(canonicalExampleBytes(example.invalid))).status, "invalid");
}
const invalidRequest = examples.find(entry => entry.format === "urn:aihq:scan:request:1.0.0").invalid;
assert.equal((await runScan(invalidRequest)).phase, "request");

const source = resolve("assessment-subject");
mkdirSync(source);
writeFileSync(resolve(source, "README.md"), "# Public consumer fixture\n");
const result = await runScan({
  schema: "urn:aihq:scan:request:1.0.0",
  source: { kind: "local", path: source },
  selection: { paths: "all", excludedPaths: [] },
  detectors: [
    { detectorId: "detector.aih-native", configuration: {} },
    { detectorId: "detector.unavailable", configuration: {} },
  ],
});
assert.equal(result.status, "assessment");
assert.equal(result.report.completion, "partial");
assert.equal(result.report.results.length, 2);
assert.equal(result.report.results.find((entry) => entry.detectorId === "detector.aih-native").outcome, "succeeded");
assert.equal(result.report.results.find((entry) => entry.detectorId === "detector.unavailable").outcome, "refused");
assert.equal(result.report.producer.version, manifest.version);
assert.equal(JSON.stringify(result.report).includes(source), false);
assert(result.annexes.length > 0, "The installed assessment binds nonempty native annex bytes");

const annexes = result.annexes.map(({ id, bytesBase64 }) => ({ id, bytes: new Uint8Array(Buffer.from(bytesBase64, "base64")) }));
const prepared = await prepareArtifact({ report: result.report, annexes });
assert.equal(prepared.scanId, result.scanId);
assert.equal(prepared.artifact.attestation, undefined);
assert.equal((await readArtifact(prepared.bytes)).authenticity, "unchecked");
assert.equal((await readReport(new Uint8Array(Buffer.from(prepared.artifact.report.bytesBase64, "base64")))).scanId, result.scanId);

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const spki = publicKey.export({ format: "der", type: "spki" });
const keyId = `ed25519:${createHash("sha256").update(spki).digest("hex")}`;
const signed = await signArtifact({ report: result.report, annexes, signer: { keyId, privateKey } });
assert.equal(signed.scanId, result.scanId);
const authenticated = await authenticateArtifact({
  bytes: signed.bytes,
  expectedScanId: result.scanId,
  trust: { keys: [{ identity: "consumer-organization", keyId, publicKeySpkiBase64: spki.toString("base64") }], publishers: [] },
});
assert.equal(authenticated.status, "authenticated");
assert.equal(authenticated.producerIdentity, "consumer-organization");
assert.equal((await authenticateArtifact({ bytes: signed.bytes, expectedScanId: result.scanId, trust: { keys: [], publishers: [] } })).status, "unverifiable");
assert.equal((await readArtifact(signed.bytes)).authenticity, "unchecked");

// Load the actual packed ESM entry graph in a realm without process, Buffer,
// filesystem, subprocesses or network fetch. The harness resolves portable
// package dependencies as a browser bundler would, while refusing Node built-ins.
const context = createContext({ TextEncoder, TextDecoder, Uint8Array, crypto: webcrypto, atob, btoa, URL });
const modules = new Map();
const moduleFor = (url) => {
  if (modules.has(url)) return modules.get(url);
  const module = new SourceTextModule(readFileSync(fileURLToPath(url), "utf8"), { context, identifier: url });
  modules.set(url, module);
  return module;
};
const linkPortable = (specifier, referencing) => {
  if (isBuiltin(specifier)) throw new Error(`Portable entry imported a host module: ${specifier}`);
  return moduleFor(specifier.startsWith("./") || specifier.startsWith("../")
    ? new URL(specifier, referencing.identifier).href
    : import.meta.resolve(specifier));
};
const portableContracts = moduleFor(import.meta.resolve("@aihq/scan/contracts"));
await portableContracts.link(linkPortable);
await portableContracts.evaluate();
assert.equal(portableContracts.namespace.contractSupport.package.version, manifest.version);
const portableRead = moduleFor(import.meta.resolve("@aihq/scan/read"));
await portableRead.link(linkPortable);
await portableRead.evaluate();
const portableResult = await portableRead.namespace.readArtifact(new Uint8Array(signed.bytes));
assert.equal(portableResult.status, "read");
assert.equal(portableResult.scanId, result.scanId);
assert.equal(portableResult.authenticity, "unchecked");

process.stdout.write(JSON.stringify({
  installedVersion: manifest.version,
  completion: result.report.completion,
  annexes: annexes.length,
  read: portableResult.status,
  authenticity: authenticated.status,
  portableEntries: ["contracts", "read"],
}) + "\n");
