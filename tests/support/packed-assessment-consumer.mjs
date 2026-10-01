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
  compareMaterialInventories,
  createRetainedObservationsV1,
  deliverMaterialChange,
  prepareArtifact,
  runScan,
  signArtifact,
} from "@aihq/scan/host";

const manifest = JSON.parse(readFileSync("node_modules/@aihq/scan/package.json", "utf8"));
assert.deepEqual(contractSupport.package, { name: manifest.name, version: manifest.version });
assert.equal(contractSupport.schema, "urn:aihq:package-support:1.0.0");
assert.equal(contractSupport.contracts.length, 6);
for (const name of ["request", "run-result", "report", "artifact", "evidence-association", "material-change"]) {
  const schema = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.json`)), "utf8"));
  assert.equal(schema.$id, `urn:aihq:scan:${name}:1.0.0`);
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(contractSupport.contracts.find(entry => entry.id === schema.$id), {
    id: schema.$id,
    role: { request: "accepts", "run-result": "produces", report: "both", artifact: "both", "evidence-association": "accepts", "material-change": "both" }[name],
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
const request = {
  schema: "urn:aihq:scan:request:1.0.0",
  source: { kind: "local", path: source },
  selection: { paths: "all", excludedPaths: [] },
  detectors: [
    { detectorId: "detector.aih-native", configuration: {} },
    { detectorId: "detector.unavailable", configuration: {} },
  ],
};
const retained = createRetainedObservationsV1();
const result = await runScan(request, { retained });
assert.equal(result.status, "assessment");
assert.equal(result.report.completion, "partial");
assert.equal(result.report.results.length, 2);
assert.equal(result.report.results.find((entry) => entry.detectorId === "detector.aih-native").outcome, "succeeded");
assert.equal(result.report.results.find((entry) => entry.detectorId === "detector.unavailable").outcome, "refused");
assert.equal(result.report.producer.version, manifest.version);
assert.equal(JSON.stringify(result.report).includes(source), false);
assert(result.annexes.length > 0, "The installed assessment binds nonempty native annex bytes");
const repeated = await runScan(request, { retained });
assert.equal(repeated.status, "assessment");
assert.equal(repeated.report.completion, "partial");
assert.equal(repeated.report.results[0].observations[0].origin, "reused");
assert.deepEqual(repeated.report.results[0].observations[0].body, result.report.results[0].observations[0].body);
assert.deepEqual(repeated.annexes, result.annexes);
assert.notEqual(repeated.scanId, result.scanId);

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
const priorPath = resolve("prior-artifact.json");
writeFileSync(priorPath, signed.bytes);
const imported = await runScan({
  ...request,
  priorArtifacts: [{ scanId: result.scanId, location: { kind: "file", path: priorPath } }],
}, {
  reuseTrust: { keys: [{ identity: "consumer-organization", keyId, publicKeySpkiBase64: spki.toString("base64") }], publishers: [] },
});
assert.equal(imported.status, "assessment");
assert.equal(imported.report.completion, "partial");
assert.equal(imported.report.results[0].observations[0].origin, "reused");
assert.equal(imported.report.results[0].observations[0].fromScanId, result.scanId);
assert.deepEqual(imported.report.results[0].observations[0].body, result.report.results[0].observations[0].body);
assert.deepEqual(imported.annexes, result.annexes);

const materialInventory = (scanId, digest) => ({
  scanId, projection: "aih-material-v1", complete: true,
  items: [{ itemId: "skills/review", paths: [{ path: "skills/review/SKILL.md", sha256: digest.repeat(64) }], metadata: { install: "copy" } }],
});
const material = await compareMaterialInventories({
  sourceId: "https://github.com/example/skills",
  before: materialInventory(result.scanId, "1"), after: materialInventory(repeated.scanId, "2"),
});
assert.equal(material.status, "compared");
assert.equal(material.materialChange.schema, "urn:aihq:scan:material-change:1.0.0");
assert.equal(material.materialChange.changes.length, 1);
assert.equal(material.materialChange.changes[0].kind, "modified");
assert.equal(material.materialChange.changes[0].beforeSha256, "0c3d7c0efc10d1a8471d3c7c3c8e4cba0c7628f3bce18757af83e7e319230e80");
assert.notEqual(material.materialChange.changes[0].afterSha256, material.materialChange.changes[0].beforeSha256);
const disabledDelivery = await deliverMaterialChange({ summary: material.materialChange, enabled: false });
assert.equal(disabledDelivery.results[0].status, "failed");
assert.equal(disabledDelivery.results[0].diagnostics[0].code, "delivery-disabled");
assert.deepEqual(disabledDelivery.retryableSummary, material.materialChange);
const artifactBeforeDelivery = new Uint8Array(signed.bytes);
let deliveredIssue;
const deliveryTransport = {
  listIssues: async () => ({ issues: deliveredIssue ? [deliveredIssue] : [], hasNextPage: false }),
  createIssue: async ({ body }) => (deliveredIssue = { number: 1, state: "open", body, html_url: "https://github.com/example/tracker/issues/1" }),
  updateIssue: async ({ body }) => (deliveredIssue = { ...deliveredIssue, body }),
};
const enabledDeliveryInput = { summary: material.materialChange, enabled: true, target: { owner: "example", repository: "tracker" }, credential: "test-only", transport: deliveryTransport };
assert.equal((await deliverMaterialChange(enabledDeliveryInput)).results[0].status, "created");
assert.equal((await deliverMaterialChange(enabledDeliveryInput)).results[0].status, "updated");
deliveredIssue.state = "closed";
assert.equal((await deliverMaterialChange(enabledDeliveryInput)).results[0].status, "closed-disposition");
assert.deepEqual(signed.bytes, artifactBeforeDelivery);
assert.equal((await readArtifact(signed.bytes)).scanId, result.scanId);

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
  materialChange: material.materialChange.changes[0].kind,
}) + "\n");
