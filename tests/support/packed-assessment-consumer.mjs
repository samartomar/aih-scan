// Copied into an isolated installed consumer by package-install-v2.test.ts.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, webcrypto } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire, isBuiltin } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, runInContext, SourceTextModule } from "node:vm";
import { contractSupport, entrySupport } from "@aihq/scan/contracts";
import * as readApi from "@aihq/scan/read";
import { coverageBatchLimits, maxContentDescriptors, readArtifact, readContentCoverage, readContentCoverageBatch, readReport } from "@aihq/scan/read";
import { listDetectorCapabilitiesV1 } from "@aihq/scan";
import { exerciseSummarySelection } from "./summary-selection-cases.mjs";
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
assert.equal(contractSupport.contracts.length, 7);
// Exactly the package-support 1.0.0 entry shape; lifecycle status is the sibling entrySupport.
assert.deepEqual(contractSupport.entries, [
  { export: "@aihq/scan/contracts", runtime: "portable" },
  { export: "@aihq/scan/read", runtime: "portable" },
  { export: "@aihq/scan/host", runtime: "node", nodeRange: ">=24.15.0 <25" },
  { export: "@aihq/scan", runtime: "node", nodeRange: ">=24.15.0 <25" },
]);
assert.equal(entrySupport.package, contractSupport.package);
assert.deepEqual(entrySupport.entries.map(({ export: name, status }) => [name, status]), [
  ["@aihq/scan/contracts", "current"],
  ["@aihq/scan/read", "current"],
  ["@aihq/scan/host", "current"],
  ["@aihq/scan", "compatibility-only"],
]);
for (const name of ["request", "run-result", "report", "artifact", "evidence-association", "material-change", "detector-definition"]) {
  const schema = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.json`)), "utf8"));
  assert.equal(schema.$id, `urn:aihq:scan:${name}:1.0.0`);
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(contractSupport.contracts.find(entry => entry.id === schema.$id), {
    id: schema.$id,
    role: { request: "accepts", "run-result": "produces", report: "both", artifact: "both", "evidence-association": "accepts", "material-change": "both", "detector-definition": "accepts" }[name],
    schemaExport: `@aihq/scan/schemas/${name}/1.0.0.json`,
  });
}
const require = createRequire(import.meta.url);
const exampleDocument = JSON.parse(readFileSync(require.resolve("@aihq/scan/schemas/examples/1.0.0.json"), "utf8"));
assert.match(exampleDocument.description, /Representative static JSON examples/);
assert.match(exampleDocument.description, /unsigned and asserts no producer authenticity/);
const examples = exampleDocument.examples;
const summarySelection = await exerciseSummarySelection(readApi, examples.find(entry => entry.format === "urn:aihq:scan:report:1.0.0").valid, listDetectorCapabilitiesV1().map(entry => entry.detectorId), JSON.parse(readFileSync("node_modules/@aihq/scan/examples/detector-definitions/definition.json", "utf8")));
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

// Content coverage over installed read results: exact match, mismatch, partial
// coverage, a refused sibling detector and unsupported or invalid reads.
const readmeEntry = result.report.source.capture.entries.find((entry) => entry.path === "README.md");
const readme = { path: "README.md", sha256: readmeEntry.sha256, byteLength: readmeEntry.byteLength };
const preparedRead = await readArtifact(prepared.bytes);
// Distinct valid envelopes wrap one report identity, with authentication kept
// per acquisition. Corrupt supplied annex bytes still fail the artifact reader.
const anotherKey = generateKeyPairSync("ed25519");
const anotherKeyId = `ed25519:${createHash("sha256").update(anotherKey.publicKey.export({type:"spki",format:"der"})).digest("hex")}`;
const anotherEnvelope = await signArtifact({ report: result.report, annexes, signer: {keyId:anotherKeyId,privateKey:anotherKey.privateKey} });
const envelopes = await readApi.selectAssessments({
  assessments: [prepared.bytes, anotherEnvelope.bytes].map((bytes,index)=>({sourceId:"fixture",location:String(index),format:"artifact",bytes,authentication:index===0?{status:"unverifiable",reason:"unsigned"}:{status:"unverifiable",reason:"untrusted-key"}})),
  context:{sourceIds:["fixture"],descriptors:[readme],selection:result.report.selection},
  evaluationTime:result.report.createdAt,checks:[],
});
assert.equal(envelopes.status,"selected");assert.equal(envelopes.assessments.length,1);assert.equal(envelopes.assessments[0].acquisitions.length,2);assert.equal(envelopes.conflicts.length,0);
const corruptAnnex=structuredClone(prepared.artifact);corruptAnnex.annexes[0].bytesBase64="AA==";
assert.equal((await readApi.readSummary({format:"artifact",bytes:canonicalExampleBytes(corruptAnnex)})).status,"invalid");
const matchedCoverage = await readContentCoverage({ read: preparedRead, descriptors: [readme] });
assert.equal(matchedCoverage.status, "matched");
assert.equal(matchedCoverage.scanId, result.scanId);
assert.equal(matchedCoverage.authenticity, "unchecked");
assert.equal("annexBytes" in matchedCoverage, false);
assert.equal(matchedCoverage.observations.length, 1);
assert.equal(matchedCoverage.observations[0].detector.detectorId, "detector.aih-native");
assert.deepEqual(matchedCoverage.observations[0].coverage.coveredPaths, ["README.md"]);
assert(matchedCoverage.observations[0].annexes.length > 0);
assert.deepEqual(matchedCoverage.detectorsWithoutCoverage, ["detector.unavailable"]);
// The installed public seam answers independent queries without repeating payloads.
const batchCoverage = await readContentCoverageBatch({ read: preparedRead, queries: [
  { descriptors: [readme] },
  { descriptors: [{ ...readme, sha256: "0".repeat(64) }] },
  { descriptors: [readme] },
  { descriptors: [] },
] });
assert.equal(batchCoverage.status, "complete");
assert.deepEqual(batchCoverage.results.map(row => row.status), ["matched", "mismatched", "matched", "invalid"]);
assert.equal(batchCoverage.observations.length, matchedCoverage.observations.length);
for (const at of [0, 2]) {
  const { observationIndexes, ...row } = batchCoverage.results[at];
  assert.deepEqual({ ...row, observations: observationIndexes.map(index => batchCoverage.observations[index]) }, matchedCoverage);
}
assert(Object.isFrozen(batchCoverage.observations[0].input.targetPaths));
assert.equal(coverageBatchLimits.maxQueries, 4096);
assert.equal((await readContentCoverageBatch({ read: preparedRead, queries: [], trusted: true })).status, "invalid");
const mismatchedCoverage = await readContentCoverage({ read: preparedRead, descriptors: [{ ...readme, sha256: "0".repeat(64) }] });
assert.equal(mismatchedCoverage.status, "mismatched");
assert.deepEqual(mismatchedCoverage.unmatchedPaths, ["README.md"]);
const unsupportedCoverage = await readContentCoverage({
  read: await readReport(new TextEncoder().encode('{"schema":"urn:aihq:scan:report:2.0.0"}')),
  descriptors: [readme],
});
assert.equal(unsupportedCoverage.status, "unavailable");
assert.equal(unsupportedCoverage.reason, "unsupported-report");
const invalidCoverage = await readContentCoverage({ read: await readReport(new TextEncoder().encode("{}")), descriptors: [readme] });
assert.equal(invalidCoverage.reason, "invalid-read");
assert.equal((await readContentCoverage({ read: preparedRead, descriptors: [] })).status, "invalid");
assert.equal(maxContentDescriptors, 10000);
const partialSource = resolve("partial-coverage-subject");
mkdirSync(partialSource);
writeFileSync(resolve(partialSource, "A.md"), "# A\n");
writeFileSync(resolve(partialSource, "B.md"), "# B\n");
const partial = await runScan({ ...request, source: { kind: "local", path: partialSource }, selection: { paths: ["A.md"], excludedPaths: [] } });
assert.equal(partial.status, "assessment");
const partialDescriptors = partial.report.source.capture.entries
  .filter((entry) => entry.kind === "file")
  .map(({ path, sha256, byteLength }) => ({ path, sha256, byteLength }));
const partialCoverage = await readContentCoverage({ read: await readReport(canonicalExampleBytes(partial.report)), descriptors: partialDescriptors });
assert.equal(partialCoverage.status, "matched");
assert.equal(partialCoverage.observations.length, 0);
assert.equal(partialCoverage.excluded["coverage-incomplete"], 1);

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
// Strict JSON inputs are plain objects of the reader's own realm, as a browser
// consumer would construct them.
context.descriptorJson = JSON.stringify([readme]);
const portableDescriptors = runInContext("JSON.parse(descriptorJson)", context);
const portableCoverage = await portableRead.namespace.readContentCoverage({ read: portableResult, descriptors: portableDescriptors });
const portableBatchCoverage = await portableRead.namespace.readContentCoverageBatch({ read: portableResult, queries: [{ descriptors: portableDescriptors }] });
assert.equal(portableBatchCoverage.status, "complete");
assert.equal(portableBatchCoverage.results[0].status, "matched");

assert.equal(portableCoverage.status, "matched");
assert.equal(portableCoverage.observations.length, 1);
context.evidenceBytes = new Uint8Array(signed.bytes);
const portableSummary = await runInContext('globalThis.summaryInput = {format:"artifact",bytes:evidenceBytes};', context);
assert.equal((await portableRead.namespace.readSummary(portableSummary)).status,"read");
context.reportTime = result.report.createdAt;
context.selectionJson = JSON.stringify(result.report.selection);
const portableSelection = runInContext('({assessments:[{sourceId:"fixture",location:"memory",format:"artifact",bytes:evidenceBytes}],context:{sourceIds:["fixture"],descriptors:JSON.parse(descriptorJson),selection:JSON.parse(selectionJson)},evaluationTime:reportTime,checks:[]})',context);
const portableSelected = await portableRead.namespace.selectAssessments(portableSelection);
assert.equal(portableSelected.status,"selected");
assert.equal(portableSelected.selectedScanId,result.scanId);

process.stdout.write(JSON.stringify({
  installedVersion: manifest.version,
  completion: result.report.completion,
  annexes: annexes.length,
  read: portableResult.status,
  coverage: [matchedCoverage.status, mismatchedCoverage.status, unsupportedCoverage.status, portableCoverage.status],
  authenticity: authenticated.status,
  portableEntries: ["contracts", "read"],
  materialChange: material.materialChange.changes[0].kind,
  summarySelection,
}) + "\n");
