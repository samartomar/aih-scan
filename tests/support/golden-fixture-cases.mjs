// Runs in the outside-workspace consumer. All product data and code resolve through exports.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { contractSupport } from "@aihq/scan/contracts";
import { compareMaterialInventories, deliverMaterialChange, runScan } from "@aihq/scan/host";
import { readArtifact, readContentCoverage, readReport } from "@aihq/scan/read";

const canonical = value => {
  const encode = item => Array.isArray(item) ? `[${item.map(encode).join(",")}]`
    : item !== null && typeof item === "object"
      ? `{${Object.keys(item).sort().map(key => `${JSON.stringify(key)}:${encode(item[key])}`).join(",")}}`
      : JSON.stringify(item);
  return new TextEncoder().encode(encode(value));
};
const json = specifier => JSON.parse(readFileSync(new URL(import.meta.resolve(specifier)), "utf8"));

export async function exerciseGoldenFixtures() {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  const manifest = [];
  const fixtures = new Map();
  for (const { id, schemaExport } of contractSupport.contracts) {
    const specifier = schemaExport.replace(/\.json$/, ".fixtures.json");
    const fixture = json(specifier);
    assert.equal(fixture.contractId, id);
    assert.equal(fixture.contractVersion, "1.0.0");
    const schema = json(schemaExport);
    assert.equal(schema.$id, id);
    const validate = ajv.compile(schema);
    assert(fixture.cases.some(entry => entry.expectation === "accept"));
    assert(fixture.cases.some(entry => entry.expectation === "refuse"));
    for (const entry of fixture.cases) {
      assert(["accept", "refuse"].includes(entry.expectation));
      const valid = validate(entry.value);
      // Digest corruption is intentionally schema-valid and must be refused by the reader.
      assert.equal(valid, entry.validation === "reader" || entry.expectation === "accept",
        `${specifier} ${entry.name}: ${JSON.stringify(validate.errors)}`);
      if (entry.expectation === "accept") assert.equal(entry.code, null);
      else assert.equal(typeof entry.code, "string");
      manifest.push({ contractId: id, version: fixture.contractVersion, specifier,
        name: entry.name, expectation: entry.expectation, code: entry.code });
    }
    fixtures.set(id.split(":")[3], fixture);
  }
  const fixture = name => fixtures.get(name);
  const valid = name => fixture(name).cases.find(entry => entry.expectation === "accept").value;
  const requestFixture = fixture("request");
  const source = resolve("golden-grill-me");
  mkdirSync(source);
  for (const material of requestFixture.materials) {
    assert(!material.path.includes("..") && !material.path.startsWith("/"));
    const bytes = Buffer.from(material.bytesBase64, "base64");
    assert.equal(bytes.length, material.byteLength);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), material.sha256);
    const path = resolve(source, material.path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
  }
  for (const entry of requestFixture.cases) {
    const request = structuredClone(entry.value);
    // The portable fixture uses /fixtures/grill-me; only this location is rebound.
    assert.equal(request.source.path, "/fixtures/grill-me");
    request.source.path = source;
    const result = await runScan(request);
    assert.equal(result.status, entry.expectation === "accept" ? "assessment" : "diagnostic");
    if (entry.expectation === "refuse") {
      assert.equal(result.phase, "request");
      assert.equal(result.diagnostics[0].code, entry.code);
    } else {
      assert.equal(result.report.completion, "complete");
      assert.deepEqual(result.report.source.capture, valid("report").source.capture);
    }
  }
  for (const [name, reader] of [["report", readReport], ["artifact", readArtifact]]) {
    for (const entry of fixture(name).cases) {
      const result = await reader(canonical(entry.value));
      assert.equal(result.status, entry.expectation === "accept" ? "read" : "invalid");
      if (entry.expectation === "refuse") assert.equal(result.diagnostics[0].code, entry.code);
      else {
        assert.equal(result.authenticity, "unchecked");
        assert.equal(result.scanId, valid("run-result").scanId);
      }
    }
  }
  const read = await readArtifact(canonical(valid("artifact")));
  const descriptors = requestFixture.materials.map(({ path, sha256, byteLength }) => ({ path, sha256, byteLength }));
  assert.equal((await readContentCoverage({ read, descriptors })).status, "matched");
  const changedSkill = fixture("material-change").comparison.after.items[0].paths.find(entry => entry.path === "SKILL.md");
  const changedDescriptors = descriptors.map(entry => entry.path === "SKILL.md" ? { ...entry, sha256: changedSkill.sha256 } : entry);
  assert.equal((await readContentCoverage({ read, descriptors: changedDescriptors })).status, "mismatched");
  assert.deepEqual((await compareMaterialInventories(fixture("material-change").comparison)).materialChange, valid("material-change"));
  for (const entry of fixture("material-change").cases) {
    if (entry.expectation === "accept") {
      const result = await deliverMaterialChange({ summary: entry.value, enabled: false });
      assert.equal(result.diagnostics[0].code, "delivery-disabled");
    } else {
      await assert.rejects(deliverMaterialChange({ summary: entry.value, enabled: false }), error => error.code === entry.code);
    }
  }
  const rules = new Uint8Array(Buffer.from(fixture("detector-definition").rulesBase64, "base64"));
  for (const entry of fixture("detector-definition").cases) {
    const result = await runScan({ ...valid("request"), source: {kind: "local", path: source} },
      { detectorDefinitions: [{ definition: entry.value, rules }] });
    assert.equal(result.status, entry.expectation === "accept" ? "assessment" : "diagnostic");
    if (entry.expectation === "refuse") {
      assert.equal(result.phase, "request");
      assert.equal(result.diagnostics[0].code, entry.code);
    }
  }
  // The run-result and association contracts have no public standalone parser.
  // Their exact exported schemas are checked above; the embedded report/artifact
  // and real material comparison are exercised through public APIs here.
  assert.deepEqual(valid("run-result").report, valid("report"));
  assert.equal(valid("evidence-association").scanId, read.scanId);
  return manifest;
}
