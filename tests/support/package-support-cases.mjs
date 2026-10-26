// Runs only in an outside-workspace packed consumer, using public exports.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import { contractSupport, contractSupport11 } from '@aihq/scan/contracts';
import { readArtifact, readReport, verifyItemRecord } from '@aihq/scan/read';
import { deliverMaterialChange } from '@aihq/scan/host';

const json = specifier => JSON.parse(readFileSync(new URL(import.meta.resolve(specifier)), 'utf8'));
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const bytes = value => new TextEncoder().encode(JSON.stringify(canonical(value)));

// Core's engine deliberately delegates suite interpretation to the host reader.
// A suite is accepted only when every case has the declared schema/reader outcome.
export function packageSupportAdapters() {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  const readers = Object.fromEntries(contractSupport11.contracts.map(contract => {
    const schema = json(contract.schemaExport);
    assert.equal(schema.$id, contract.id);
    const validate = ajv.compile(schema);
    return [contract.id, async data => {
      const suite = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
      assert.equal(suite.contractId, contract.id);
      assert.equal(suite.contractVersion, contract.versions[0]);
      assert(suite.cases.some(entry => entry.expectation === 'accept'));
      assert(suite.cases.some(entry => entry.expectation === 'refuse'));
      for (const entry of suite.cases) {
        assert.equal(validate(entry.value), entry.validation === 'reader' || entry.expectation === 'accept',
          `${contract.id}/${entry.name}: ${JSON.stringify(validate.errors)}`);
        if (contract.id.includes(':report:') || contract.id.includes(':artifact:')) {
          const read = contract.id.includes(':report:') ? readReport : readArtifact;
          const result = await read(bytes(entry.value));
          assert.equal(result.status, entry.expectation === 'accept' ? 'read' : 'invalid');
          if (entry.expectation === 'refuse') assert.equal(result.diagnostics[0].code, entry.code);
        }
        if (contract.id.includes(':item-record:')) {
          const context = entry.report ? entry : suite.cases.find(candidate => candidate.expectation === 'accept');
          const assessment = await readReport(bytes(context.report));
          assert.equal(assessment.status, 'read');
          assert.equal(await verifyItemRecord(entry.value, assessment, context.item), entry.expectation === 'accept' ? 'same' : 'differs');
        }
        if (contract.id.includes(':material-change:')) {
          if (entry.expectation === 'accept') {
            const result = await deliverMaterialChange({ summary: entry.value, enabled: false });
            assert.equal(result.diagnostics[0].code, 'delivery-disabled');
          } else await assert.rejects(deliverMaterialChange({ summary: entry.value, enabled: false }), error => error.code === entry.code);
        }
      }
      return { accepted: true };
    }];
  }));
  const loadFixture = (packageName, specifier) => {
    assert.equal(packageName, '@aihq/scan');
    assert(contractSupport11.contracts.some(entry => entry.fixtures.some(fixture => fixture.export === specifier)));
    return new Uint8Array(readFileSync(new URL(import.meta.resolve(specifier))));
  };
  return { readers, loadFixture };
}

export async function exercisePackageSupport(core) {
  assert.equal(contractSupport.schema, 'urn:aihq:package-support:1.0.0');
  assert.equal(contractSupport11.schema, 'urn:aihq:package-support:1.1.0');
  assert.deepEqual(contractSupport11.contracts.map(({ fixtures, versions, ...entry }) => entry), contractSupport.contracts);
  assert.equal(contractSupport11.package, contractSupport.package);
  assert.equal(contractSupport11.entries, contractSupport.entries);
  const adapters = packageSupportAdapters();
  for (const contract of contractSupport11.contracts) for (const fixture of contract.fixtures) {
    assert.equal(fixture.expect, 'accept');
    assert.deepEqual(await adapters.readers[contract.id](adapters.loadFixture('@aihq/scan', fixture.export)), { accepted: true });
  }
  if (!core) return;
  assert.equal(core.validatePackageSupport(contractSupport).valid, true);
  assert.equal(core.validatePackageSupport(contractSupport11).valid, true);
  const consumer = { ...contractSupport11, package: { name: 'scan-contract-consumer', version: '0.1.0' },
    contracts: contractSupport11.contracts.map(entry => ({ ...entry, role: 'accepts', fixtures: [] })) };
  const checked = await core.checkContracts({ declarations: [consumer, contractSupport11], ...adapters });
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.equal(checked.checks.length, 14);
  assert(checked.checks.every(row => row.status === 'passed'));
  // Missing fixture bytes and readers must remain unavailable, never an empty pass.
  for (const overrides of [{ readers: {} }, { loadFixture: () => 'unavailable' }]) {
    const refused = await core.checkContracts({ declarations: [consumer, contractSupport11], ...adapters, ...overrides });
    assert.equal(refused.ok, false);
    assert.equal(refused.checks.length, 14);
    assert(refused.checks.every(row => row.status === 'unavailable'));
  }
  return checked;
}
