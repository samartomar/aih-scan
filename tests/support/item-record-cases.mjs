// Executed only against the installed exact packed archive.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { runScan } from '@aihq/scan/host';
import Ajv2020 from 'ajv/dist/2020.js';
import * as api from '@aihq/scan/read';
const canonical = value => JSON.stringify(Array.isArray(value) ? value.map(v => JSON.parse(canonical(v))) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, JSON.parse(canonical(value[k]))])) : value);
export async function exerciseItemRecords() {
  assert.equal(typeof api.recordItem, 'function', 'public recordItem export');
  const fixtures = JSON.parse(readFileSync(new URL(import.meta.resolve('@aihq/scan/schemas/report/2.0.0.fixtures.json')), 'utf8'));
  const report = fixtures.cases.find(c => c.name === 'grill-me-local-nonexecutable').value;
  const assessment = await api.readReport(new TextEncoder().encode(canonical(report)));
  assert.equal(assessment.status, 'read');
  const item = { frameworkId: 'matt-skills', itemId: 'grill-me', contentSha256: 'a'.repeat(64), behaviourSha256: 'b'.repeat(64), materials: report.source.capture.entries.filter(e => 'sha256' in e).map(({ path, sha256, byteLength, executable }) => ({ path, sha256, byteLength, executable, role: path === 'SKILL.md' ? 'behaviour' : 'content' })) };
  const record = await api.recordItem(assessment, item);
  assert.equal(record.schema, 'urn:aihq:scan:item-record:1.0.0');
  assert.equal(record.coverage, 'matched');
  assert.equal(record.scanId, assessment.scanId);
  assert.equal(record.authenticity, 'unchecked');
  assert.equal(record.detectors[0].itemCoverage, 'covered');
  const schema = JSON.parse(readFileSync(new URL(import.meta.resolve('@aihq/scan/schemas/item-record/1.0.0.json')), 'utf8'));
  assert.equal(schema.$id, 'urn:aihq:scan:item-record:1.0.0');
  let reads = 0;
  const hostile = { ...record };
  Object.defineProperty(hostile, 'subject', { enumerable: true, get() { reads++; return record.subject; } });
  assert.equal(await api.verifyItemRecord(hostile, assessment, item), 'differs');
  assert.equal(reads, 0, 'cache accessors must never execute');
  // Verification observes the cache supplied at invocation, before its first await.
  const repaired = structuredClone(record);
  repaired.evidenceKey = '0'.repeat(64);
  const repairPending = api.verifyItemRecord(repaired, assessment, item);
  repaired.evidenceKey = record.evidenceKey;
  assert.equal(await repairPending, 'differs', 'repairing a corrupt cache after invocation cannot make it equal');
  const changedAfterInvocation = structuredClone(record);
  const originalPending = api.verifyItemRecord(changedAfterInvocation, assessment, item);
  changedAfterInvocation.evidenceKey = '0'.repeat(64);
  assert.equal(await originalPending, 'same', 'later cache mutation cannot alter the original snapshot');
  const itemAfterInvocation = structuredClone(item);
  const itemPending = api.verifyItemRecord(record, assessment, itemAfterInvocation);
  itemAfterInvocation.itemId = 'changed-after-invocation';
  assert.equal(await itemPending, 'same', 'item snapshot remains captured at invocation');
  const assessmentAfterInvocation = structuredClone(assessment);
  const assessmentPending = api.verifyItemRecord(record, assessmentAfterInvocation, item);
  assessmentAfterInvocation.report.createdAt = '2099-01-01T00:00:00.000Z';
  assert.equal(await assessmentPending, 'same', 'assessment snapshot remains captured at invocation');
  const missing = { ...item, materials: item.materials.map(m => ({ ...m, path: `missing/${m.path}` })) };
  assert.equal(await api.verifyItemRecord(hostile, assessment, missing), 'not-covered', 'missing capture takes precedence over malformed cache');
  assert.equal(reads, 0, 'malformed cache remains getter-safe when capture is missing');
  assert.equal(await api.verifyItemRecord(null, assessment, item), 'differs', 'malformed cache is refused when capture is available');
  await exerciseContracts();
  await exerciseAttribution();
  return { status: 'tested' };
}

const bytes = value => new TextEncoder().encode(canonical(value));
const hash = value => createHash('sha256').update(value).digest('hex');
const fixture = name => JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}`)), 'utf8'));
async function read(report) { const result = await api.readReport(bytes(report)); assert.equal(result.status, 'read', JSON.stringify(result)); return result; }
function rebind(report) {
  report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
  for (const result of report.results) for (const observation of result.observations)
    observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
  for (const result of report.results) result.observations.sort((a, b) => a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0);
  return report;
}
async function exerciseContracts() {
  const fixtures = fixture('item-record/1.0.0.fixtures.json');
  assert.equal(fixtures.contractId, 'urn:aihq:scan:item-record:1.0.0');
  const validate = new Ajv2020({ strict: false, allErrors: true }).compile(fixture('item-record/1.0.0.json'));
  const accepted = fixtures.cases.filter(c => c.expectation === 'accept');
  assert.deepEqual(accepted.map(c => c.name), ['grill-me', 'hook-git-guard', 'mcp-github']);
  for (const entry of fixtures.cases) {
    assert.equal(validate(entry.value), entry.expectation === 'accept', JSON.stringify(validate.errors));
    if (entry.expectation !== 'accept') continue;
    const assessment = await read(entry.report);
    const record = await api.recordItem(assessment, entry.item);
    assert.deepEqual(record, entry.value);
    assert.equal(record.coverage, 'matched');
    assert.equal(record.detectors.find(d => d.detectorId === 'detector.unavailable').itemCoverage, 'uncovered');
    assert.equal(record.detectors.find(d => d.detectorId === 'detector.unavailable').effectiveProfileId, null);
    assert.equal(await api.verifyItemRecord(record, assessment, entry.item), 'same');
    const batch = await api.recordItemBatch({ assessment, items: [entry.item, { ...entry.item, itemId: 'another-item' }] });
    assert.equal(batch.status, 'complete');
    assert.deepEqual(batch.results, await Promise.all([entry.item, { ...entry.item, itemId: 'another-item' }].map(item => api.recordItem(assessment, item))));
    const changed = structuredClone(entry.item);
    changed.materials.find(m => m.role === 'behaviour').sha256 = '0'.repeat(64);
    assert.equal((await api.recordItem(assessment, changed)).coverage, 'mismatched');
    assert.equal(await api.verifyItemRecord(record, assessment, changed), 'not-covered');
    assert.equal(await api.verifyItemRecord({ ...record, subject: { ...record.subject, itemId: 'another-item' } }, assessment, entry.item), 'not-covered');
    const executable = structuredClone(entry.item); executable.materials[0].executable = true;
    assert.equal(await api.verifyItemRecord(record, assessment, executable), 'differs');
    const invalid = await api.recordItem(assessment, { ...entry.item, materials: [] });
    assert.equal(invalid.coverage, 'invalid'); assert.equal(validate(invalid), true, JSON.stringify(validate.errors));
    assert.equal((await api.recordItem(assessment, { ...entry.item, toolId: 'forbidden' })).coverage, 'invalid');
    const unavailable = await api.recordItem({ status: 'invalid', diagnostics: [] }, entry.item);
    assert.equal(unavailable.coverage, 'unavailable'); assert.equal(validate(unavailable), true, JSON.stringify(validate.errors));
    // Every stored derived field is compared, including array shape and all nested leaves.
    const mutations = [];
    const walk = (value, path = []) => {
      if (path[0] === 'subject') return;
      if (Array.isArray(value)) { mutations.push([path, []]); value.forEach((v, i) => walk(v, [...path, i])); }
      else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) walk(v, [...path, k]);
      else mutations.push([path, typeof value === 'boolean' ? !value : typeof value === 'number' ? value + 1 : value === null ? 'changed' : `${value}-changed`]);
    };
    walk(record);
    for (const [path, value] of mutations) {
      const changed = structuredClone(record); let parent = changed;
      for (const key of path.slice(0, -1)) parent = parent[key];
      if (canonical(parent[path.at(-1)]) === canonical(value)) continue;
      parent[path.at(-1)] = value;
      assert.equal(await api.verifyItemRecord(changed, assessment, entry.item), 'differs', `tamper ${path.join('.')}`);
    }
  }
  const base = accepted[0];
  let getterCalls = 0;
  const hostileItem = { ...base.item };
  Object.defineProperty(hostileItem, 'materials', { enumerable: true, get() { getterCalls++; return base.item.materials; } });
  assert.equal((await api.recordItem(await read(base.report), hostileItem)).coverage, 'invalid');
  assert.equal(getterCalls, 0);
  assert.equal((await api.recordItemBatch({ assessment: await read(base.report), items: [base.item], [Symbol('extra')]: true })).status, 'invalid');
  const mixedItems = [base.item, { ...base.item, materials: [] }, { ...base.item, materials: base.item.materials.map(m => ({ ...m, sha256: '0'.repeat(64) })) }];
  const mixedRead = await read(base.report);
  assert.deepEqual((await api.recordItemBatch({ assessment: mixedRead, items: mixedItems })).results, await Promise.all(mixedItems.map(item => api.recordItem(mixedRead, item))));
  const keyExample = fixtures.evidenceKeyExample;
  assert.equal(hash(bytes(keyExample.preimage)), keyExample.sha256, 'independent canonical SHA-256 worked example');
  assert.equal(base.value.evidenceKey, keyExample.sha256);
  assert.equal((await api.recordItem(await read(base.report), base.item)).evidenceKey, keyExample.sha256);
  const large = { ...base.item, materials: Array.from({ length: 4097 }, (_, i) => ({ ...base.item.materials[0], path: `missing-${i}`, role: i === 0 ? 'behaviour' : 'content' })) };
  assert.equal((await api.recordItem(await read(base.report), large)).coverage, 'mismatched', 'one item retains the existing 10000-descriptor bound');
  // The entire executable comparison truth table is exercised through public documents.
  const truthTable = [[false, false, 'equal'], [true, false, 'differs'], ['unknown', false, 'unknown'], [false, true, 'differs'], [true, true, 'equal'], ['unknown', true, 'unknown'], [false, 'unknown', 'unknown'], [true, 'unknown', 'unknown'], ['unknown', 'unknown', 'unknown']];
  for (const captured of [false, true, 'unknown']) {
    const report = structuredClone(base.report);
    for (const entry of report.source.capture.entries) if ('sha256' in entry) entry.executable = captured;
    for (const result of report.results) for (const observation of result.observations)
      for (const entry of observation.body.input.entries) if ('sha256' in entry) entry.executable = captured;
    const assessment = await read(rebind(report));
    for (const [declared, , expected] of truthTable.filter(row => row[1] === captured)) {
      const item = { ...base.item, materials: base.item.materials.map(m => ({ ...m, executable: declared })) };
      const record = await api.recordItem(assessment, item);
      assert(record.materials.every(m => m.executableComparison === expected));
      assert.equal(record.coverage, expected === 'differs' ? 'mismatched' : 'matched');
    }
  }
  const partitioned = structuredClone(base.report);
  const native = partitioned.results.find(r => r.detectorId === 'detector.aih-native');
  const observation = native.observations[0];
  native.observations = observation.body.coverage.coveredPaths.map(path => {
    const unit = structuredClone(observation);
    unit.body.input.targetPaths = [path]; unit.body.coverage.coveredPaths = [path]; unit.body.findings = [];
    return unit;
  });
  const partitionedRecord = await api.recordItem(await read(rebind(partitioned)), base.item);
  assert.equal(partitionedRecord.detectors.find(d => d.detectorId === 'detector.aih-native').itemCoverage, 'covered');
  assert.equal(partitionedRecord.detectors.find(d => d.detectorId === 'detector.aih-native').inputSha256s.length, base.item.materials.length);
  assert.notEqual(partitionedRecord.evidenceKey, base.value.evidenceKey, 'scope/entry input identities affect grouping');
  const legacyFixture = fixture('report/1.0.0.fixtures.json').cases.find(c => c.expectation === 'accept').value;
  const legacyItem = { ...base.item, materials: legacyFixture.source.capture.entries.filter(e => 'sha256' in e).map(({ path, sha256, byteLength }, index) => ({ path, sha256, byteLength, executable: true, role: index === 0 ? 'behaviour' : 'content' })) };
  const legacyRecord = await api.recordItem(await read(legacyFixture), legacyItem);
  assert.equal(legacyRecord.coverage, 'matched');
  assert(legacyRecord.materials.every(m => m.executableComparison === 'unknown'));
  // Recipe-only assessments cannot be transferred onto an MCP definition.
  const mcp = accepted.find(c => c.name === 'mcp-github');
  const root = resolve('item-recipe-only'); mkdirSync(root);
  const source = fixtures.sourceItems.find(c => c.name === 'mcp-github');
  writeFileSync(resolve(root, 'recipe.json'), Buffer.from(source.materials[0].bytesBase64, 'base64'));
  const recipe = await runScan({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }] });
  assert.equal(recipe.status, 'assessment');
  const record = await api.recordItem(await read(recipe.report), mcp.item);
  assert.equal(record.coverage, 'mismatched');
  assert.equal(record.materials.find(m => m.role === 'behaviour').captured, false);
  assert.equal(await api.verifyItemRecord(mcp.value, await read(recipe.report), mcp.item), 'not-covered');
  // Selection's strict descriptor contract is retained; callers project explicitly.
  const projected = mcp.item.materials.map(({ path, sha256, byteLength }) => ({ path, sha256, byteLength }));
  assert.equal((await api.readContentCoverage({ read: await read(mcp.report), descriptors: projected })).status, 'matched');
  assert.equal((await api.readContentCoverage({ read: await read(mcp.report), descriptors: mcp.item.materials })).status, 'invalid');
  const selection = { assessments: [{ sourceId: 'fixture', location: 'fixture.json', format: 'report', bytes: bytes(mcp.report) }], context: { sourceIds: ['fixture'], selection: mcp.report.selection, descriptors: projected }, evaluationTime: mcp.report.createdAt, checks: [] };
  const selected = await api.selectAssessments(selection);
  assert.equal(selected.status, 'selected');
  assert.equal(selected.selectedScanId, mcp.value.scanId);
  assert.equal((await api.selectAssessments({ ...selection, context: { ...selection.context, descriptors: mcp.item.materials } })).status, 'invalid');
}
async function exerciseAttribution() {
  const root = resolve('item-attribution'); mkdirSync(root);
  for (const path of ['own.md', 'other.md', 'behaviour.json']) writeFileSync(resolve(root, path), 'same bytes\n');
  const request = { schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }] };
  const run = await runScan(request); assert.equal(run.status, 'assessment');
  const report = run.report;
  const file = report.source.capture.entries.find(e => e.path === 'own.md');
  const present = value => ({ state: 'present', value });
  const unavailable = { state: 'unavailable', reason: 'not-reported', detail: '' };
  const finding = (path, digest, fingerprint) => ({ rawOccurrenceFingerprint: `raw-occurrence-v1:${fingerprint.repeat(64)}`, multiplicity: 3, rule: present({ nativeRuleId: 'original.rule' }), severity: present({ level: 'vendor-critical', vendorSeverity: '9' }), message: present('Original finding'), location: path === null ? unavailable : present({ path, fileSha256: digest, startLine: 2 }), supportingEvidence: unavailable });
  const own = finding('own.md', file.sha256, '1');
  const original = [own, finding('other.md', file.sha256, '2'), finding(null, null, '3')];
  report.results[0].observations[0].body.findings = original;
  const assessment = await read(rebind(report));
  const item = { frameworkId: 'fixture', itemId: 'own', contentSha256: 'c'.repeat(64), behaviourSha256: 'd'.repeat(64), materials: [file, report.source.capture.entries.find(e => e.path === 'behaviour.json')].map(({ path, sha256, byteLength, executable }) => ({ path, sha256, byteLength, executable, role: path === 'behaviour.json' ? 'behaviour' : 'content' })) };
  const record = await api.recordItem(assessment, item);
  assert.deepEqual(record.detectors[0].findings, [own]);
  const changedFindings = structuredClone(report);
  changedFindings.results[0].observations[0].body.findings[0].severity.value.level = 'different-severity';
  const changedAssessment = await read(rebind(changedFindings));
  const changedRecord = await api.recordItem(changedAssessment, item);
  assert.equal(changedRecord.evidenceKey, record.evidenceKey, 'display grouping key is not a findings claim');
  assert.equal(await api.verifyItemRecord(record, changedAssessment, item), 'differs');
  assert.deepEqual(assessment.report.results[0].observations[0].body.findings, original, 'release-level findings remain intact');
  const partial = await runScan({ ...request, selection: { paths: ['own.md'], excludedPaths: [] } });
  assert.equal(partial.status, 'assessment');
  const partialRecord = await api.recordItem(await read(partial.report), item);
  assert.equal(partialRecord.coverage, 'matched');
  assert.equal(partialRecord.detectors[0].itemCoverage, 'partial');
}
