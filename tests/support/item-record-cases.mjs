// Executed only against the installed exact packed archive.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { runScan } from '@aihq/scan/host';
import Ajv2020 from 'ajv/dist/2020.js';
import * as api from '@aihq/scan/read';
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => new TextEncoder().encode(JSON.stringify(sort(v)));
const hash = v => createHash('sha256').update(v).digest('hex');
const fixture = name => JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}`)), 'utf8'));
async function read(report) { const result = await api.readReport(bytes(report)); assert.equal(result.status, 'read', JSON.stringify(result)); return result; }

export async function exerciseItemRecords() {
  for (const name of ['recordItems', 'verifyItemRecord', 'readItemRecord', 'itemIdentity', 'pickRecord', 'summariseItem'])
    assert.equal(typeof api[name], 'function', `public ${name} export`);
  const fixtures = fixture('item-record/1.0.0.fixtures.json');
  assert.equal(fixtures.contractId, 'urn:aihq:scan:item-record:1.0.0');
  const profile = fixtures.severityProfile;
  const validate = new Ajv2020({ strict: false, allErrors: true }).compile(fixture('item-record/1.0.0.json'));
  const accepted = fixtures.cases.filter(c => c.expectation === 'accept');
  assert.deepEqual(accepted.map(c => c.name), ['extensions.matt.grill-me', 'extensions.hook.git-guard', 'ecc.mcp.clickhouse', 'ecc.mcp.cloudflare-docs']);
  for (const entry of fixtures.cases) {
    assert.equal(validate(entry.value), entry.expectation === 'accept', `${entry.name}: ${JSON.stringify(validate.errors)}`);
    if (entry.expectation !== 'accept') {
      assert.equal(api.readItemRecord(entry.value).diagnostics[0].code, entry.code);
      continue;
    }
    // The item's hashes are the contract's encoding over its own fields and materials.
    const content = entry.item.materials.filter(m => m.role === 'content');
    const identity = await api.itemIdentity({ ...entry.item, materials: content, executable: Object.fromEntries(content.map(m => [m.relPath, m.executable])) });
    assert.deepEqual([identity.contentSha256, identity.behaviourSha256], [entry.item.contentSha256, entry.item.behaviourSha256]);
    const assessment = await read(entry.report);
    const batch = await api.recordItems({ artifact: assessment, items: [entry.item], severityProfile: profile });
    assert.equal(batch.status, 'complete');
    assert.deepEqual(batch.results[0], entry.value);
    assert.equal(entry.value.coverage, 'matched');
    const payload = bytes(entry.item.payload);
    assert.deepEqual(entry.value.materials.at(-1), { materialId: '#payload', relPath: '#payload', sha256: hash(payload), byteLength: payload.length, executable: false, captured: true });
    assert.equal(await api.verifyItemRecord(entry.value, assessment, entry.item, profile), 'same');
    assert.equal((await api.recordItems({ artifact: { status: 'invalid', diagnostics: [] }, items: [entry.item], severityProfile: profile })).results[0].coverage, 'unavailable');
  }
  const evidence = fixtures.evidenceKeyExample;
  assert.equal(hash(bytes(evidence.preimage)), evidence.sha256, 'independent canonical SHA-256 worked example');
  assert.equal(accepted[0].value.evidenceKey, evidence.sha256);
  // A real scan of one ECC MCP server, relabelled as its sibling (same files, other payload), never covers it.
  const [docs, clickhouse] = ['ecc.mcp.cloudflare-docs', 'ecc.mcp.clickhouse'].map(name => accepted.find(c => c.name === name));
  const docsRead = await read(docs.report);
  assert.equal(await api.verifyItemRecord({ ...docs.value, subject: clickhouse.value.subject }, docsRead, clickhouse.item, profile), 'not-covered');
  assert.equal(await api.verifyItemRecord(docs.value, docsRead, clickhouse.item, profile), 'not-covered');
  // A recipe-only capture cannot cover the MCP definition: the payload's carrier was not captured.
  const source = fixtures.sourceItems.find(s => s.itemId === clickhouse.item.itemId);
  const root = resolve('item-recipe-only');
  for (const m of source.materials.filter(m => m.role === 'content')) {
    mkdirSync(dirname(resolve(root, m.capturePath)), { recursive: true });
    writeFileSync(resolve(root, m.capturePath), Buffer.from(m.bytesBase64, 'base64'));
  }
  const recipe = await runScan({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }] });
  assert.equal(recipe.status, 'assessment');
  const recipeRead = await read(recipe.report);
  const recipeRecord = (await api.recordItems({ artifact: recipeRead, items: [clickhouse.item], severityProfile: profile })).results[0];
  assert.equal(recipeRecord.coverage, 'mismatched');
  assert.equal(recipeRecord.materials.find(m => m.materialId === '#payload').captured, false);
  assert.equal(await api.verifyItemRecord(clickhouse.value, recipeRead, clickhouse.item, profile), 'not-covered');
  // Precise refusals.
  assert.equal(api.readItemRecord({ ...accepted[0].value, schema: 'urn:aihq:scan:item-record:2.0.0' }).diagnostics[0].code, 'SCHEMA_UNSUPPORTED');
  assert.equal((await api.readReport(bytes({ schema: 'urn:aihq:scan:report:9.0.0' }))).diagnostics[0].code, 'SCHEMA_UNSUPPORTED');
  const changed = await api.recordItems({ artifact: await read(accepted[1].report), items: [{ ...accepted[1].item, payload: { ...accepted[1].item.payload, matcher: 'Bash' } }], severityProfile: profile });
  assert.equal(changed.results[0].diagnostics[0].code, 'behaviour-mismatch', 'a payload-only change needs its own behaviour file and hash');
  // Batch rows equal singleton rows in order; invalid items keep their own row.
  const grill = accepted[0], grillRead = await read(grill.report);
  const mixed = [grill.item, { ...grill.item, materials: [] }, { ...grill.item, contentSha256: '0'.repeat(64) }, { ...grill.item, itemId: 'another-item' }];
  const batch = await api.recordItems({ artifact: grillRead, items: mixed, severityProfile: profile });
  assert.equal(batch.status, 'complete');
  for (const [index, item] of mixed.entries())
    assert.deepEqual(batch.results[index], (await api.recordItems({ artifact: grillRead, items: [item], severityProfile: profile })).results[0]);
  assert.deepEqual(batch.results.map(r => r.coverage), ['matched', 'invalid', 'invalid', 'matched']);
  assert.equal(batch.results[2].diagnostics[0].code, 'item-identity-mismatch');
  assert.equal((await api.recordItems({ artifact: grillRead, items: [grill.item], severityProfile: profile, extra: true })).status, 'invalid');
  let getterCalls = 0;
  const hostileItem = { ...grill.item };
  Object.defineProperty(hostileItem, 'materials', { enumerable: true, get() { getterCalls++; return grill.item.materials; } });
  assert.equal((await api.recordItems({ artifact: grillRead, items: [hostileItem], severityProfile: profile })).status, 'invalid');
  assert.equal(getterCalls, 0, 'item accessors never execute');
  // Findings belong to the item only by exact capture path and file digest; others stay at release level.
  const report = structuredClone(grill.report);
  const skill = grill.item.materials.find(m => m.relPath === 'SKILL.md'), license = grill.item.materials.find(m => m.relPath === 'LICENSE');
  const present = value => ({ state: 'present', value });
  const unavailable = { state: 'unavailable', reason: 'not-reported', detail: '' };
  const finding = (location, n, level) => ({ rawOccurrenceFingerprint: `raw-occurrence-v1:${String(n).repeat(64)}`, multiplicity: n, rule: present({ nativeRuleId: `rule-${n}` }), severity: present({ level }), message: present('Original finding'), location: location ? present(location) : unavailable, supportingEvidence: unavailable });
  const native = report.results.find(r => r.detectorId === 'detector.aih-native');
  native.observations[0].body.findings = [finding({ path: skill.capturePath, fileSha256: skill.sha256 }, 2, 'error'), finding({ path: license.capturePath, fileSha256: license.sha256 }, 3, 'warning'), finding(null, 4, 'error')];
  report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
  for (const r of report.results) { for (const o of r.observations) o.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2 '), bytes(o.body)]))}`; r.observations.sort((a, b) => a.observationId < b.observationId ? -1 : 1); }
  const attributedRead = await read(report);
  const attributed = (await api.recordItems({ artifact: attributedRead, items: [grill.item], severityProfile: profile })).results[0];
  assert.deepEqual(attributed.detectors.find(d => d.id === 'detector.aih-native').findings, { error: 2, warning: 3, note: 0, unavailable: 0 }, 'the locationless finding is not attributed');
  assert.equal(attributed.evidenceKey, grill.value.evidenceKey, 'findings never change the evidence key');
  assert.equal(await api.verifyItemRecord(grill.value, attributedRead, grill.item, profile), 'differs', 'changed findings are not the stored record');
  assert.equal(attributedRead.report.results.find(r => r.detectorId === 'detector.aih-native').observations[0].body.findings.length, 3, 'release-level findings remain intact');
  return { status: 'tested' };
}
