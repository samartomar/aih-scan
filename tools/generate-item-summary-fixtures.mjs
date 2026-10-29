// Build first. Real-data-derived decision-table specimens: stored records are what recordItems gives over the
// published item-record fixture reports; every expected summary is written from the contract's decision table,
// never from summariseItem. No scanner, network or native execution.
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
import { readReport, recordItems } from '@aihq/scan/read';
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => Buffer.from(JSON.stringify(sort(v)));
const hash = v => createHash('sha256').update(v).digest('hex');
const records = JSON.parse(readFileSync(new URL('../schemas/item-record/1.0.0.fixtures.json', import.meta.url), 'utf8'));
const golden = name => records.cases.find(c => c.name === name);
const profile = records.severityProfile;
const other = { ...structuredClone(profile), id: 'organization-lenient', rules: [] };
const ref = p => `${p.id}@sha256:${hash(bytes(p))}`;
const policy = { schema: 'urn:aihq:scan:evidence-policy:1.0.0', id: 'organization', version: '1', requiredDetectors: ['detector.aih-native'], severityProfile: { id: profile.id, sha256: hash(bytes(profile)) } };
const rebind = report => {
  report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
  for (const result of report.results) {
    for (const observation of result.observations) observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
    result.observations.sort((a, b) => a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0);
  }
  return report;
};
/** Only the native detector: a complete assessment of the same real bytes. */
const completeReport = source => {
  const report = structuredClone(source);
  report.requestedDetectors = report.requestedDetectors.filter(d => d.detectorId === 'detector.aih-native');
  report.results = report.results.filter(d => d.detectorId === 'detector.aih-native');
  report.completion = 'complete';
  return report;
};
async function stored(report, item, severityProfile = profile) {
  const read = await readReport(bytes(report));
  if (read.status !== 'read') throw new Error(JSON.stringify(read));
  const batch = await recordItems({ artifact: read, items: [item], severityProfile });
  if (batch.status !== 'complete' || !('subject' in batch.results[0])) throw new Error(JSON.stringify(batch));
  return batch.results[0];
}
const grill = golden('extensions.matt.grill-me');
const base = completeReport(grill.report);
const at = shift => new Date(Date.parse(base.createdAt) + shift).toISOString();
const evaluationTime = at(86400000);
const candidate = async (report, options = {}) => ({ record: options.record ?? await stored(report, options.item ?? grill.item, options.profile), report, authentication: options.authentication ?? { status: 'authenticated' } });
const input = async (changes = {}) => ({ records: changes.records ?? [await candidate(base)], item: changes.item ?? grill.item, policy: changes.policy ?? policy, severityProfiles: changes.severityProfiles ?? [profile, other], trustStatus: changes.trustStatus ?? 'available', evaluationTime: changes.evaluationTime ?? evaluationTime });
const none = { error: 0, warning: 0, note: 0, unavailable: 0 };
const summary = (state, why, extra = {}) => ({ state, ...(why ? { why } : {}), findings: none, suppressed: 0, scannedAt: base.createdAt, ...extra });
const empty = state => ({ state, findings: none, suppressed: 0, scannedAt: null });
const cases = [];
const add = async (row, name, data, value, picked = null) => cases.push({ row, name, expectation: 'accept', code: null, input: await data, value, ...(picked ? { picked } : {}) });

await add(1, 'no-records', input({ records: [] }), empty('not-scanned'));
const extraField = { ...(await stored(base, grill.item)), schema: 'urn:aihq:scan:item-record:9.0.0' };
await add(2, 'record-schema-unsupported', input({ records: [{ record: extraField, report: base, authentication: { status: 'authenticated' } }] }), empty('unreadable'));
// A real ECC MCP scan relabelled as its sibling: same files, other payload and behaviourSha256.
const docs = golden('ecc.mcp.cloudflare-docs'), clickhouse = golden('ecc.mcp.clickhouse');
const relabelled = structuredClone(docs.value); relabelled.subject = structuredClone(clickhouse.value.subject);
await add(3, 'relabelled-other-behaviour', input({ item: clickhouse.item, records: [{ record: relabelled, report: docs.report, authentication: { status: 'authenticated' } }] }), empty('not-covered'));
const unknownModes = structuredClone(base);
for (const e of unknownModes.source.capture.entries) if ('sha256' in e) e.executable = 'unknown';
for (const r of unknownModes.results) for (const o of r.observations) for (const e of o.body.input.entries) if ('sha256' in e) e.executable = 'unknown';
rebind(unknownModes);
await add(4, 'capture-without-executable-bits', input({ records: [await candidate(unknownModes)] }), summary('not-covered'));
await add(5, 'partial-assessment', input({ records: [await candidate(grill.report)] }), summary('partial'));
await add(6, 'required-detector-missing', input({ policy: { ...policy, requiredDetectors: ['detector.aih-native', 'detector.absent'] } }), summary('not-verified', 'detector-missing'));
await add(7, 'severity-profile-not-policy', input({ records: [await candidate(base, { profile: other })] }), summary('not-verified', 'profile-not-allowed'));
await add(8, 'authentication-revoked', input({ records: [await candidate(base, { authentication: { status: 'revoked' } })], trustStatus: 'expired' }), summary('not-verified', 'revoked'));
await add(9, 'trust-offline', input({ trustStatus: 'unavailable' }), summary('not-verified', 'offline'));
await add(10, 'authentication-unchecked', input({ records: [await candidate(base, { authentication: { status: 'skipped', reason: 'not-requested' } })] }), summary('not-verified', 'unchecked'));
await add(11, 'future-dated', input({ evaluationTime: at(-60000) }), summary('not-verified', 'future-dated'));
await add(12, 'older-than-policy', input({ policy: { ...policy, maxAge: 'PT1H' } }), summary('not-verified', 'older-than-policy'));
await add(13, 'verified', input(), summary('verified'), { index: 0, why: 'only-record' });

const variants = [];
const variant = async (row, name, data, value, picked = null) => variants.push({ row, name, input: await data, value, ...(picked ? { picked } : {}) });
await variant(2, 'artifact-unreadable', input({ records: [{ ...(await candidate(base)), report: { schema: 'urn:aihq:scan:report:99.0.0' } }] }), empty('unreadable'));
await variant(2, 'severity-profile-not-supplied', input({ records: [await candidate(base, { profile: other })], severityProfiles: [profile] }), empty('unreadable'));
await variant(3, 'other-bytes-same-name', input({ records: [{ record: (() => { const r = structuredClone(golden('extensions.hook.git-guard').value); r.subject = structuredClone(grill.value.subject); return r; })(), report: golden('extensions.hook.git-guard').report, authentication: { status: 'authenticated' } }] }), empty('not-covered'));
await variant(3, 'tampered-record-differs', input({ records: [{ ...(await candidate(base)), record: { ...(await stored(base, grill.item)), evidenceKey: '0'.repeat(64) } }] }), empty('not-covered'));
// A translated MCP entry cannot inherit the recipe's coverage: the recipe file alone was captured, not the payload.
const recipeOnly = await (async () => {
  const sourceItem = records.sourceItems.find(s => s.itemId === clickhouse.item.itemId);
  const root = mkdtempSync(join(tmpdir(), 'aih-recipe-only-'));
  try {
    for (const m of sourceItem.materials.filter(m => m.role === 'content')) {
      mkdirSync(dirname(join(root, m.capturePath)), { recursive: true }); writeFileSync(join(root, m.capturePath), Buffer.from(m.bytesBase64, 'base64'));
    }
    const run = await runScan({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }] });
    if (run.status !== 'assessment') throw new Error(JSON.stringify(run));
    const report = run.report; report.createdAt = base.createdAt;
    for (const e of report.source.capture.entries) if ('sha256' in e) e.executable = false;
    for (const r of report.results) for (const o of r.observations) { o.body.startedAt = o.body.completedAt = report.createdAt; for (const e of o.body.input.entries) if ('sha256' in e) e.executable = false; }
    return rebind(report);
  } finally { rmSync(root, { recursive: true, force: true }); }
})();
await variant(3, 'mcp-recipe-only-no-payload', input({ item: clickhouse.item, records: [await candidate(recipeOnly, { item: clickhouse.item })] }), empty('not-covered'));
await variant(10, 'authentication-failed', input({ records: [await candidate(base, { authentication: { status: 'unverifiable', reason: 'invalid-signature' } })] }), summary('not-verified', 'not-authenticated'));
await variant(9, 'trust-expired-before-unchecked', input({ trustStatus: 'expired', records: [await candidate(base, { authentication: { status: 'skipped', reason: 'not-requested' } })] }), summary('not-verified', 'offline'));
await variant(8, 'trust-revoked-historically-authentic', input({ trustStatus: 'revoked' }), summary('not-verified', 'revoked'));
await variant(13, 'age-at-boundary', input({ policy: { ...policy, maxAge: 'P1D' } }), summary('verified'), { index: 0, why: 'only-record' });
// Ranking: never newest alone.
const newer = structuredClone(base); newer.createdAt = at(3600000); for (const r of newer.results) for (const o of r.observations) o.body.startedAt = o.body.completedAt = newer.createdAt; rebind(newer);
const newerPartial = structuredClone(grill.report); newerPartial.createdAt = newer.createdAt; for (const r of newerPartial.results) for (const o of r.observations) o.body.startedAt = o.body.completedAt = newer.createdAt; rebind(newerPartial);
await variant(13, 'authenticated-older-beats-unchecked-newer', input({ records: [await candidate(newer, { authentication: { status: 'skipped', reason: 'not-requested' } }), await candidate(base)] }), summary('verified'), { index: 1, why: 'authentication' });
await variant(13, 'complete-older-beats-partial-newer', input({ records: [await candidate(newerPartial), await candidate(base)] }), summary('verified'), { index: 1, why: 'completion' });
await variant(13, 'matched-beats-unavailable', input({ records: [await candidate(unknownModes), await candidate(base)] }), summary('verified'), { index: 1, why: 'coverage' });
await variant(13, 'policy-profile-beats-newer-other-profile', input({ records: [await candidate(newer, { profile: other }), await candidate(base)] }), summary('verified'), { index: 1, why: 'severity-profile' });
await variant(13, 'newest-when-all-else-equal', input({ records: [await candidate(base), await candidate(newer)] }), summary('verified', undefined, { scannedAt: newer.createdAt }), { index: 1, why: 'time' });
await variant(13, 'unreadable-and-relabelled-ignored', input({ records: [{ record: extraField, report: base, authentication: { status: 'authenticated' } }, { record: relabelled, report: docs.report, authentication: { status: 'authenticated' } }, await candidate(base)] }), summary('verified'), { index: 2, why: 'only-record' });
// Controlled, item-attributed findings over real captured bytes. Multiplicities are independent literals;
// locationless findings are release-level and not attributed.
const counted = structuredClone(base);
const skill = grill.item.materials.find(m => m.relPath === 'SKILL.md'), license = grill.item.materials.find(m => m.relPath === 'LICENSE');
const finding = (level, rule, multiplicity, ordinal, material = skill) => ({ rawOccurrenceFingerprint: `raw-occurrence-v1:${String(ordinal).repeat(64)}`, multiplicity, rule: { state: 'present', value: { nativeRuleId: rule } }, severity: level ? { state: 'present', value: { level } } : { state: 'unavailable', reason: 'not-supplied', detail: '' }, message: { state: 'present', value: 'Controlled fixture finding' }, location: material ? { state: 'present', value: { path: material.capturePath, fileSha256: material.sha256 } } : { state: 'unavailable', reason: 'not-supplied', detail: '' }, supportingEvidence: { state: 'unavailable', reason: 'not-supplied', detail: '' } });
counted.results[0].observations[0].body.findings = [finding('error', 'keep', 3, 1), finding('warning', 'warn', 2, 2), finding('vendor-high', 'unmapped', 1, 3), finding(null, 'absent', 1, 4, license), finding('error', 'suppress', 4, 5), finding('error', 'locationless', 5, 7, null)];
rebind(counted);
const suppressing = { ...structuredClone(profile), id: 'aih-default-suppressed', suppressions: [{ detectorId: 'detector.aih-native', nativeRuleId: 'suppress', path: skill.capturePath, reason: 'Documented exception' }] };
await variant(13, 'severity-and-suppression-occurrences', input({ records: [await candidate(counted, { profile: suppressing })], policy: { ...policy, severityProfile: { id: suppressing.id, sha256: hash(bytes(suppressing)) } }, severityProfiles: [suppressing] }), summary('verified', undefined, { findings: { error: 3, warning: 2, note: 0, unavailable: 2 }, suppressed: 4 }), { index: 0, why: 'only-record' });

const emit = (name, data) => { const dir = new URL(`../schemas/${name}/`, import.meta.url); mkdirSync(dir, { recursive: true }); writeFileSync(new URL('1.0.0.fixtures.json', dir), `${JSON.stringify(data, null, 2)}\n`); };
const metadata = { contractVersion: '1.0.0', provenance: { sourceContract: records.contractId, sourceItems: records.sourceItems.map(({ name, frameworkId, itemId, contentSha256, behaviourSha256 }) => ({ name, frameworkId, itemId, contentSha256, behaviourSha256 })), note: 'Decision-table specimens over the published real Catalog item-record fixtures. Each candidate carries its stored record, the report document it names and a host authentication result. No native execution or authenticity claim.' } };
emit('item-summary', { contractId: 'urn:aihq:scan:item-summary:1.0.0', ...metadata, cases: [...cases, { name: 'unsupported-positive-word', expectation: 'refuse', code: 'invalid-input', value: { ...empty('not-scanned'), state: 'approved' } }], variants });
for (const [name, value, invalid] of [['evidence-policy', policy, { ...policy, requiredDetectors: [] }], ['severity-profile', profile, { ...profile, rules: [{ detectorId: '*', level: 'high', maps: 'approved' }] }]]) emit(name, { contractId: value.schema, ...metadata, cases: [{ name: 'organization', expectation: 'accept', code: null, value }, { name: 'closed-contract', expectation: 'refuse', code: 'invalid-input', value: invalid }] });
console.log(cases.length, variants.length, ref(profile));
