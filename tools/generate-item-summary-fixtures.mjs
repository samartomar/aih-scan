// Static, real-data-derived specimens; expected states come from the published
// decision table, never from summariseItem. No scanner, network or native execution.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => Buffer.from(JSON.stringify(sort(v)));
const hash = v => createHash('sha256').update(v).digest('hex');
const old = JSON.parse(readFileSync(new URL('../schemas/item-record/1.0.0.fixtures.json', import.meta.url), 'utf8'));
const source = old.cases[0];
const profile = { schema: 'urn:aihq:scan:severity-profile:1.0.0', id: 'organization', version: '1', rules: [{ detectorId: '*', level: 'high', maps: 'warning' }, { detectorId: 'detector.aih-native', level: 'high', maps: 'error' }] };
const policy = { schema: 'urn:aihq:scan:evidence-policy:1.0.0', id: 'organization', version: '1', requiredDetectors: [], severityProfile: { id: profile.id, sha256: hash(bytes(profile)) }, suppressions: [] };
const complete = structuredClone(source.report);
complete.requestedDetectors = complete.requestedDetectors.filter(d => d.detectorId === 'detector.aih-native');
complete.results = complete.results.filter(d => d.detectorId === 'detector.aih-native');
complete.completion = 'complete';
const time = '2026-10-26T00:00:00.000Z';
const candidate = document => ({ sourceId: 'fixture', location: 'memory', format: 'report', document });
const baseline = () => ({ assessmentsInput: { assessments: [candidate(structuredClone(complete))], context: { sourceIds: ['fixture'], selection: structuredClone(complete.selection) }, checks: [{ sourceId: 'fixture', attemptedAt: time, lastSuccessfulAt: time, status: 'succeeded', diagnostics: [] }] }, item: structuredClone(source.item), evidencePolicy: structuredClone(policy), severityProfile: structuredClone(profile), authentication: { status: 'authenticated' }, trustStatus: 'available', evaluationTime: time });
const reportOf = input => input.assessmentsInput.assessments[0].document;
const rebind = report => {
  report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
  for (const result of report.results) {
    for (const observation of result.observations) observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
    result.observations.sort((a, b) => a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0);
  }
};
const cases = [];
function add(row, name, change, state, why, selected = row >= 8, extra = {}) {
  const input = baseline(); change(input);
  const report = input.assessmentsInput.assessments[0]?.document;
  const value = { schema: 'urn:aihq:scan:item-summary:1.0.0', state, ...(why ? { why } : {}), freshness: row === 1 ? null : row === 3 ? 'last-known' : 'checked', findings: { error: 0, warning: 0, note: 0, unavailable: 0 }, suppressed: { count: 0, reasons: [] }, scannedAt: selected ? report.createdAt : null, scanId: selected ? `scan:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.report.v1\0'), bytes(report)]))}` : null, ...extra };
  cases.push({ row, name, expectation: 'accept', code: null, input, value });
}
add(1, 'no-sources', c => { c.assessmentsInput.context.sourceIds = []; c.assessmentsInput.assessments = []; c.assessmentsInput.checks = []; }, 'not-scanned', 'no-sources');
add(2, 'nothing-found', c => { c.assessmentsInput.assessments = []; }, 'not-scanned', 'not-found');
add(3, 'unreadable-only', c => { c.assessmentsInput.assessments[0].document = {}; }, 'unreadable');
add(4, 'future-only', c => { reportOf(c).createdAt = '2027-01-01T00:00:00.000Z'; }, 'not-verified', 'future-dated');
add(5, 'other-materials', c => { c.item.materials[0].sha256 = '0'.repeat(64); }, 'not-covered', 'content-mismatch');
add(6, 'scope-mismatch', c => { c.assessmentsInput.context.selection.excludedPaths = [complete.selection.paths[0]]; }, 'not-covered', 'scope-mismatch');
add(7, 'mixed-future-and-other-content', c => { reportOf(c).createdAt = '2027-01-01T00:00:00.000Z'; c.assessmentsInput.assessments.push({ ...candidate(structuredClone(old.cases[2].report)), location: 'other' }); }, 'not-scanned', 'not-found');
add(8, 'executable-mismatch', c => { c.item.materials[0].executable = true; }, 'not-covered', 'content-mismatch');
add(9, 'newer-partial-wins', c => { c.assessmentsInput.assessments[0].document = structuredClone(source.report); reportOf(c).createdAt = '2026-10-25T01:00:00.000Z'; c.assessmentsInput.assessments.push({ ...candidate(structuredClone(complete)), location: 'older-complete' }); }, 'partial');
add(10, 'detector-missing', c => { c.evidencePolicy.requiredDetectors = [{ detectorId: 'detector.absent', allowedProfileIds: [] }]; }, 'not-verified', 'detector-missing');
add(11, 'declared-executable-captured-unknown', c => { c.item.materials[0].executable = true; const report = reportOf(c); for (const e of report.source.capture.entries) if ('sha256' in e) e.executable = 'unknown'; for (const r of report.results) for (const o of r.observations) for (const e of o.body.input.entries) if ('sha256' in e) e.executable = 'unknown'; rebind(report); }, 'not-verified', 'executable-unknown');
add(12, 'profile-not-allowed', c => { c.evidencePolicy.requiredDetectors = [{ detectorId: 'detector.aih-native', allowedProfileIds: ['another-profile'] }]; }, 'not-verified', 'profile-not-allowed');
add(13, 'revoked-authentication', c => { c.authentication = { status: 'revoked' }; c.trustStatus = 'expired'; }, 'not-verified', 'revoked');
add(14, 'offline-last-known', c => { c.trustStatus = 'unavailable'; c.assessmentsInput.checks = [{ sourceId: 'fixture', attemptedAt: time, status: 'offline', diagnostics: [] }]; }, 'not-verified', 'offline', true, { freshness: 'last-known' });
add(15, 'authentication-unchecked', c => { c.authentication = { status: 'skipped', reason: 'not-requested' }; }, 'not-verified', 'unchecked');
add(16, 'older-than-policy', c => { c.evidencePolicy.maxAge = 'PT1H'; }, 'not-verified', 'older-than-policy');
add(17, 'verified-no-age-limit', () => {}, 'verified');
const variants = [];
function variant(baseRow, name, change, state, why) {
  const c = structuredClone(cases.find(c => c.row === baseRow)); c.name = name; change(c.input); c.value.state = state; if (why) c.value.why = why; else delete c.value.why;
  const report = reportOf(c.input); if (c.value.scanId) { c.value.scanId = `scan:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.report.v1\0'), bytes(report)]))}`; c.value.scannedAt = report.createdAt; }
  variants.push(c); return c;
}
variant(17, 'empty-policy-detector-not-covering', c => {
  const report = reportOf(c), path = report.selection.paths[0];
  report.selection.paths = [path]; c.assessmentsInput.context.selection.paths = [path];
  report.results[0].coverage.coveredPaths = [path];
  for (const observation of report.results[0].observations) { observation.body.input.targetPaths = [path]; observation.body.coverage.coveredPaths = [path]; }
  rebind(report);
}, 'not-verified', 'detector-not-covering');
variant(17, 'required-detector-not-covering', c => {
  const narrow = structuredClone(variants[0].input); Object.assign(c, narrow); c.evidencePolicy.requiredDetectors = [{ detectorId: 'detector.aih-native', allowedProfileIds: [] }];
}, 'not-verified', 'detector-not-covering');
variant(17, 'age-at-boundary', c => { c.evidencePolicy.maxAge = 'P1D'; }, 'verified');
variant(17, 'authentication-failed', c => { c.authentication = { status: 'unverifiable', reason: 'invalid-signature' }; }, 'not-verified', 'not-authenticated');
variant(17, 'expired-trust-before-unchecked', c => { c.trustStatus = 'expired'; c.authentication = { status: 'skipped' }; }, 'not-verified', 'offline');
variant(17, 'revoked-trust-historically-authentic', c => { c.trustStatus = 'revoked'; }, 'not-verified', 'revoked');
variant(6, 'source-mismatch', c => { c.assessmentsInput.context.selection = structuredClone(complete.selection); c.assessmentsInput.context.git = { repository: 'https://github.com/example/source', commit: 'a'.repeat(40) }; }, 'not-covered', 'source-mismatch');
variant(6, 'provider-mismatch', c => { c.assessmentsInput.context.selection = structuredClone(complete.selection); c.assessmentsInput.context.providers = [{ detectorId: 'detector.absent' }]; }, 'not-covered', 'provider-mismatch');
for (const field of ['missing', 'invalid']) {
  const v = variant(3, `${field}-createdAt`, c => { c.assessmentsInput.assessments[0].document = structuredClone(complete); if (field === 'missing') delete reportOf(c).createdAt; else reportOf(c).createdAt = 'yesterday'; }, 'unreadable');
  delete v.value.why;
}
// Controlled, item-attributed findings over real captured bytes. Multiplicities
// are independent literals; release/locationless findings are not attributed.
const counted = variant(17, 'severity-and-suppression-occurrences', c => {
  const report = reportOf(c), observation = report.results[0].observations[0];
  const material = c.item.materials[0];
  const finding = (level, rule, multiplicity, ordinal) => ({ rawOccurrenceFingerprint: `raw-occurrence-v1:${String(ordinal).repeat(64)}`, multiplicity, rule: { state: 'present', value: { nativeRuleId: rule } }, severity: level ? { state: 'present', value: { level } } : { state: 'unavailable', reason: 'not-supplied', detail: '' }, message: { state: 'present', value: 'Controlled fixture finding' }, location: { state: 'present', value: { path: material.path, fileSha256: material.sha256 } }, supportingEvidence: { state: 'unavailable', reason: 'not-supplied', detail: '' } });
  observation.body.findings = [finding('high', 'keep', 3, 1), finding('unknown', 'unknown', 2, 2), finding(null, 'absent', 1, 3), finding('high', 'suppress', 4, 4)];
  c.evidencePolicy.suppressions = [{ detectorId: 'detector.aih-native', nativeRuleId: 'suppress', path: material.path, reason: 'Documented exception' }]; rebind(report);
}, 'verified');
counted.value.findings = { error: 0, warning: 3, note: 0, unavailable: 3 };
counted.value.suppressed = { count: 4, reasons: [{ detectorId: 'detector.aih-native', nativeRuleId: 'suppress', reason: 'Documented exception', count: 4 }] };
const emit = (name, data) => { const dir = new URL(`../schemas/${name}/`, import.meta.url); mkdirSync(dir, { recursive: true }); writeFileSync(new URL('1.0.0.fixtures.json', dir), `${JSON.stringify(data, null, 2)}\n`); };
const metadata = { contractVersion: '1.0.0', provenance: { ...old.provenance, sourceContract: old.contractId, sourceItems: old.sourceItems.map(({ name, frameworkId, itemId, contentSha256, behaviourSource }) => ({ name, frameworkId, itemId, contentSha256, ...(behaviourSource ? { behaviourSource } : {}) })), note: 'Controlled decision-table specimens over the published real Catalog/stress-bundle item-record fixtures. No native execution or authenticity claim.' } };
const refused = { schema: 'urn:aihq:scan:item-summary:1.0.0', state: 'approved' };
emit('item-summary', { contractId: 'urn:aihq:scan:item-summary:1.0.0', ...metadata, cases: [...cases, { name: 'unsupported-positive-word', expectation: 'refuse', code: 'invalid-input', value: refused }], variants });
for (const [name, value, invalid] of [['evidence-policy', policy, { ...policy, signers: [] }], ['severity-profile', profile, { ...profile, rules: [{ detectorId: '*', level: 'high', maps: 'approved' }] }]]) emit(name, { contractId: value.schema, ...metadata, cases: [{ name: 'organization', expectation: 'accept', code: null, value }, { name: 'closed-contract', expectation: 'refuse', code: 'invalid-input', value: invalid }] });
