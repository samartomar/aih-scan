// Build first. Replays only the public fixture inputs, without network or native detectors.
// Usage: node tools/generate-item-record-fixtures.mjs [source-items.json]
// The optional argument replaces `sourceItems` (real Catalog release 1.7 items with their exact bytes).
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
import { readReport, recordItems } from '@aihq/scan/read';
const file = new URL('../schemas/item-record/1.0.0.fixtures.json', import.meta.url);
const fixtures = JSON.parse(readFileSync(file, 'utf8'));
if (process.argv[2]) fixtures.sourceItems = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, sort(value[k])])) : value;
const bytes = value => Buffer.from(JSON.stringify(sort(value)));
const hash = value => createHash('sha256').update(value).digest('hex');
const severityProfile = {
  schema: 'urn:aihq:scan:severity-profile:1.0.0', id: 'aih-default', version: '1',
  rules: [{ detectorId: '*', level: 'error', maps: 'error' }, { detectorId: '*', level: 'warning', maps: 'warning' }, { detectorId: '*', level: 'note', maps: 'note' }],
  suppressions: [],
};
/** The descriptor a Catalog reader passes for one item: its subject, behaviour fields and exact materials. */
export const descriptorOf = source => ({
  frameworkId: source.frameworkId, itemId: source.itemId, contentSha256: source.contentSha256, behaviourSha256: source.behaviourSha256,
  kind: source.kind, payload: source.payload, requirements: source.requirements, dependencies: source.dependencies,
  materials: source.materials.map(({ materialId, relPath, capturePath, executable, role, bytesBase64 }) => {
    const data = Buffer.from(bytesBase64, 'base64');
    return { materialId, relPath, capturePath, sha256: hash(data), byteLength: data.length, executable, role };
  }),
});
const cases = [];
for (const source of fixtures.sourceItems) {
  const root = mkdtempSync(join(tmpdir(), 'aih-item-golden-'));
  try {
    for (const { capturePath, bytesBase64 } of source.materials) {
      const target = join(root, capturePath);
      mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, Buffer.from(bytesBase64, 'base64')); chmodSync(target, 0o644);
    }
    const item = descriptorOf(source);
    const run = await runScan({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }, { detectorId: 'detector.unavailable', configuration: {} }] });
    if (run.status !== 'assessment') throw new Error(JSON.stringify(run));
    // Fixed time; captured modes are the 0644 regular files written above (Windows reports them as unknown).
    const report = run.report; report.createdAt = '2026-10-29T00:00:00.000Z';
    for (const entry of report.source.capture.entries) if ('sha256' in entry) entry.executable = false;
    report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
    for (const result of report.results) for (const observation of result.observations) {
      observation.body.startedAt = observation.body.completedAt = report.createdAt;
      for (const entry of observation.body.input.entries) if ('sha256' in entry) entry.executable = false;
      observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
    }
    for (const result of report.results) result.observations.sort((a, b) => a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0);
    const assessment = await readReport(bytes(report));
    if (assessment.status !== 'read') throw new Error(JSON.stringify(assessment));
    const batch = await recordItems({ artifact: assessment, items: [item], severityProfile });
    if (batch.status !== 'complete' || !('subject' in batch.results[0])) throw new Error(JSON.stringify(batch));
    cases.push({ name: source.name, expectation: 'accept', code: null, item, report, value: batch.results[0] });
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const authenticated = structuredClone(cases[0].value); authenticated.authenticity = 'authenticated';
cases.push({ name: 'record-cannot-assert-authenticity', expectation: 'refuse', code: 'invalid-record', value: authenticated });
const extra = structuredClone(cases[0].value); extra.materials[0].role = 'content';
cases.push({ name: 'unknown-material-field', expectation: 'refuse', code: 'unknown-field', value: extra });
// Independent worked example of the contract's evidence key preimage, computed here rather than by recordItems.
const base = cases[0];
const preimage = { contentSha256: base.item.contentSha256, behaviourSha256: base.item.behaviourSha256, detectors: base.report.requestedDetectors.map(({ detectorId }) => {
  const input = base.report.results.find(r => r.detectorId === detectorId).observations[0]?.body.input;
  return { id: detectorId, version: input?.detectorVersion ?? 'unavailable', rulesSha256: input?.rulesSha256 ?? null, profileSha256: input?.profileSha256 ?? null };
}).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0) };
const evidenceKeyExample = { note: 'Contract preimage { contentSha256, behaviourSha256, detectors[{ id, version, rulesSha256, profileSha256 }] }, computed by this generator independently of recordItems.', preimage, sha256: hash(bytes(preimage)) };
if (evidenceKeyExample.sha256 !== base.value.evidenceKey) throw new Error('evidence key example disagrees with recordItems');
writeFileSync(file, `${JSON.stringify({ ...fixtures, severityProfile, cases, evidenceKeyExample }, null, 2)}\n`);
