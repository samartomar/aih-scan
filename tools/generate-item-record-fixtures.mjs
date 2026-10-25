// Build first. Replays only the public fixture inputs, without network or native detectors.
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
import { readReport, recordItem } from '@aihq/scan/read';
const file = new URL('../schemas/item-record/1.0.0.fixtures.json', import.meta.url);
const fixtures = JSON.parse(readFileSync(file, 'utf8'));
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, sort(value[k])])) : value;
const bytes = value => Buffer.from(JSON.stringify(sort(value)));
const hash = value => createHash('sha256').update(value).digest('hex');
const cases = [];
for (const source of fixtures.sourceItems) {
  const root = mkdtempSync(join(tmpdir(), 'aih-item-golden-'));
  try {
    const materials = source.materials.map(({ path, bytesBase64, executable, role }) => {
      const data = Buffer.from(bytesBase64, 'base64'), target = join(root, path);
      mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, data); chmodSync(target, 0o644);
      return { path, sha256: hash(data), byteLength: data.length, executable, role };
    });
    const item = { frameworkId: source.frameworkId, itemId: source.itemId, contentSha256: source.contentSha256, behaviourSha256: materials.find(m => m.role === 'behaviour').sha256, materials };
    const run = await runScan({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }, { detectorId: 'detector.unavailable', configuration: {} }] });
    if (run.status !== 'assessment') throw new Error(JSON.stringify(run));
    const report = run.report; report.createdAt = '2026-10-25T00:00:00.000Z';
    for (const entry of report.source.capture.entries) if ('sha256' in entry) entry.executable = false;
    report.source.capture.captureSha256 = hash(bytes({ domain: 'aih.scan.capture.v2', profile: report.source.capture.profile, entries: report.source.capture.entries }));
    for (const result of report.results) for (const observation of result.observations) {
      observation.body.startedAt = observation.body.completedAt = report.createdAt;
      for (const entry of observation.body.input.entries) if ('sha256' in entry) entry.executable = false;
      observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
    }
    const assessment = await readReport(bytes(report));
    if (assessment.status !== 'read') throw new Error(JSON.stringify(assessment));
    const record = await recordItem(assessment, item);
    cases.push({ name: source.name, expectation: 'accept', code: null, item, report, value: record });
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const invalid = structuredClone(cases[0].value); invalid.authenticity = 'authenticated';
cases.push({ name: 'record-cannot-assert-authenticity', expectation: 'refuse', code: 'invalid-input', value: invalid });
writeFileSync(file, `${JSON.stringify({ ...fixtures, cases }, null, 2)}\n`);
