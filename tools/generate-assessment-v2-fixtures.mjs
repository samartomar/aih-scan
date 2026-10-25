// Golden contract specimens from the existing real grill-me materials. No network or native detectors.
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
const old = JSON.parse(readFileSync(new URL('../schemas/request/1.0.0.fixtures.json', import.meta.url), 'utf8'));
const canonical = value => Buffer.from(JSON.stringify(sort(value)));
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
const hash = value => createHash('sha256').update(value).digest('hex');
const root = mkdtempSync(join(tmpdir(), 'aih-capture2-golden-'));
const request = { ...old.cases.find(entry => entry.expectation === 'accept').value,
  schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'local', path: root } };
try {
  for (const material of old.materials) {
    const path = join(root, material.path); mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, Buffer.from(material.bytesBase64, 'base64'), { mode: 0o644 });
    chmodSync(path, 0o644);
  }
  const first = await runScan(request);
  if (first.status !== 'assessment') throw new Error(JSON.stringify(first));
  const make = (kind, executable) => {
    const run = structuredClone(first);
    run.report.createdAt = '2026-10-25T00:00:00.000Z';
    // Keep original observation timing and recompute identity-bearing bodies for static specimens.
    for (const result of run.report.results) for (const observation of result.observations) {
      observation.body.startedAt = observation.body.completedAt = run.report.createdAt;
      for (const entry of observation.body.input.entries) if ('sha256' in entry) entry.executable = executable === true ? entry.path === 'SKILL.md' : executable;
      observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), canonical(observation.body)]))}`;
    }
    const capture = run.report.source.capture;
    for (const entry of capture.entries) if ('sha256' in entry) entry.executable = executable === true ? entry.path === 'SKILL.md' : executable;
    capture.captureSha256 = hash(canonical({ domain: 'aih.scan.capture.v2', profile: capture.profile, entries: capture.entries }));
    if (kind === 'git') run.report.source = { kind, repository: 'https://example.invalid/grill-me.git', commit: 'a'.repeat(40), capture };
    run.reachability = run.report.reachability = kind === 'git' ? 'unchecked' : null;
    run.scanId = `scan:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.report.v1\0'), canonical(run.report)]))}`;
    return run;
  };
  const variants = [ ['grill-me-local-nonexecutable', make('local', false)], ['grill-me-executable-only-change', make('local', true)], ['local-mode-unavailable', make('local', 'unknown')], ['git-tree-100755-and-100644', make('git', true)] ];
  const save = (name, cases) => writeFileSync(new URL(`../schemas/${name}/2.0.0.fixtures.json`, import.meta.url), `${JSON.stringify({ contractId: `urn:aihq:scan:${name}:2.0.0`, contractVersion: '2.0.0', provenance: { ...old.provenance, note: 'Static contract specimens derived from real grill-me captured bytes. Mode variants and Git source labels are explicit specimens, not native platform or reachability execution evidence.' }, ...(name === 'request' ? { materials: old.materials } : {}), cases }, null, 2)}\n`);
  const accepted = (name, value) => ({ name, expectation: 'accept', code: null, value });
  const rejected = (name, value, code = 'invalid-input', validation = 'schema') => ({ name, expectation: 'refuse', code, validation, value });
  const portable = { ...request, source: { kind: 'local', path: '/fixtures/grill-me' } };
  save('request', [accepted('grill-me-request-v2', portable), accepted('exact-npm-version', { ...portable, source: { kind: 'npm', package: '@aihq/fixture', version: '1.2.3' } }), accepted('integrity-pinned-npm-archive', { ...portable, source: { kind: 'npm', archive: { url: 'https://example.invalid/fixture.tgz', integrity: `sha512-${Buffer.alloc(64).toString('base64')}` } } }), rejected('mutable-npm-version', { ...portable, source: { kind: 'npm', package: '@aihq/fixture', version: 'latest' } })]);
  save('report', [...variants.map(([name, run]) => accepted(name, run.report)), rejected('missing-executable-state', (() => { const r = structuredClone(variants[0][1].report); delete r.source.capture.entries.find(e => 'sha256' in e).executable; return r; })())]);
  save('run-result', [ ...variants.map(([name, run]) => accepted(name, run)), rejected('missing-reachability-outcome', (() => { const r = structuredClone(variants[0][1]); delete r.reachability; return r; })()) ]);
} finally { rmSync(root, { recursive: true, force: true }); }
