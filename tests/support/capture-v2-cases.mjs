// Executed only in the exact packed package's disposable consumer.
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRetainedObservationsV1, prepareArtifact, runScan, signArtifact } from '@aihq/scan/host';
import { readArtifact, readContentCoverage, readReport } from '@aihq/scan/read';

import { createHash, generateKeyPairSync } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const bytes = value => new TextEncoder().encode(JSON.stringify(sorted(value)));
const fixture = spec => JSON.parse(readFileSync(new URL(import.meta.resolve(spec)), 'utf8'));
export async function exerciseCaptureV2() {
  const root = resolve('capture-v2-grill-me');
  mkdirSync(root);
  const skill = resolve(root, 'SKILL.md');
  writeFileSync(skill, '# grill-me\n', { mode: 0o644 });
  const request = {
    schema: 'urn:aihq:scan:request:2.0.0',
    source: { kind: 'local', path: root },
    selection: { paths: 'all', excludedPaths: [] },
    detectors: [{ detectorId: 'detector.aih-native', configuration: {} }],
  };
  const retained = createRetainedObservationsV1();
  const first = await runScan(request, { retained });
  assert.equal(first.status, 'assessment', JSON.stringify(first));
  assert.equal(first.schema, 'urn:aihq:scan:run-result:2.0.0');
  assert.equal(first.report.schema, 'urn:aihq:scan:report:2.0.0');
  assert.equal(first.report.source.capture.profile, 'aih-source-capture-2');
  assert.equal(first.report.source.capture.entries[0].executable, process.platform === 'win32' ? 'unknown' : false);
  assert.equal(first.report.results[0].observations[0].body.format, 'aih-observation-v2');
  const again = await runScan(request, { retained });
  assert.equal(again.report.results[0].observations[0].origin, 'reused');
  if (process.platform !== 'win32') {
    chmodSync(skill, 0o755);
    const changed = await runScan(request, { retained });
    assert.equal(changed.status, 'assessment', JSON.stringify(changed));
    assert.equal(changed.report.source.capture.entries[0].executable, true);
    assert.notEqual(changed.report.source.capture.captureSha256, first.report.source.capture.captureSha256);
    assert.equal(changed.report.results[0].observations[0].origin, 'fresh');
    assert.notEqual(changed.report.results[0].observations[0].observationId, first.report.results[0].observations[0].observationId);
  }
  const unsupported = await readReport(new TextEncoder().encode('{"schema":"urn:aihq:scan:report:99.0.0"}'));
  assert.deepEqual(unsupported.diagnostics?.[0], {
    code: 'unsupported-format', path: '$.schema', encountered: 'urn:aihq:scan:report:99.0.0',
    supported: ['urn:aihq:scan:report:1.0.0', 'urn:aihq:scan:report:2.0.0'],
    detail: 'Unsupported format at $.schema',
  });
  const encode = value => new TextEncoder().encode(JSON.stringify(value));
  // A read view exposes unknown mode facts without changing the original report or its identity.
  const oldFixture = JSON.parse((await import('node:fs')).readFileSync(new URL(import.meta.resolve('@aihq/scan/schemas/report/1.0.0.fixtures.json')), 'utf8'));
  const wire = oldFixture.cases.find(entry => entry.expectation === 'accept').value;
  const oldRead = await readReport(encode(sorted(wire)));
  assert.equal(oldRead.status, 'read');
  assert(oldRead.capture.entries.filter(entry => 'sha256' in entry).every(entry => entry.executable === 'unknown'));
  assert.deepEqual(oldRead.report, wire);
  const packed = await prepareArtifact({ report: first.report, annexes: first.annexes.map(a => ({ id: a.id, bytes: Buffer.from(a.bytesBase64, 'base64') })) });
  assert.equal(packed.artifact.schema, 'urn:aihq:scan:artifact:1.0.0');
  assert.equal(packed.statement.predicate.reportSchema, 'urn:aihq:scan:report:2.0.0');
  assert.equal((await readArtifact(packed.bytes)).status, 'read');
  const keys = generateKeyPairSync('ed25519');
  const keyId = `ed25519:${createHash('sha256').update(keys.publicKey.export({ format: 'der', type: 'spki' })).digest('hex')}`;
  const signed = await signArtifact({ report: first.report, annexes: first.annexes.map(a => ({ id: a.id, bytes: Buffer.from(a.bytesBase64, 'base64') })), signer: { keyId, privateKey: keys.privateKey } });
  assert.equal((await readArtifact(signed.bytes)).status, 'read');
  const unknownContainer = { ...packed.artifact, schema: 'urn:aihq:scan:artifact:99.0.0' };
  for (const unknown of [unknownContainer, { ...unknownContainer, newGenerationField: true }, { schema: unknownContainer.schema }]) {
    const refused = await readArtifact(bytes(unknown));
    assert.equal(refused.status, 'invalid');
    assert.deepEqual(refused.diagnostics[0], { code: 'unsupported-format', path: '$.schema', encountered: unknownContainer.schema,
      supported: ['urn:aihq:scan:artifact:1.0.0'], detail: 'Unsupported format at $.schema' });
  }
  const knownWithExtra = await readArtifact(bytes({ ...packed.artifact, newGenerationField: true }));
  assert.equal(knownWithExtra.status, 'invalid');
  assert.equal(knownWithExtra.diagnostics[0].code, 'invalid-artifact');
  assert.equal((await runScan({ ...request, schema: 'urn:aihq:scan:request:99.0.0' })).diagnostics[0].code, 'unsupported-format');
  const retainedLegacy = createRetainedObservationsV1();
  const legacy = await runScan({ ...request, schema: 'urn:aihq:scan:request:1.0.0' }, { retained: retainedLegacy });
  const afterLegacy = await runScan(request, { retained: retainedLegacy });
  assert.equal(afterLegacy.report.results[0].observations[0].origin, process.platform === 'win32' ? 'reused' : 'fresh');
  if (process.platform === 'win32') {
    assert.equal(afterLegacy.report.results[0].observations[0].observationId, legacy.report.results[0].observations[0].observationId);
    assert.equal(afterLegacy.report.results[0].observations[0].body.format, 'aih-observation-v1');
  }
  assert.notEqual(legacy.report.source.capture.captureSha256, afterLegacy.report.source.capture.captureSha256);
  if (process.platform !== 'win32') {
    // System filesystem boundary: links retain target mode and containment remains fail-closed.
    symlinkSync('SKILL.md', resolve(root, 'linked-skill'));
    const link = await runScan(request);
    assert.equal(link.status, 'assessment', JSON.stringify(link));
    assert.equal(link.report.source.capture.entries.find(e => e.path === 'linked-skill').executable, true);
    symlinkSync('../outside', resolve(root, 'escape'));
    writeFileSync(resolve('outside'), 'outside captured root');
    assert.equal((await runScan(request)).phase, 'capture');
  }
  const selected = resolve('capture-v2-selected'); mkdirSync(selected);
  writeFileSync(resolve(selected, 'SKILL.md'), '# selected\n', { mode: 0o644 });
  writeFileSync(resolve(selected, 'other.txt'), 'other\n', { mode: 0o644 });
  const scopedRequest = { ...request, source: { kind: 'local', path: selected }, selection: { paths: ['SKILL.md'], excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-binding-gate', configuration: {} }, ...request.detectors] };
  const scopedStore = createRetainedObservationsV1();
  const before = await runScan(scopedRequest, { retained: scopedStore });
  if (process.platform !== 'win32') {
    chmodSync(resolve(selected, 'other.txt'), 0o755);
    const after = await runScan(scopedRequest, { retained: scopedStore });
    assert.equal(after.status, 'assessment', JSON.stringify(after));
    assert.equal(after.report.results[0].observations[0].origin, 'reused');
    assert.equal(after.report.results[0].observations[0].observationId, before.report.results[0].observations[0].observationId);
    assert.equal(after.report.results[1].observations[0].origin, 'fresh');
  }
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  for (const name of ['request', 'report', 'run-result']) {
    const doc = fixture(`@aihq/scan/schemas/${name}/2.0.0.fixtures.json`);
    const schema = fixture(`@aihq/scan/schemas/${name}/2.0.0.json`);
    assert.equal(doc.contractId, schema.$id);
    const validate = ajv.compile(schema);
    for (const entry of doc.cases) {
      assert.equal(validate(entry.value), entry.expectation === 'accept', `${name}/${entry.name}: ${JSON.stringify(validate.errors)}`);
      if (name === 'report') assert.equal((await readReport(bytes(entry.value))).status, entry.expectation === 'accept' ? 'read' : 'invalid');
      if (name === 'request') {
        const req = structuredClone(entry.value);
        if (req.source.kind === 'local') req.source.path = selected;
        const run = await runScan(req);
        if (req.source.kind === 'npm' && entry.expectation === 'accept') {
          assert.equal(run.phase, 'capture'); assert.equal(run.diagnostics[0].code, 'source-kind-unavailable');
        } else assert.equal(run.status, entry.expectation === 'accept' ? 'assessment' : 'diagnostic');
      }
    }
  }
  const reportFixtures = fixture('@aihq/scan/schemas/report/2.0.0.fixtures.json');
  const unknown = structuredClone(reportFixtures.cases.find(e => e.name === 'local-mode-unavailable').value);
  // Profile-1 observations may be embedded unchanged only with unknown relevant modes.
  const oldReport = oldFixture.cases.find(e => e.expectation === 'accept').value;
  unknown.results = structuredClone(oldReport.results);
  unknown.createdAt = '2099-01-01T00:00:00.000Z';
  assert.equal((await readReport(bytes(unknown))).status, 'invalid', 'old observations embedded in a new assessment must be marked reused');
  for (const result of unknown.results) for (const observation of result.observations) {
    observation.origin = 'reused'; observation.fromScanId = oldRead.scanId;
  }
  const compatible = await readReport(bytes(unknown));
  assert.equal(compatible.status, 'read', JSON.stringify(compatible));
  assert.deepEqual(compatible.report.results.flatMap(r => r.observations.map(o => o.body)), oldReport.results.flatMap(r => r.observations.map(o => o.body)));
  unknown.source.capture.entries.find(e => 'sha256' in e).executable = true;
  unknown.source.capture.captureSha256 = createHash('sha256').update(bytes({ domain: 'aih.scan.capture.v2', profile: unknown.source.capture.profile, entries: unknown.source.capture.entries })).digest('hex');
  assert.equal((await readReport(bytes(unknown))).status, 'invalid');
  await exerciseGitModesV2(request);
  const limited = await runScan({ ...scopedRequest, limits: { maxSourceEntries: 1 } });
  assert.equal(limited.phase, 'capture'); assert.equal(limited.diagnostics[0].code, 'resource-limit');
  const firstRead = await readReport(bytes(first.report));
  const descriptor = first.report.source.capture.entries.find(e => e.kind === 'file');
  assert.equal((await readContentCoverage({ read: firstRead, descriptors: [{ path: descriptor.path, sha256: descriptor.sha256, byteLength: descriptor.byteLength }] })).status, 'matched');
  const unsupportedBody = structuredClone(first.report);
  unsupportedBody.results[0].observations[0].body.format = 'aih-observation-v99';
  const bodyRefusal = await readReport(bytes(unsupportedBody));
  assert.equal(bodyRefusal.diagnostics[0].code, 'unsupported-format');
  assert.equal(bodyRefusal.diagnostics[0].path, '$.results[0].observations[0].body.format');
  return { status: 'tested' };
}

async function exerciseGitModesV2(request) {
  if (process.platform === 'win32') return; // Static Git-mode specimens are read on every platform.
  const { execFileSync } = await import('node:child_process');
  const { delimiter } = await import('node:path');
  const fixtureRoot = resolve('capture-v2-git-fixture'); mkdirSync(fixtureRoot);
  const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  const git = args => execFileSync(realGit, args, { cwd: fixtureRoot, env, encoding: 'utf8', stdio: 'pipe' });
  git(['init', '--quiet']);
  writeFileSync(resolve(fixtureRoot, 'executable'), 'same bytes\n');
  writeFileSync(resolve(fixtureRoot, 'regular'), 'same bytes\n');
  git(['add', '.']); git(['update-index', '--chmod=+x', 'executable']);
  git(['update-index', '--chmod=-x', 'regular']);
  git(['-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'tree modes']);
  const commit = git(['rev-parse', 'HEAD']).trim();
  const bin = resolve('capture-v2-fixture-bin'); mkdirSync(bin);
  // Mock only the external Git executable. Production modules and process containment run unchanged.
  writeFileSync(resolve(bin, 'git'), `#!${process.execPath}\nconst {execFileSync}=require('node:child_process');\nconst args=process.argv.slice(2);\nif(args.includes('init')||args.includes('fetch'))process.exit(0);\nprocess.stdout.write(execFileSync(${JSON.stringify(realGit)},['--git-dir='+${JSON.stringify(resolve(fixtureRoot,'.git'))},...args],{stdio:['ignore','pipe','pipe']}));\n`, { mode: 0o755 });
  const oldPath = process.env.PATH;
  process.env.PATH = `${bin}${delimiter}${oldPath}`;
  try {
    const run = await runScan({ ...request, source: { kind: 'git', repository: 'https://example.invalid/fixture.git', commit } });
    assert.equal(run.status, 'assessment', JSON.stringify(run));
    assert.equal(run.reachability, 'unchecked'); assert.equal(run.report.reachability, 'unchecked');
    assert.deepEqual(run.report.source.capture.entries.map(e => [e.path,e.executable]), [['executable',true],['regular',false]]);
  } finally { process.env.PATH = oldPath; }
}
