// Executes only against the exact archive installed outside the source checkout.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import * as api from '@aihq/scan/read';
import { authenticateArtifact, signArtifact } from '@aihq/scan/host';
import { summaryFixtureInput, replayItemSummaries } from './item-summary-replay.mjs';
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => new TextEncoder().encode(JSON.stringify(sort(v)));
const hash = v => createHash('sha256').update(v).digest('hex');
const fixture = name => JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.fixtures.json`)), 'utf8'));
export async function exerciseItemSummaries() {
  const fixtures = fixture('item-summary');
  const replay = await replayItemSummaries(api, fixtures);
  assert.deepEqual(replay.rows, Array.from({ length: 17 }, (_, i) => i + 1));
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  for (const name of ['item-summary', 'evidence-policy', 'severity-profile']) {
    const schema = JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.json`)), 'utf8'));
    assert.equal(schema.$id, `urn:aihq:scan:${name}:1.0.0`);
    const validate = ajv.compile(schema);
    for (const c of fixture(name).cases) assert.equal(validate(c.value), c.expectation === 'accept', `${name}/${c.name}: ${JSON.stringify(validate.errors)}`);
  }
  const example = name => summaryFixtureInput([...fixtures.cases, ...fixtures.variants].find(c => c.name === name));
  const countedInput = example('severity-and-suppression-occurrences');
  const assessment = await api.readReport(countedInput.assessmentsInput.assessments[0].bytes);
  const recordBefore = await api.recordItem(assessment, countedInput.item);
  const originalInput = JSON.stringify(countedInput);
  await api.summariseItem(countedInput);
  assert.equal(JSON.stringify(countedInput), originalInput, 'input evidence and policy unchanged');
  assert.deepEqual(await api.recordItem(assessment, countedInput.item), recordBefore, 'suppressions never modify records');
  const wrongPath = example('severity-and-suppression-occurrences');
  wrongPath.evidencePolicy.suppressions[0].path = 'other-file';
  const unsuppressed = await api.summariseItem(wrongPath);
  assert.equal(unsuppressed.summary.findings.warning, 7);
  assert.equal(unsuppressed.summary.suppressed.count, 0, 'suppression paths match exactly');
  delete wrongPath.evidencePolicy.suppressions[0].path;
  assert.equal((await api.summariseItem(wrongPath)).summary.suppressed.count, 4, 'path is optional');
  const malformedAuthentication = example('verified-no-age-limit');
  malformedAuthentication.authentication = { status: 'authenticated', reason: 'not-a-known-association-reason' };
  assert.equal((await api.summariseItem(malformedAuthentication)).status, 'invalid', 'host authentication reasons retain the existing closed enum');
  const mismatch = example('verified-no-age-limit'); mismatch.evidencePolicy.severityProfile.sha256 = '0'.repeat(64);
  assert.equal((await api.summariseItem(mismatch)).diagnostics[0].code, 'severity-profile-mismatch');
  const badContext = example('verified-no-age-limit'); badContext.assessmentsInput.context.selection.excludedPaths = ['not-selected'];
  assert.equal((await api.summariseItem(badContext)).status, 'invalid', 'selector admission failure passes through');
  const missingInputs = fixture('item-record').cases[0];
  const missingRecord = await api.recordItem(await api.readReport(bytes(missingInputs.report)), missingInputs.item);
  assert.equal(missingRecord.detectors.find(d => d.detectorId === 'detector.unavailable').effectiveProfileId, null);
  for (const maxAge of ['garbage', 'P', 'PT', '-P1D', 'P1DT', 'P9999999999999999999999Y']) {
    const bad = example('verified-no-age-limit'); bad.evidencePolicy.maxAge = maxAge;
    assert.equal((await api.summariseItem(bad)).status, 'invalid', maxAge);
  }
  // Public snapshots remain stable across async digest work, without executing getters.
  let getters = 0;
  const hostile = example('verified-no-age-limit');
  Object.defineProperty(hostile.evidencePolicy, 'suppressions', { enumerable: true, get() { getters++; return []; } });
  assert.equal((await api.summariseItem(hostile)).status, 'invalid'); assert.equal(getters, 0);
  const mutable = example('verified-no-age-limit');
  const pending = api.summariseItem(mutable);
  mutable.item.materials[0].sha256 = '0'.repeat(64); mutable.authentication.status = 'revoked'; mutable.assessmentsInput.assessments[0].bytes.fill(0);
  assert.equal((await pending).summary.state, 'verified');
  // Same authentic bytes remain authentic after a current revocation. This is
  // local ephemeral-key evidence, with no production signer or trust update.
  const historical = example('verified-no-age-limit');
  const report = JSON.parse(new TextDecoder().decode(historical.assessmentsInput.assessments[0].bytes));
  report.annexes = [];
  for (const result of report.results) for (const observation of result.observations) {
    observation.body.annexIds = [];
    observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const keyId = `ed25519:${hash(spki)}`;
  const signed = await signArtifact({ report, annexes: [], signer: { keyId, privateKey } });
  assert(signed.bytes instanceof Uint8Array);
  const authenticationInput = { bytes: signed.bytes, expectedScanId: signed.scanId, trust: { keys: [{ identity: 'fixture-organization', keyId, publicKeySpkiBase64: spki.toString('base64') }], publishers: [] } };
  const authenticated = await authenticateArtifact(authenticationInput);
  assert.equal(authenticated.status, 'authenticated');
  historical.assessmentsInput.assessments = [{ sourceId: 'fixture', location: 'signed', format: 'artifact', bytes: signed.bytes, authentication: authenticated }];
  historical.authentication = authenticated;
  assert.equal((await api.summariseItem(historical)).summary.state, 'verified');
  historical.trustStatus = 'revoked';
  assert.equal((await api.summariseItem(historical)).summary.why, 'revoked');
  assert.equal((await authenticateArtifact(authenticationInput)).status, 'authenticated');
  const sameLocation = example('newer-partial-wins');
  sameLocation.assessmentsInput.assessments.reverse();
  for (const candidate of sameLocation.assessmentsInput.assessments) candidate.location = 'same-address';
  const newest = await api.summariseItem(sameLocation);
  assert.equal(newest.status, 'summarised', JSON.stringify(newest));
  assert.equal(newest.summary.state, 'partial', 'selection identifies bytes, not just a mutable source address');
  return replay;
}
