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
  assert.deepEqual(replay.rows, Array.from({ length: 13 }, (_, i) => i + 1));
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  for (const name of ['item-summary', 'evidence-policy', 'severity-profile']) {
    const schema = JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}/1.0.0.json`)), 'utf8'));
    assert.equal(schema.$id, `urn:aihq:scan:${name}:1.0.0`);
    const validate = ajv.compile(schema);
    for (const c of fixture(name).cases) assert.equal(validate(c.value), c.expectation === 'accept', `${name}/${c.name}: ${JSON.stringify(validate.errors)}`);
  }
  const example = name => summaryFixtureInput(api, [...fixtures.cases, ...fixtures.variants].find(c => c.name === name));
  const verified = await example('verified');
  const before = JSON.stringify(verified);
  assert.equal((await api.summariseItem(verified)).summary.state, 'verified');
  assert.equal(JSON.stringify(verified), before, 'inputs are unchanged');
  const picked = await api.pickRecord({ records: verified.records, item: verified.item, policy: verified.policy, severityProfiles: verified.severityProfiles });
  assert.deepEqual([picked.status, picked.index, picked.why], ['picked', 0, 'only-record']);
  const malformed = await example('verified');
  malformed.records[0].authentication = { status: 'authenticated', reason: 'not-a-known-association-reason' };
  assert.equal((await api.summariseItem(malformed)).status, 'invalid', 'host authentication reasons retain the existing closed enum');
  for (const maxAge of ['garbage', 'P', 'PT', '-P1D', 'P1DT', 'P9999999999999999999999Y']) {
    const bad = await example('verified'); bad.policy.maxAge = maxAge;
    assert.equal((await api.summariseItem(bad)).status, 'invalid', maxAge);
  }
  let getters = 0;
  const hostile = await example('verified');
  Object.defineProperty(hostile.policy, 'requiredDetectors', { enumerable: true, get() { getters++; return ['detector.aih-native']; } });
  assert.equal((await api.summariseItem(hostile)).status, 'invalid'); assert.equal(getters, 0);
  // Same authentic bytes remain authentic after a current revocation. This is
  // local ephemeral-key evidence, with no production signer or trust update.
  const entry = fixtures.cases.find(c => c.name === 'verified');
  const report = structuredClone(entry.input.records[0].report);
  report.annexes = [];
  for (const result of report.results) for (const observation of result.observations) {
    observation.body.annexIds = [];
    observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from('aih.scan.observation.v2\0'), bytes(observation.body)]))}`;
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const keyId = `ed25519:${hash(spki)}`;
  const signed = await signArtifact({ report, annexes: [], signer: { keyId, privateKey } });
  const authenticationInput = { bytes: signed.bytes, expectedScanId: signed.scanId, trust: { keys: [{ identity: 'fixture-organization', keyId, publicKeySpkiBase64: spki.toString('base64') }], publishers: [] } };
  const authenticated = await authenticateArtifact(authenticationInput);
  assert.equal(authenticated.status, 'authenticated');
  const artifact = await api.readArtifact(signed.bytes);
  const record = (await api.recordItems({ artifact, items: [verified.item], severityProfile: verified.severityProfiles[0] })).results[0];
  const historical = { ...verified, records: [{ record, artifact, authentication: authenticated }] };
  assert.equal((await api.summariseItem(historical)).summary.state, 'verified');
  assert.equal((await api.summariseItem({ ...historical, trustStatus: 'revoked' })).summary.why, 'revoked');
  assert.equal((await authenticateArtifact(authenticationInput)).status, 'authenticated');
  const other = await authenticateArtifact({ ...authenticationInput, trust: { keys: [], publishers: [] } });
  assert.equal((await api.summariseItem({ ...historical, records: [{ record, artifact, authentication: other }] })).summary.why, 'not-authenticated');
  return replay;
}
