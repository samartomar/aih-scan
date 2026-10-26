// Copied beside an exact packed installation. All product calls use public exports.
// Local fixture CA/log keys never become maintained publisher trust.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import { attachAttestation, authenticateArtifact, prepareArtifact, signArtifact } from '@aihq/scan/host';
import { readArtifact, summariseItem } from '@aihq/scan/read';

const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => Buffer.from(JSON.stringify(sort(v)));
const hash = v => createHash('sha256').update(v).digest('hex');

export async function exercisePublisherSigning() {
  const originals = [];
  const block = (object, key) => {
    originals.push([object, key, object[key]]);
    object[key] = () => { throw new Error(`Network/OIDC forbidden in offline publisher fixture: ${key}`); };
  };
  block(globalThis, 'fetch');
  for (const [object, keys] of [[http, ['request', 'get']], [https, ['request', 'get']], [net, ['connect', 'createConnection']], [tls, ['connect']], [dns, ['lookup', 'resolve']], [dns.promises, ['lookup', 'resolve']]]) for (const key of keys) block(object, key);
  syncBuiltinESMExports();
  try {
    const { artifact, publisher, summaryInput } = JSON.parse(readFileSync('offline-publisher-fixture.json', 'utf8'));
    const report = JSON.parse(Buffer.from(artifact.report.bytesBase64, 'base64'));
    const annexes = artifact.annexes.map(a => ({ id: a.id, bytes: Buffer.from(a.bytesBase64, 'base64') }));
    assert(annexes[0].bytes.length > 0);
    const prepared = await prepareArtifact({ report, annexes });
    // Report v2 is admitted by the existing artifact and statement generations.
    assert.equal(prepared.artifact.schema, 'urn:aihq:scan:artifact:1.0.0');
    assert.deepEqual(prepared.statement, {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'scan-report', digest: { sha256: hash(Buffer.from(artifact.report.bytesBase64, 'base64')) } }],
      predicateType: 'urn:aihq:scan:artifact-attestation:1.0.0',
      predicate: {
        scanId: artifact.scanId,
        reportSchema: 'urn:aihq:scan:report:2.0.0',
        reportByteLength: Buffer.from(artifact.report.bytesBase64, 'base64').length,
        annexManifestSha256: hash(bytes(report.annexes)),
      },
    });
    const attached = await attachAttestation({ bytes: prepared.bytes, bundle: artifact.attestation });
    const read = await readArtifact(attached.bytes);
    assert.equal(read.status, 'read');
    assert.equal(read.authenticity, 'unchecked');
    assert.equal(read.annexBytes, 'checked');
    const authenticate = publishers => authenticateArtifact({ bytes: attached.bytes, expectedScanId: attached.scanId, trust: { keys: [], publishers } });
    const selected = await authenticate([publisher]);
    assert.equal(selected.status, 'authenticated');
    assert.equal(selected.producerIdentity, 'TEST-ONLY-local-publisher');
    summaryInput.assessmentsInput.assessments = [{ sourceId: 'fixture', location: 'offline-fixture', format: 'artifact', bytes: attached.bytes, authentication: selected }];
    summaryInput.authentication = selected;
    const summary = async () => {
      const result = await summariseItem(summaryInput);
      assert.equal(result.status, 'summarised');
      assert.equal(result.summary.scanId, attached.scanId);
      return result.summary;
    };
    assert.equal((await summary()).state, 'verified', 'test-only selected identity and exact item coverage');
    const unselected = structuredClone(publisher);
    unselected.policy.subjectAlternativeName = 'https://test.invalid/workflows/unselected@refs/heads/test';
    summaryInput.authentication = await authenticate([unselected]);
    assert.equal(summaryInput.authentication.status, 'unverifiable');
    assert.equal((await summary()).why, 'not-authenticated');
    assert.equal((await summary()).state, 'not-verified');
    assert.equal((await authenticate([])).status, 'unverifiable');
    // Host trust availability is independent of historical crypto authentication.
    // The public summary receives the same explicit statuses a host/TUF client supplies.
    for (const trustStatus of ['expired', 'unavailable']) {
      summaryInput.trustStatus = trustStatus;
      for (const authentication of [selected, { status: 'skipped', reason: 'not-requested' }]) {
        summaryInput.authentication = authentication;
        assert.equal((await summary()).state, 'not-verified');
        assert.equal((await summary()).why, 'offline', `row 14: ${trustStatus} precedes unchecked`);
      }
    }
    assert.equal((await authenticate([publisher])).status, 'authenticated', 'trust freshness does not rewrite historical authenticity');
    // A public key beside the evidence is merely untrusted data. Only the
    // independently supplied trust argument can select it.
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const keyId = `ed25519:${hash(spki)}`;
    const signed = await signArtifact({ report, annexes, signer: { keyId, privateKey } });
    writeFileSync('evidence-adjacent-key.json', JSON.stringify({ keyId, publicKeySpkiBase64: spki.toString('base64') }));
    assert.equal((await authenticateArtifact({ bytes: signed.bytes, expectedScanId: signed.scanId, trust: { keys: [], publishers: [] } })).reason, 'untrusted-key');
    assert.equal((await authenticateArtifact({ bytes: signed.bytes, expectedScanId: signed.scanId, trust: { keys: [{ identity: 'TEST-ONLY-caller-selected-key', keyId, publicKeySpkiBase64: spki.toString('base64') }], publishers: [] } })).status, 'authenticated');
    // Statement/annex admission refuses an item subject and altered annex bytes.
    const itemSubject = structuredClone(artifact.attestation);
    const statement = JSON.parse(Buffer.from(itemSubject.dsseEnvelope.payload, 'base64'));
    statement.subject.push({ name: 'item', digest: { sha256: '0'.repeat(64) } });
    itemSubject.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
    await assert.rejects(attachAttestation({ bytes: prepared.bytes, bundle: itemSubject }));
    const changedAnnex = structuredClone(artifact);
    changedAnnex.annexes[0].bytesBase64 = Buffer.from('tampered annex').toString('base64');
    assert.equal((await readArtifact(bytes(changedAnnex))).status, 'invalid');
  } finally {
    for (const [object, key, value] of originals) object[key] = value;
    syncBuiltinESMExports();
  }
}
