// Conformance of the portable Sigstore evidence checks with real upstream-format evidence:
// a production Fulcio certificate, SCT and Rekor v1 entry (public synthetic research bundle),
// and sigstore-js's Rekor v2 Ed25519 checkpoint and production RFC 3161 timestamp fixture.
// These bundles are DSSE, which the public profile refuses; here only the shared mechanisms
// (chain, SCT, inclusion proof, checkpoint, SET, RFC 3161) are exercised.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { TlogEntry } from "../../src/read/sigstore/bundle.js";
import { base64Decode } from "../../src/read/sigstore/bytes.js";
import {
  verifyChain,
  verifyInclusion,
  verifyScts,
  verifyTimestamp,
} from "../../src/read/sigstore/evidence.js";
import { parseTrustedRoot } from "../../src/read/sigstore/trust.js";
import { parseCertificate, subjectAlternativeName } from "../../src/read/sigstore/x509.js";

const fixtures = join(import.meta.dirname, "..", "artifact", "fixtures");
const json = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const b64 = (value: string) => base64Decode(value) as Uint8Array;

function entryOf(raw: Record<string, any>): TlogEntry {
  const proof = raw.inclusionProof;
  return {
    logIndex: BigInt(raw.logIndex),
    logId: b64(raw.logId.keyId),
    kind: raw.kindVersion.kind,
    version: raw.kindVersion.version,
    integratedTime: raw.integratedTime === undefined ? undefined : BigInt(raw.integratedTime),
    signedEntryTimestamp:
      raw.inclusionPromise === undefined
        ? undefined
        : b64(raw.inclusionPromise.signedEntryTimestamp),
    body: b64(raw.canonicalizedBody),
    proof: {
      logIndex: BigInt(proof.logIndex),
      treeSize: BigInt(proof.treeSize),
      rootHash: b64(proof.rootHash),
      hashes: proof.hashes.map(b64),
      checkpoint: proof.checkpoint.envelope,
    },
  };
}

describe("portable Sigstore mechanisms on real upstream-format evidence", () => {
  it("verifies a production Fulcio chain, SCT and Rekor v1 SET/proof under the public root", async () => {
    const bundle = json("keyless-research-bundle.json");
    const trust = parseTrustedRoot(json("public-sigstore-root.json"));
    const leaf = parseCertificate(b64(bundle.verificationMaterial.certificate.rawBytes));
    expect(subjectAlternativeName(leaf)).toMatch(/^https:\/\/github\.com\/samartomar\/aih-scan\//);
    const entry = entryOf(bundle.verificationMaterial.tlogEntries[0]);
    const { integratedTime } = await verifyInclusion(entry, trust.tlogs);
    expect(integratedTime).toBe(
      Number(bundle.verificationMaterial.tlogEntries[0].integratedTime) * 1000,
    );
    const path = await verifyChain(leaf, trust.certificateAuthorities, integratedTime as number);
    expect(path).toHaveLength(3);
    expect(await verifyScts(leaf, path[1] as never, trust.ctlogs)).toBe(1);
    // A signing time after the leaf expired is outside its window.
    await expect(
      verifyChain(leaf, trust.certificateAuthorities, leaf.notAfter + 1000),
    ).rejects.toThrow();
    // Altered proof material is refused.
    const broken = { ...entry, proof: { ...entry.proof!, rootHash: new Uint8Array(32) } };
    await expect(verifyInclusion(broken, trust.tlogs)).rejects.toThrow();
    const otherSet = { ...entry, integratedTime: (entry.integratedTime as bigint) + 1n };
    await expect(verifyInclusion(otherSet, trust.tlogs)).rejects.toThrow();
  });

  it("verifies sigstore-js's Rekor v2 Ed25519 checkpoint and production RFC 3161 timestamp", async () => {
    const bundle = json("upstream-dsse-002.json");
    const trust = parseTrustedRoot(json("upstream-test-root.json"));
    const entry = entryOf(bundle.verificationMaterial.tlogEntries[0]);
    const { integratedTime } = await verifyInclusion(entry, trust.tlogs);
    expect(integratedTime).toBeUndefined();
    const signature = b64(bundle.dsseEnvelope.signatures[0].sig);
    const token = b64(
      bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp,
    );
    const time = await verifyTimestamp(token, signature, trust.timestampAuthorities);
    const leaf = parseCertificate(b64(bundle.verificationMaterial.certificate.rawBytes));
    expect(time).toBeGreaterThanOrEqual(leaf.notBefore);
    expect(time).toBeLessThanOrEqual(leaf.notAfter);
    await expect(
      verifyTimestamp(token, new Uint8Array(signature.length), trust.timestampAuthorities),
    ).rejects.toThrow();
  });
});
