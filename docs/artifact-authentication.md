# Immutable artifact APIs

`@aihq/scan/read` reads complete portable artifacts without detector execution.
It checks canonical container/report bytes, immutable Scan ID and complete annex
bindings. Successful reads always report `authenticity: "unchecked"`; presence
of a signature makes no authentication claim. Unsupported detailed report
generations remain explicitly unsupported after outer byte checks.

`@aihq/scan/host` requires Node `>=24.15.0 <25` and exposes separate promise APIs:

```js
const prepared = await prepareArtifact({ report, annexes: [{ id, bytes }] });
const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
const signed = await signArtifact({
  report, annexes,
  signer: { keyId, privateKey } // explicit Node Ed25519 private KeyObject
});
const authenticity = await authenticateArtifact({
  bytes: signed.bytes, expectedScanId: signed.scanId,
  trust: { keys, publishers } // independently selected; both arrays explicit
});
```

Preparation validates a supported complete report account and exact annexes. A
partial assessment is signable. It returns canonical unsigned artifact bytes and
the minimal derived in-toto statement. Attachment checks bounded Sigstore v0.3
DSSE structure and byte/identity/manifest bindings; it does not verify a signature
or authenticate a producer. It rejects already-attested input. Prepare the
unchanged assessment again to replace a signature while retaining its Scan ID.
These APIs write/post nothing and do not receive OIDC tokens or signing URLs.

Local signing uses Ed25519 over DSSE PAE. Derive `keyId` as `ed25519:` followed
by SHA-256 of the public SPKI DER bytes. The bundle public-key hint and DSSE keyid
must both equal that fingerprint. Selected organization keys are
`{identity,keyId,publicKeySpkiBase64}`. No certificate, log or nonempty timestamp
data can enter this explicit key profile.

Certificate trust uses purpose-selected `sigstore-public` publisher records with
independently supplied public Sigstore roots, exact issuer/SAN and exact required
OID DER values. The pinned upstream verifier checks P-256 leaf signing, CA/CT,
Rekor proofs and witnessed signing time with all three thresholds equal to one.
DSSE `0.0.1` requires proof plus verified promise; `0.0.2` requires proof plus a
verified RFC3161 witness. Current leaf expiry does not expire historical reports.
Verification preserves the originally decoded statement bytes, including valid
noncanonical JSON ordering. It never retries a failed trust path as another.

Authentication is narrow: it can authenticate an unsupported detailed report's
opaque bytes, but that does not validate its findings or observation semantics.
Producer identity comes from selected trust. Equivalent historical policy matches
for one identity consolidate; matches for differing identities refuse. Explicit
distrust changes subsequent authentication, while repeated reads have no TTL.
No consumer network/root refresh, ambient key search or artifact-supplied trust
is used. No maintained producer trust is shipped by Scan.

Construction promises reject with bounded safe messages and one of
`invalid-input`, `resource-limit`, `unsupported-artifact`, `already-attested`, or
`signing-failed`. Authentication returns the finite evidence-association refusal
reasons. All control JSON is strict UTF-8, duplicate-free, NFC, closed and uses
nonnegative safe integers. Upstream uint64 indices remain exact decimal strings.
Decoded limits include report/each annex 16 MiB, aggregate 64 MiB, artifact 96 MiB,
statement 128 KiB and attestation 1 MiB. Additional certificate, log, timestamp,
proof and independently selected trust caps are enforced before crypto parsing.

Local synthetic CA/CT/Rekor/TSA fixtures exercise successful `authenticateArtifact`
with the Scan predicate, a nonempty annex, original statement bytes and an expired
leaf verified at witnessed signing time. They cover literal SAN/issuer/OID policy,
historical identity consolidation, ambiguous identities and offline verification
under independent test-only trust. Both DSSE `0.0.1` with a signed promise and
`0.0.2` with a real RFC3161 token and separate TSA chain succeed through the
product API. Missing, mismatched and invalid signing witnesses refuse. Retained research and upstream fixtures cover
library mechanisms and product rejection of the research predicate separately.
These tests do not establish authentication by a maintained production publisher;
the real production proof remains pending. See [publisher activation](production-publisher.md).
