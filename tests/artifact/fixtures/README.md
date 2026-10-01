# Test-only certificate fixtures

`keyless-research-bundle.json` is the public synthetic bundle from
[Scan run 36797464166](https://github.com/samartomar/aih-scan/actions/runs/36797464166),
commit `847f381b3e25c3fb559290643c95888021795a1e`. Its predicate is
`urn:aihq:research:keyless-smoke:1.0.0`; the product rejects it. Its exact smoke
workflow/ref is test identity only. `public-sigstore-root.json` is the separately
acquired public Sigstore root from that reviewed offline mechanism proof. It is
test data and does not select a maintained product publisher.

`upstream-dsse-002.json` and `upstream-test-root.json` preserve Sigstore JS's
`V3.DSSE.WITH_SIGNING_CERT.TLOG_DSSEV002` and its test root at commit
`769a53d8713248a8bf49edfc2a5d1955b0dcc24d`. Copyright 2023 The Sigstore Authors;
Apache License 2.0, see the repository LICENSE. These test fixtures prove the
pinned verifier's historical DSSE 0.0.2/RFC3161 mechanism only. They do not prove
a production Scan statement or production trust policy.

`../synthetic-keyless.ts` creates a separate local fixture universe on each call:
four ephemeral Node P-256 keypairs, a self-signed test CA, an expired leaf with a
signed SCT, and a one-leaf Rekor proof/checkpoint plus inclusion promise. Its small
DER/TLS encoder constructs test inputs; it never verifies certificates. The full
product API verifies those inputs with the pinned upstream library, including a
Scan statement with a nonempty annex and indented original payload bytes. All
identities, roots and log URLs are explicitly test-only. No fixture private key
is retained, exported or accepted as maintained publisher trust.

No test makes a signing service request. Authentication of a real production
publisher's production-format nonempty-annex artifact remains a separate gate.
