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

No private key is retained. No test makes a signing service request. A positive
production-format nonempty-annex artifact remains a separate activation gate.
