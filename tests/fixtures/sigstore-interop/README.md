# Test-only Sigstore interoperability fixtures

These files let `tests/read-v1/sigstore-interop.test.ts` check the portable verifier's
mechanisms (certificate chain, SCT, Rekor inclusion proof and checkpoint, RFC 3161
timestamp) against evidence produced by real Sigstore services and by sigstore-js. They
are DSSE bundles, so the `aih-sigstore-keyless/1` profile itself refuses them; the test
reaches the mechanism checks through internal modules.

- `keyless-research-bundle.json` is a public synthetic bundle from
  [Scan run 36797464166](https://github.com/samartomar/aih-scan/actions/runs/36797464166),
  commit `847f381b3e25c3fb559290643c95888021795a1e`, issued by the production Fulcio and
  logged in the production Rekor v1. `public-sigstore-root.json` is the public Sigstore
  trusted root acquired for that proof. Neither selects a trusted publisher.
- `upstream-dsse-002.json` and `upstream-test-root.json` preserve Sigstore JS's
  `V3.DSSE.WITH_SIGNING_CERT.TLOG_DSSEV002` vector and its test root at commit
  `769a53d8713248a8bf49edfc2a5d1955b0dcc24d` (Rekor v2 Ed25519 checkpoint and a
  timestamp.sigstore.dev RFC 3161 token). Copyright 2023 The Sigstore Authors; Apache
  License 2.0.

No test makes a signing service request.
