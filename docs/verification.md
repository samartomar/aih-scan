# Signing and verifying scan summaries

A summary is signed once over its exact bytes; it pins every SARIF file by SHA-256, so the
signature covers the findings too. Anyone can sign with their own identity. Verification is
offline and separate from reading, coverage and risk.

## Profile `aih-sigstore-keyless/1`

The only accepted evidence is a Sigstore bundle `application/vnd.dev.sigstore.bundle.v0.3+json`
with an X.509 signing certificate and a `messageSignature` (SHA2_256 digest, ECDSA P-256 key)
over the exact summary or withdrawal bytes. DSSE attestations, bare public keys, certificate
chains inside the bundle and other bundle versions are refused explicitly. `/contracts` exports
the profile as `verification` (encodings, algorithms, rules and the trust snapshot).

A signature verifies only when all of these hold under the selected trust material:

- a fresh SHA-256 of the supplied bytes equals the bundle's digest and the signature verifies;
- the certificate chains to a selected Fulcio CA valid at every authenticated signing time;
- at least one embedded certificate-transparency SCT verifies under a selected CT log;
- every transparency-log entry is a `hashedrekord` (Rekor v1 `0.0.1` or Rekor v2 `0.0.2`) bound
  to the digest, certificate and signature, with a verified inclusion proof and signed checkpoint;
- at least one authenticated signing time (Rekor signed entry timestamp or RFC 3161 timestamp)
  lies within the certificate's validity. An expired certificate is not by itself a refusal.

Certificates and proofs in a bundle are evidence, never trust anchors. Verification makes no
network calls.

## Trust material

The package ships a pinned snapshot of the Sigstore public-good `trusted_root.json`, obtained
through an authenticated TUF update from `https://tuf-repo-cdn.sigstore.dev`. `/contracts`
exports its exact text (`sigstoreTrustedRootText`; the same bytes ship as
`trust/sigstore-trusted-root.json`) and its provenance and SHA-256
(`verification.trustSnapshot`). A snapshot authenticates evidence under that material only; it
does not check revocation or freshness and does not discover withdrawals. Package updates may
carry a newer snapshot. `tools/write-sigstore-trust-snapshot.mjs` embeds an independently
authenticated file.

Pass `trustedRoot` (bytes or a parsed Sigstore trusted root) to replace the snapshot for one
call; `null` selects none.

## `verifySummary`

```js
import { verifySummary, matchScan } from "@aihq/scan/read";
import { defaultSigners } from "@aihq/scan/contracts";

const verified = await verifySummary(summaryBytes, bundle, defaultSigners, {
  trustedRoot,            // optional override
  withdrawn,              // optional aih-scan-withdrawn/1 bytes (or an array)
  withdrawnBundle,        // the bundle for each withdrawal, same order
});
// { status: "ok", verified: true, withdrawn: false,
//   signer: { identity: "aihq-scan-production", trusted: true, issuer, subject },
//   summary, signedAt: [...], withdrawals: [] }
await matchScan(verified, files);
```

`verifySummary` returns a promise (it uses WebCrypto) and never throws. It runs in browsers:
no Node globals or built-ins.

- **Signer trust.** `allowedSigners` is a list of `{ identity, issuer, subject, extensions? }`.
  A signer is trusted only when the OIDC issuer and the exact certificate subject match, plus
  every listed Fulcio extension (dotted OID → exact text). `identity` is your label, reported
  back; it creates no trust. Omit the list to use `defaultSigners`; pass `[]` to trust nobody. A
  valid signature by anyone else returns `verified: true` with `signer.trusted: false` ("signed,
  not by a trusted publisher").
- **Default publishing identity.** `defaultSigners` holds the documented Scan report publisher:
  issuer `https://token.actions.githubusercontent.com`, subject
  `https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main`,
  repository ID `1336836161`, owner ID `9993940`, GitHub-hosted runner, `workflow_dispatch`
  and public visibility.
- **Withdrawals.** A withdrawal counts only when it verifies by the same rules, names the same
  scan key, is signed by the same signer, and the summary's `revision` is at most its
  `throughRevision`. A withdrawn result keeps `verified: true` and has `withdrawn: true` and
  `signer.trusted: false`. Revisions are compared only within one signer; a later revision is
  valid unless a later withdrawal covers it. `withdrawals` reports each one's outcome
  (`applies`, or `not-applicable` with `other-key`, `other-signer` or `later-revision`, or why it
  did not verify).
- **Outcomes.** An unreadable summary returns its `readSummary` problem. No usable trust:
  `refused` / `trust-data-unavailable`. Malformed trust: `invalid` / `trusted-root`. Another
  bundle version: `unsupported-version`. Another evidence form: `refused` /
  `unsupported-profile`. Another algorithm: `refused` / `unsupported-algorithm`. A failed
  signature, chain, SCT, log, proof or time check: `refused` / `invalid-signature`. None of these
  is verified or trusted; `readSummary` still reads the summary.

`matchScan` takes the signer only from a `verifySummary` result; a summary alone gives
`signer: null`.

## CLI

```
aih-scan sign <summary.json | withdrawn.json> [--bundle <new-file>] [--trusted-root <file>]
aih-scan verify <summary.json> --bundle <file> [--signers <file>] [--trusted-root <file>]
                [--withdrawn <file> --withdrawn-bundle <file>]... [--json]
```

`sign` signs with your own identity: an ephemeral P-256 key, a Fulcio certificate for your
OIDC token and a Rekor transparency-log entry (public-good instance by default; `--fulcio-url`
and `--rekor-url` select another). The token comes from `SIGSTORE_ID_TOKEN`, or from GitHub
Actions with `id-token: write`; there is no interactive sign-in. Your certificate identity and
the log entry are public. The bundle (default: the document path with `.sigstore`) is verified
offline before it is written. `verify` exits 0 when the signature verifies (trusted or not)
and 2 otherwise.
