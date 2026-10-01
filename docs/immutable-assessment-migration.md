# Immutable assessment migration evidence

This change implements the software portion of
[samartomar/aih-scan#83](https://github.com/samartomar/aih-scan/issues/83).
The donor source and tests were inspected at
`efd4c4df59c5afd125b256d0a9ff7d5c5da0c9ab`. The new public path owns its report,
artifact and authentication contracts; the historical V2 entry remains separate.

| Inspected donor and assertions | Disposition | New boundary and regression evidence |
| --- | --- | --- |
| `src/contract/strict-json-v1.ts`: strict parser, UTF-8/NFC, duplicate keys, canonical ordering; `tests/contracts/strict-json-v1.test.ts` | Extract the portable parser without changing legacy finite-number semantics; retain its Node Buffer/hash wrapper. Add the assessment profile's nonnegative safe integers and depth bound. | `src/assessment/{strict-json,json}.ts`; retained 17 parser cases plus `tests/assessment/{read,bounds}.test.ts`, including the 16 MiB annex boundary. |
| `src/observation/source-observation-seal-v1.ts`: stable descriptor reads, before/after file/directory/link identity, containment; `source-entry-name-v1.ts`: bounded representable names | Adapt capture to hash exactly the copied bytes, omit root `.git`, preserve contained link identity and privately snapshot detector input. Require a nonempty selection for a nonempty file set. | `src/assessment/capture.ts`; `run.test.ts` covers omitted Git metadata, empty input, selection and byte limits, links and snapshot mutation without a Scan ID. Existing seal/name regressions remain. |
| `src/cli/process-runner.ts`: bounded process trees and Windows supervisor; `src/runner/run-detector-v1.ts`: prerequisite, option, platform and execution checks | Reuse the runner for detectors and Git. Materialize pinned Git objects without checkout, source hooks, filters or EOL conversion. Hash the commit and blob bytes against their Git identities. | `src/assessment/{capture,git-command,run}.ts`; `git.test.ts` uses disposable real Git objects and the external process boundary, verifies known blob bytes and rejects checkout-based acquisition. Existing containment tests remain. |
| `src/baseline/runtime-v1.ts`: exact shipped Semgrep rules; `src/findings/scan-findings-v1.ts`: findings, unavailable fields and gaps | Export and hash the existing rule text. Adapt reliable findings into immutable observation bodies and bind support to annexes and captured files. Account for every requested detector. | `run.test.ts` retains a successful native sibling beside external failure/cancellation and refuses unsupported profiles. Native output has a nonempty annex. The report validator checks coverage partitions, findings and observation digests. |
| Vendor profiles whose donor cannot identify exact rule bytes | Refuse those profiles on this new path with `rules-material-unavailable`; do not invent an empty rule digest. | [Assessment support limits](assessment-api.md) document the currently supported profiles. Historical runner behavior is unchanged. |
| `src/observation/scan-attestation-v2.ts`: SPKI fingerprint, DSSE PAE, own-data validation, complete annex set; adversarial signature/key/annex tests | Adapt the byte bindings and independent key selection to a Sigstore v0.3 DSSE bundle. Use the maintained verifier for certificate/log cryptography and Ed25519 verification. | `src/artifact/`; `artifact.test.ts` covers prepare/attach/sign/authenticate, PAE, changed/missing/extra annexes, malformed JSON/base64, independent key selection and original payload bytes. Attachment deliberately makes no authenticity claim. |
| `src/baseline/attestation-v1.ts` and `src/observation/scan-bundle-v2.ts`: detached preparation, verification, stable bounded file reads and owned outputs | Retain separate preparation, signing and verification. Operator tools accept bounded data and write an authenticated output only after independent verification. | `tools/artifact/`; `publisher.test.ts` exercises detached digest checking, independent trust refusal and exclusive output creation in temporary fixtures. |
| Legacy Core locks, full-success projection, same-execution annex custody, expiry and replay rejection | Remove these requirements from the new path. Retain historical APIs and their tests. Default CI verifies Scan without a Core checkout. | Portable readers accept unsigned and partial reports; narrow authentication can accept unsupported detailed report bytes. Packed consumer checks require no Core package and keep reading separate from authentication. |
| Observation reuse and material-change delivery | Leave outside this change. Supplied prior artifacts produce an explained reuse miss and fresh work. | Public `runScan` regression checks the miss; the new API performs no posting or publication. |

The installed-package test uses one packed tarball to exercise the public
contracts/read/host exports, schemas, static valid/invalid examples, a partial
assessment with nonempty annex bytes, and local independent authentication.
It also loads the portable JavaScript graph without Node globals/built-ins and
typechecks the installed declarations with DOM libraries and no Node types.

The certificate fixtures preserve their original public research or upstream
predicates and identities; [fixture provenance](../tests/artifact/fixtures/README.md)
records their source commits. They test historical signing-time and witness
mechanisms, and product refusal of the research predicate. They do not establish
production Scan authentication.

Repository validation runs typecheck, lint, build, tests, coverage and action-pin
verification. The PR records the actual final commands and results. Production
protection, separately authorized signing and a real production-format artifact
verified through the offline consumer remain open requirements; see the
[inactive publisher plan](production-publisher.md).
