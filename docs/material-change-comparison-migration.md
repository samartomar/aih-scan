# Material comparison migration evidence

This software change implements the comparison and contract portion of
[samartomar/aih-scan#88](https://github.com/samartomar/aih-scan/issues/88).
Source and relevant assertions were inspected at fixed donor commit
`6da220f71d615145916ca9a7094fbc7db3b2f6d8`.

| Inspected source/assertions | Disposition | Current boundary and regression |
| --- | --- | --- |
| `src/assessment/json.ts`: `canonicalBytes`, `sha256`, `strictParse`, safe `ContractError` and `errorDiagnostic`; `strict-json.ts`: canonical key ordering, Unicode/NFC and strict own data semantics | Reuse the accepted canonicalizer and hash. Add bounded descriptor admission before canonicalization, then parse an independent canonical snapshot. Do not create another identity algorithm. | `src/material-change/{compare,validation,identity}.ts`; public comparison tests cover path/key ordering and content changes; validation tests cover getters, hidden/symbol/extra fields, Unicode, unsafe numbers, duplicates and resource limits. |
| `src/assessment/shapes.ts`: digest, Scan ID, path, diagnostic and repository admission; `tests/assessment/read.test.ts`: unknown-field/unsafe-number refusal | Reuse shapes and strict refusal vocabulary. Restrict source identity to canonical credential-free repository spelling or an explicit stable local label. | `tests/material-change/validation.test.ts` exercises the public host boundary and advertised schema identity; unsupported projection is refused. |
| `src/baseline/batch-v1.ts`: component IDs, published paths and exact content bindings; request source binds a pinned commit and whole-source tree | Adapt the binding concept, not the historical request or runtime. The new owner declaration uses sorted published path digests plus explicit installation metadata. Whole-source commit/tree, counts and analyzer results do not determine item identity. | `compare.test.ts` covers equal counts with changed bytes, metadata changes, metadata-only/path ordering, initial additions, complete removals, partial inventory and unchanged material across Scan IDs. |
| No material comparison or issue identity implementation in the donor's assessment/public surface; research found no suitable finished matching adapter | Implement the narrow accepted projection and domain-separated change/item identities. No legacy baseline, TTL, replay, qualification, signing or delivery dependency is introduced into comparison. | `identity.test.ts` checks a fixed known-answer change digest through the public delivery seam and its independence from Scan IDs/diagnostics; delivery tests separately verify item-marker vectors. |
| Existing public contract exports and packed consumer | Extend the same exports and single packed/install proof. Keep portable contracts free of host imports and retain unrelated package assertions. | `tests/support/packed-assessment-consumer.mjs` exercises comparison and separate delivery on installed exports; `tests/package-install-v2.test.ts` checks installed portable material declarations without Node types and host declarations with Node types. |

The focused tests use explicit disposable data. They do not scan the source
checkout or perform real GitHub posting. [Delivery migration evidence](material-change-delivery-migration.md)
owns the adapter disposition. Final command results are recorded with the reviewed
delivery; source integration remains Unreleased software, not npm publication or
authenticated report publication.
