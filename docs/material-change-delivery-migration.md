# Material handoff delivery migration

Inspected donor: `samartomar/aih-scan` at
`6da220f71d615145916ca9a7094fbc7db3b2f6d8`.
Focused searches of `src`, `tools`, `.github` and `tests` found no issue
create/update adapter or `aihq-scan-change` marker implementation. Existing
publication code produces evidence artifacts rather than issue delivery. A new
bounded module is required for the explicit GitHub operation.

| Inspected mechanism/assertion | Decision | Delivery location/evidence |
| --- | --- | --- |
| `src/assessment/json.ts`: `canonicalBytes`, strict JSON, bounded safe `ContractError` | Retain shared canonical validation and error conventions; identity/summary validation is owned by the material contract module | `src/material-change/delivery.ts` calls validated summary/identity helpers; public host tests use independent literal identity vectors |
| `src/assessment/prior-artifacts.ts`: `readHttpsSnapshot` checks content length, cumulative chunks, cancellation, `redirect: "error"`, explicit input | Adapt the bounded HTTP mechanics to a fixed GitHub API origin and explicit bearer credential; no file acquisition or producer-trust logic | `src/material-change/github.ts`; mocked-fetch public host regressions |
| `src/baseline/publication-v1.ts`: `createBaselineVetPublicationV1`, canonical publication parser and result | Preserve independent immutable publication; delivery does not rewrite or invalidate its artifacts | Public delivery tests verify input immutability and retained retry summary |
| `tests/baseline/publication-reuse.test.ts`: explicit runner and release-custody fixture assertions | Preserve existing route and assertions in place; do not import release downloading/replay into issue lookup | Existing suite remains owned by publication; focused delivery tests use injected GitHub transport |
| Legacy baseline TTL/replay/qualification/complete-success coupling | Drop from the new delivery route; those concepts do not determine material identity, issue disposition or publication success | New delivery module has no baseline, qualification or artifact-mutation dependencies |

Actual focused checks: `npm test -- tests/material-change/delivery.test.ts
tests/material-change/github.test.ts` passed 30 tests; `npm run typecheck`,
`npm run lint` and `git diff --check` passed. Lint reports existing and new
non-null-assertion warnings without errors. The red-to-green behavioral slices
covered explicit refusal, new paginated/PR-filtered creation, open update,
closed disposition, duplicate ambiguity, malformed sections, lookup bounds,
default HTTP delivery, invalid configuration, timeout, display safety and
retained prior links. Subsequent regression tests cover uncertain create/retry,
input snapshots, malformed success and HTTP refusal/response limits.

A later improvement slice added public regressions first. A focused run of the
same two files then showed 12 expected failures and 38 passes. The failures
covered ascending lookup order, non-NFC and ordinary numeric third-party data,
duplicate-key classification, five HTTP status classes, long non-ASCII issue
bodies, canonical-case issue URLs and stopping mutations after the first failure.
Guards for exact issue routes, oversized bodies and a failed later page already
passed. The corresponding `github.ts` and `delivery.ts` changes preserve the
request, invocation, response, aggregate and page bounds; the per-issue body
bound is now 256 KiB UTF-8. The host then ran `npm test -- tests/material-change`:
all 70 tests passed, including the 50 delivery/HTTP tests and 20 comparison,
validation and identity tests. Targeted formatting completed without errors.

A packed disposable consumer checks the installed `@aihq/scan/host` API; no test posts
real data or creates a live issue. This is development evidence under Unreleased,
not a package publication or production-signing claim.
