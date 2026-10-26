# Item summaries and consumer evidence policy

`summariseItem` from `@aihq/scan/read` presents one item state using the table
below. It delegates ranking to `selectAssessments`: the newest readable matching
assessment wins, including a newer partial assessment. Earlier evidence,
acquisitions, authentication, gaps, checks and failures remain in `selection`.

```ts
const result = await summariseItem({
  assessmentsInput: {
    assessments, // existing EvidenceCandidate[]: exact report/artifact bytes
    context: { sourceIds, selection }, // optional git and providers filters
    checks,
  },
  item, // the exact ItemDescriptor, including its behaviour material
  evidencePolicy,
  severityProfile,
  authentication, // host result for the selected assessment
  trustStatus: "available",
  evaluationTime: "2026-10-26T00:00:00.000Z",
});
if (result.status === "summarised") {
  const { summary, selection } = result;
  // summary is the closed urn:aihq:scan:item-summary:1.0.0 document.
  // selection is the full, unchanged selector result, or null with no sources.
}
```

`assessmentsInput` uses the existing selector's `assessments`, `checks` and optional
`detectorIds`. Its `context` omits `descriptors`, which Scan projects from the
item's materials to `{ path, sha256, byteLength }`. `evaluationTime` is supplied
once, at the top level. Source, scope and provider filters retain their existing
selector meaning. Policy detector requirements do not filter out newer evidence.
Malformed inputs return `{ status: "invalid", diagnostics }`; selector invalid
results propagate. No configured sources gives row 1 without calling selection.

The host supplies the selected assessment's `AssociationResult` from
`authenticateArtifact`, or `{ status: "revoked" }`. The existing statuses are
`authenticated`, `skipped` and `unverifiable`; the last two become `unchecked` and
`not-authenticated`. A supplied authentication `scanId` must name the selected
assessment. Scan does not authenticate inside this operation.

`trustStatus` is `available | unavailable | expired | revoked`. It describes the
host's selected current trust data. Both unavailable and expired data give
`offline`. Revocation can be reported separately from an `authenticated` historical
result: it changes the summary without changing or deleting authentic bytes. Trust
acquisition and any TUF client remain host responsibilities.

## Decision table

The first applicable row wins. Rows 2–7 apply only without a selected Scan ID;
rows 8–17 apply to the selected assessment's re-derived and verified item record.

| Row | Situation | state | why |
| --- | --- | --- | --- |
| 1 | No configured evidence source | `not-scanned` | `no-sources` |
| 2 | No assessment and no acquisition/read failure | `not-scanned` | `not-found` |
| 3 | No readable assessment and an acquisition/read failure | `unreadable` | omitted |
| 4 | Every readable assessment is excluded only as future-dated | `not-verified` | `future-dated` |
| 5 | No readable assessment captures the item's materials | `not-covered` | `content-mismatch` |
| 6 | Capturing assessments are excluded by scope, Git source, provider or identity conflict | `not-covered` | `scope-mismatch`, `source-mismatch`, `provider-mismatch`, `identity-conflict`, in that eligibility order |
| 7 | Any remaining case without selection | `not-scanned` | `not-found` |
| 8 | Record verification fails or item coverage is not matched | `not-covered` | `content-mismatch` |
| 9 | Report completion is partial | `partial` | omitted |
| 10 | A checked detector was not requested, did not succeed, has no effective profile, or did not cover the item | `not-verified` | `detector-missing`, then `detector-not-covering` |
| 11 | A declared executable material has unknown captured state | `not-verified` | `executable-unknown` |
| 12 | A checked detector's effective profile is outside its nonempty allowlist | `not-verified` | `profile-not-allowed` |
| 13 | Host authentication or current trust is revoked | `not-verified` | `revoked` |
| 14 | Selected trust data is unavailable or expired | `not-verified` | `offline` |
| 15 | Host authentication was skipped or failed | `not-verified` | `unchecked` or `not-authenticated` |
| 16 | A configured maxAge is exceeded at evaluationTime | `not-verified` | `older-than-policy` |
| 17 | None of the above | `verified` | omitted |

Row 2's absence of failure is established before row 3. Failed/offline source
checks count as acquisition failures when no readable assessment exists. Missing
or invalid report `createdAt` is a read failure. The selector's freshness is
preserved exactly (`checked` or `last-known`); it is `null` only for no sources.
`scanId` and `scannedAt` identify the selected report, or are `null` without one.
Verified describes the evidence under the consumer's rules; findings remain visible.

## Policy, severity and suppression

The closed `urn:aihq:scan:evidence-policy:1.0.0` document contains:

```ts
{ schema, id, version,
  requiredDetectors: { detectorId, allowedProfileIds: string[] }[],
  severityProfile: { id, sha256 },
  suppressions: { detectorId, nativeRuleId, path?: string, reason: string }[],
  maxAge?: string }
```

Required detector IDs are unique. When the list is empty, every requested detector
is checked. Empty profile allowlists allow any effective profile; nonempty lists
are enforced. An absent observation input never supplies an effective profile.
Signer identities stay in the host's selected keys and publishers.

The closed `urn:aihq:scan:severity-profile:1.0.0` is:

```ts
{ schema, id, version,
  rules: { detectorId: string | "*", level: string,
           maps: "error" | "warning" | "note" | "unavailable" }[] }
```

The first detector/level match wins, including a wildcard before a more specific
rule. An unmatched or unavailable level counts as `unavailable`. The profile ID
and SHA-256 of its canonical JSON bytes must match the policy; otherwise the
result is invalid with `severity-profile-mismatch`. Canonical JSON sorts object
keys recursively, retains array order and has no whitespace, matching the report
contract's canonical JSON rules.

Counts use occurrence multiplicity, not the number of finding records. Only
findings attributed by the item record to the item's exact paths and digests
contribute. Suppressions match detector, native rule and optional exact path.
The first matching suppression supplies the reason. Occurrences move from the
severity counts into `suppressed.count` and grouped `{ detectorId, nativeRuleId,
reason, count }` reasons. Original records, severities, evidence and policy remain
unchanged. Counts outside JavaScript's safe integer range are refused rather than
rounded; classification work is bounded.

An absent `maxAge` never gates age. Supported ISO 8601 duration components are
integer years, months, weeks, days, hours and minutes, and seconds with an optional
decimal fraction, for example `P30D`, `PT1H` or `P1M`. Calendar components use UTC
and clamp end-of-month days; weeks and smaller components use elapsed time. An
assessment exactly at the age boundary is within the policy. Negative, malformed
or unrepresentable durations are invalid. Evaluation time never comes from a
clock inside the summary.

## Schemas and fixtures

The three contracts publish schemas at `@aihq/scan/schemas/<name>/1.0.0.json` and
golden fixtures at the adjacent `1.0.0.fixtures.json` exports. Package support
retains its closed 1.0.0 declaration. Each decision-table fixture carries its row,
input and independently specified expected summary; candidate `document` values
are canonically encoded into `bytes` before calling the public API. These are
controlled specimens over real item-record fixture data, with no native execution
or production authentication claim. The installed consumer replays the same
matrix in a realm without Node globals or built-ins.
