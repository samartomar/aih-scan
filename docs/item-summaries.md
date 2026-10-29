# Item summaries, record choice and evidence policy

`pickRecord` and `summariseItem` from `@aihq/scan/read` read an item's stored
[item records](item-records.md), from Catalog `scan[]` or from supplements.
Each record is passed with the artifact it names and the host's authentication
of that artifact. Every reader applies the decision table below unchanged.

```ts
const result = await summariseItem({
  records: [{ record, artifact, authentication }], // artifact: readArtifact/readReport result
  item,                 // the item descriptor, as for recordItems
  policy,               // urn:aihq:scan:evidence-policy:1.0.0
  severityProfiles,     // the profile documents records may name; the policy's must be one
  trustStatus: "available",
  evaluationTime: "2026-10-30T00:00:00.000Z",
});
if (result.status === "summarised") {
  const { summary, picked, diagnostics } = result;
  // summary is the closed urn:aihq:scan:item-summary:1.0.0 document.
  // picked is { index, scanId, why } or null; diagnostics say why each other record did not count.
}
```

`authentication` is the `AssociationResult` from `authenticateArtifact`, or
`{ status: "revoked" }`:

| `status` | Summary reason |
| --- | --- |
| `authenticated` | none |
| `skipped` | `unchecked` |
| `unverifiable` | `not-authenticated` |
| `revoked` | `revoked` |

A supplied authentication `scanId` must name the record's artifact.

`trustStatus` is the host's trust-metadata state. `unavailable` and `expired`
give `offline`. `revoked` withholds `verified` from authentic historical bytes,
but does not change their authentication.

Malformed inputs return `{ status: "invalid", diagnostics }`. If the policy's
severity profile is not among the supplied profiles, the result is
`severity-profile-mismatch`.

## Summary

```ts
{
  state: "verified" | "not-verified" | "partial" | "not-covered" | "not-scanned" | "unreadable",
  why?: "not-authenticated" | "unchecked" | "offline" | "revoked" | "detector-missing"
      | "profile-not-allowed" | "future-dated" | "older-than-policy",
  findings: { error, warning, note, unavailable },
  suppressed: number,
  scannedAt: string | null
}
```

`why` appears only for `not-verified`. `findings` and `suppressed` are the picked
record's counts, summed over its detectors. Rows 1 to 3 have zero counts and a
null `scannedAt`. No output uses "safe", "clean", "passed" or "approved";
`verified` is the only positive state.

## Decision table

The first row that applies wins.

| # | Situation | `state` | `why` |
|---|---|---|---|
| 1 | No record for the item | `not-scanned` | — |
| 2 | Records exist but none can be read | `unreadable` | — |
| 3 | No record passes `verifyItemRecord` against the item's own materials | `not-covered` | — |
| 4 | The picked record's coverage is not `matched` | `not-covered` | — |
| 5 | The picked record's `completion` is `partial` | `partial` | — |
| 6 | A required detector is absent, did not succeed, or did not cover the item | `not-verified` | `detector-missing` |
| 7 | The record's severity profile is not the policy's | `not-verified` | `profile-not-allowed` |
| 8 | Authentication or trust is `revoked` | `not-verified` | `revoked` |
| 9 | Trust metadata is unavailable or expired | `not-verified` | `offline` |
| 10 | Authentication was skipped or refused | `not-verified` | `unchecked` / `not-authenticated` |
| 11 | `scannedAt` is later than `evaluationTime` | `not-verified` | `future-dated` |
| 12 | Older than the policy's `maxAge` | `not-verified` | `older-than-policy` |
| 13 | None of the above | `verified` | — |

A record cannot be read (row 2) when any of these holds:

- its schema or a field is refused (`SCHEMA_UNSUPPORTED`, `unknown-field`,
  `invalid-record`);
- its artifact is not a `read` result, or is not the one the record names
  (`artifact-mismatch`);
- its severity profile was not supplied (`severity-profile-unavailable`).

Other records that do not pass `verifyItemRecord` are `record-not-covering` or
`record-differs`. Each of these diagnostics carries the record's `index`.

## Picking one record

`pickRecord({ records, item, policy, severityProfiles })` ranks only records
that pass `verifyItemRecord`. Earlier keys decide first:

1. matched coverage;
2. authentication: authenticated, then skipped or refused, then revoked;
3. every required detector succeeded and covered the item;
4. the policy's severity profile;
5. complete before partial;
6. the newest `createdAt`;
7. the Scan ID, as a final tie-break.

The result is the record's `index` and `why`: the key that separated it from the
runner-up, or `only-record`. Time decides only after every other key.

## Evidence policy and severity profile

```ts
{ schema: "urn:aihq:scan:evidence-policy:1.0.0", id, version,
  requiredDetectors: string[],            // at least one, unique
  severityProfile: { id, sha256 },        // SHA-256 of the profile's canonical JSON
  maxAge?: "P30D" }                       // ISO 8601 duration
{ schema: "urn:aihq:scan:severity-profile:1.0.0", id, version,
  rules: { detectorId | "*", level, maps: "error" | "warning" | "note" | "unavailable" }[],
  suppressions: { detectorId, nativeRuleId, path?, reason }[] }
```

A record names the profile it was recorded with as `<id>@sha256:<digest>`. The
profile's suppressions are applied when the record is derived and are recorded
with their reasons. In `maxAge`, calendar components use UTC and clamp to the
end of a month; weeks and smaller units are elapsed time.

Fixtures for the summary, policy and profile are exported beside their schemas
under `@aihq/scan/schemas/`. The summary fixtures cover every row and the ranking
variants. Each expected value is written from this table, not produced by
`summariseItem`.
