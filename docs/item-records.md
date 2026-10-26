# Item records

`recordItem(assessment, item)`, `recordItemBatch({ assessment, items })` and
`verifyItemRecord(record, assessment, item)` are portable exports of
`@aihq/scan/read`. `assessment` is a result of `readReport` or `readArtifact`;
Scan revalidates it, including its Scan ID, before deriving coverage. These
operations perform no host access or authentication and take no policy.

An item descriptor contains exactly:

```ts
{
  frameworkId: string, itemId: string,
  contentSha256: string, behaviourSha256: string,
  materials: {
    path: string, sha256: string, byteLength: number,
    executable: true | false | "unknown", role: "content" | "behaviour"
  }[]
}
```

Paths are exact paths in the assessment's capture namespace. Materials must have
unique paths and exactly one `behaviour` file. The Catalog checked reader owns
this mapping and the two subject hashes; Scan neither computes those labels nor
interprets behaviour bytes. Recipe-only capture cannot cover a separate MCP
server definition or hook command declaration. Tool identifiers, installation
locations and support claims are outside this interface.

```js
import { readReport, recordItem, verifyItemRecord } from "@aihq/scan/read";
const assessment = await readReport(reportBytes);
const record = await recordItem(assessment, item);
if (record.coverage === "matched") {
  const comparison = await verifyItemRecord(record, assessment, item); // "same"
}
```

A derived record uses `urn:aihq:scan:item-record:1.0.0` and contains `scanId`,
`createdAt`, `subject`, `materials`, `coverage`, `detectors`, `completion`,
`evidenceKey` and `authenticity: "unchecked"`. The subject is the descriptor's
four identity labels. Each material retains its descriptor and adds `captured`,
`digestMatch`, `lengthMatch` and `executableComparison`.

| Declared executable | Captured executable | Comparison |
| --- | --- | --- |
| `true` or `false` | Same value | `equal` |
| `true` or `false` | Other boolean | `differs` |
| Any value | `unknown` | `unknown` |
| `unknown` | Any value | `unknown` |

Missing files, differing digests, lengths or executable booleans give item
`coverage: "mismatched"`. Unknown executable state permits `matched` and stays
visible per material; legacy profile-1 capture always compares as unknown.
Malformed descriptors produce `{ coverage: "invalid", diagnostics }`, including
empty materials. Unreadable or unsupported assessments produce
`{ coverage: "unavailable", diagnostics }`. These refusals are not item records.

Every requested detector appears with `detectorId`, `outcome`,
`requestedProfileId`, `effectiveProfileId` (null without observation inputs),
`itemCoverage`, `findings` and `inputSha256s`. Qualifying successful observations
must cover matching material bytes and modes. Their union may cover the item
across independent observation units. Coverage of all, some or no materials is
`covered`, `partial` or `uncovered`. The behaviour file counts equally.
`inputSha256s` are sorted SHA-256 digests of the canonical JSON observation inputs
of observations covering at least one matching item material. This includes scope,
entries and executable states where the observation format carries them.

Findings are attributed only when both their location path and file digest match
an item material. Original severity, native rule, occurrence fingerprint,
multiplicity, supporting evidence and location units are retained. Other-path and
locationless findings remain in the report; derivation never changes the report.

## Evidence key and stored records

`evidenceKey` is SHA-256 over canonical JSON of exactly:

```ts
{
  subject,
  materials: [{ path, sha256, byteLength, executable }],
  detectors: [{
    detectorId, detectorVersion, adapterSha256, rulesSha256,
    configurationSha256, profileId, profileSha256, platform,
    inputSha256s: sortedInputDigests
  }]
}
```

Detectors are sorted by `detectorId`; materials keep descriptor order. Detector
identity fields come from observation inputs, with unavailable values `null`.
The key is only a display and grouping key. It is never a reuse criterion or a
claim about findings: changes to findings, report time or Scan ID must still be
checked through the full record. No evidence key authenticates an assessment.

`verifyItemRecord` re-derives the record and compares every field. A missing or
byte/length-mismatched capture, or a different subject, returns `not-covered`.
Any other mismatch, including an executable-only change, returns `differs`.
An exactly equal record returns `same`. A stored record is only a cache.

Batch rows equal singleton results in input order. Invalid descriptors retain
an invalid row; an invalid batch shape or exceeded batch bound refuses the whole
call with `{ status: "invalid", diagnostics }`. Successful batches return
`{ status: "complete", results }`. Existing coverage limits apply: 4096 items,
10000 materials per item, 50000 total material references, 16 MiB request bytes,
32 MiB response bytes, 100000 observation associations and 10000000 classification
work units. Inputs and report state are snapshotted before asynchronous work.
To use the unchanged strict assessment selector, project every material to only
`{ path, sha256, byteLength }` when passing its `context.descriptors`.

The JSON Schema describes the public result union: a complete derived record or
an explicit `invalid`/`unavailable` diagnostics refusal. Refusals lack record facts
that cannot truthfully be derived, and never claim a schema-labelled item record.
The schema and golden fixtures are exported at
`@aihq/scan/schemas/item-record/1.0.0.json` and
`@aihq/scan/schemas/item-record/1.0.0.fixtures.json`. See
[fixture provenance and replay](contract-fixtures.md). The contract is declared
in `contractSupport`; its document version does not designate a package release.
