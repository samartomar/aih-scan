# Summary and latest matching evidence (Unreleased)

`readSummary` and `selectAssessments` are implemented additions to
`@aihq/scan/read`. They use the existing report/artifact readers and preserve the
original Scan ID. A summary is a derived view, not another signed document.
These additions are not in the previously published package merely because they
are present in source. Use an exact tested archive until a release contains them.

```js
import { readSummary, selectAssessments } from "@aihq/scan/read";

const compact = await readSummary({
  format: "artifact", bytes: artifactBytes,
  detectorIds: ["detector.aih-native", "organization.disallow-eval"],
});

const view = await selectAssessments({
  assessments: [
    { sourceId: "release-producer", location: baselineLocation,
      format: "artifact", bytes: baselineBytes, expectedScanId: baselineScanId,
      authentication: baselineAuthentication },
    { sourceId: "other-producer", location: newerLocation,
      format: "artifact", bytes: newerBytes },
  ],
  context: {
    sourceIds: ["release-producer", "other-producer"],
    descriptors: exactFiles, // [{ path, sha256, byteLength }], nonempty
    selection: { paths: requestedPaths, excludedPaths: requestedExclusions },
    // Optional exact Git constraint, in addition to matching the file bytes:
    // git: { repository: "https://example.org/project", commit: fullCommit },
    // Optional separate view: require these requested detector/profile identities:
    // providers: [{ detectorId: "organization.disallow-eval", profileId: "host-process-uv-v1" }],
  },
  evaluationTime: "2026-10-19T00:00:00.000Z",
  checks: [
    { sourceId: "release-producer", status: "succeeded",
      attemptedAt: "2026-10-19T00:00:00.000Z",
      lastSuccessfulAt: "2026-10-19T00:00:00.000Z", diagnostics: [] },
    { sourceId: "other-producer", status: "offline",
      attemptedAt: "2026-10-19T00:00:00.000Z",
      lastSuccessfulAt: "2026-10-18T00:00:00.000Z",
      diagnostics: [{ code: "offline", detail: "Host acquisition unavailable" }] },
  ],
});
if (view.status === "selected") {
  const selected = view.assessments.find(entry => entry.summary.scanId === view.selectedScanId);
  // view.freshness === "last-known": one source was offline.
  // Earlier and ineligible assessments remain in view.assessments.
}
```

The host supplies original bounded bytes, configured source identities, check
facts and authentication results. Acquisition, authentication and trust remain
host responsibilities. The selector does not verify a supplied authentication
result or obtain bytes from a location. Each acquisition keeps its own result;
an omitted result is `skipped/not-requested`. Report producer identifies Scan
software, not the signing person or organization. All summaries remain
`authenticity: "unchecked"`, including signed artifacts. A later readable unsigned
report can be the default view while release-baseline authentication remains a
separate release requirement.

Use the same source-relative capture namespace for `exactFiles` and requested
paths. There is no path-prefix inference. A Catalog inventory descriptor can be
used directly when it names that capture namespace. Capture matching uses
`readContentCoverage`: path, SHA-256 and length must match, even if no observation
covers the files. Names, labels, versions and URLs do not establish a byte match.
An explicit Git constraint additionally requires exact repository and commit.

Requested paths and exclusions are sorted and made unique in the context, then
compared with the report's checked selection. Broader/narrower requests and
different exclusions form different groups. Achieved coverage, observation
`scopeKind`, detector versions, configuration and rules never silently change
the requested group. A caller can explicitly require requested providers/profiles
with `context.providers`; findings still describe the whole report, not a
new provider-combined assessment.

Eligible reports order by `createdAt` descending and full Scan ID ascending by
ASCII code units. Source/arrival order and authentication do not affect that
order. Ties make no trust claim. Timestamps must be real UTC calendar timestamps
with milliseconds. Missing or invalid report dates are read failures; dates after
`evaluationTime` stay inspectable as `future-dated` until a later explicit
evaluation. The operations use no current clock or tolerance. Newer partial,
failed or all-provider-failed assessments can displace complete older ones.

`ScanSummary` retains source/capture identity, requested selection, producer,
completion, provider outcomes, requests/configuration, coverage, diagnostics,
observation identity/input provenance/origin/dates/gaps, and annex descriptors.
Detailed findings resolve through the original Scan ID, provider and observation
ID in the retained report; annex IDs retain their original detail references.
The compact view omits repeated capture/input entry arrays and finding bodies.
It never claims all report findings are located in the selected content.
`findings.records` counts records; `findings.occurrences` is the exact decimal
sum of multiplicity (a string so large sums remain exact). `bySeverity` preserves
each reported severity field, including vendor values and unavailable reasons.
There is no cross-provider deduplication or aggregate safety pass.

`detectorIds` optionally names known providers to show as `not-requested` when
absent. Requested providers always retain their actual outcome/reason. This list
is caller supplied; portable reading imports no execution registry and makes no
permanent assumption about the number of providers. Supplied detector definitions
use the same summary without a consumer adapter.

Identical checked report IDs deduplicate, retaining every acquisition's location,
format, annex availability and authentication. Distinct valid envelopes/signatures
do not conflict. An expected-ID mismatch refuses only that source; it cannot
poison another report that actually recomputes to the claimed ID. Differing checked
canonical report bytes that actually resolve to the same Scan ID (a digest
collision) are reported in `conflicts`, and that identity is excluded from default
selection. Invalid or unsupported documents also cannot poison checked identities.
Preserve the
original supplied bytes at their host-owned acquisition locations for diagnosis;
the API does not return duplicate byte buffers. A summary reports checked annex
availability if any acquisition supplied checked annexes; per-acquisition facts
remain distinct. Artifacts check every supplied annex before selection.

Failures are diagnostics, not new assessments. Supply previously acquired bytes
again alongside new evidence to retain last-known history. `checks` contains at
most one latest attempt per configured source. Successful checks require
`lastSuccessfulAt === attemptedAt`; failure/offline checks may retain an earlier
successful time. Attempt times cannot exceed evaluation time. Missing checks,
failed/offline checks, read failures or identity conflicts produce `last-known`.
`checked` means only that the supplied configured-source checks succeeded without
these gaps; it is never a claim of globally latest evidence.

For historical viewing, retain an explicit Scan ID and select its history entry
until the person chooses latest. This API has no policy, judgment or prepared
action inputs. Keep those exact saved bindings pinned; advancing the default
view is not an edit or approval. If an older artifact is unavailable, the host
retains its identity and displays unavailable history.

Inputs use closed own-data objects in the reader's realm. Bytes and metadata are
snapshotted before asynchronous work. Batch ceilings are `maxAssessments` (32
supplied documents, including duplicate acquisitions), `maxContentDescriptors`
(10,000) and `maxAssessmentBytes` (128 MiB aggregate original bytes). Over-limit
input returns `invalid` rather than selecting a truncated set. Existing per-report
and artifact limits still apply. `readSummary` uses the same document limits.
Malformed context returns `invalid`; per-source read failures remain in
`failures`. There is no filesystem, fetch, process, implicit clock or scanner
execution in these operations.

The packed consumer replays finite fixtures against public exports outside source
workspaces, including all current built-in identities and one supported supplied
definition, and loads/calls the entry graph in a realm without Node globals,
network or process access. Fixture findings and signing keys are synthetic; this
does not establish native provider execution, production authentication or
browser application adoption. Its receipt records fixture report/summary byte
counts and elapsed read/selection time; these are measured fixtures, not a
general latency guarantee.
