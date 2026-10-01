# Portable assessments

`@aihq/scan/contracts` publishes the installed package identity, exact supported
schema IDs, entry runtimes and JSON-compatible wire types. `@aihq/scan/read`
provides portable promise-based readers. `@aihq/scan/host` runs source acquisition
and detectors on Node `>=24.15.0 <25`.

```js
import { runScan, prepareArtifact } from "@aihq/scan/host";
import { readReport, readArtifact } from "@aihq/scan/read";

const result = await runScan({
  schema: "urn:aihq:scan:request:1.0.0",
  source: { kind: "local", path: "/absolute/path/to/source" },
  selection: { paths: "all", excludedPaths: [] },
  detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
});
if (result.status === "assessment") {
  const prepared = await prepareArtifact({
    report: result.report,
    annexes: result.annexes.map(({ id, bytesBase64 }) => ({
      id, bytes: Uint8Array.from(atob(bytesBase64), c => c.charCodeAt(0)),
    })),
  });
  const inspected = await readArtifact(prepared.bytes);
  // inspected.authenticity is "unchecked". Authentication is a separate call.
}
```

All requests and reports are closed documents. Invalid requests have no detector
effects. The request is snapshotted before acquisition; input getters, duplicate
detector IDs, duplicate paths, unsupported control fields and invalid detector
configuration are refused. Selection names files or file links. An empty file
selection requires an empty captured file set. Explicit exclusions remain visible.

Local capture reads stable regular files through file descriptors, rejects hard
links and unsupported entry types, preserves contained file and directory link
identities, and copies the exact hashed bytes into an owned private snapshot.
Root `.git` is omitted by the `aih-source-capture-1` profile. Other files, including
dot files and nested `.git` directories, remain in scope. A detector never reads
the subsequently changing local source. Capture rereads both source and snapshot
before establishing identity; detector execution checks its supplied snapshot
before and after each unit. Losing that binding yields a diagnostic result without
a Scan ID. Absolute local acquisition paths are absent from portable reports.

Git requests specify a credential-free HTTPS repository URL and a full lowercase
40-hex commit. Scan acquires only that explicit commit into an owned temporary
object store and reconstructs source from its raw tree/blob objects. It verifies
commit and blob object identities. It performs no working-tree checkout, so
attributes, filters, line-ending conversion and source-provided checkout hooks
cannot change or execute the pinned material. Unsupported modes, submodules and
unrepresentable links cause capture refusal. Acquisition disables ambient Git
configuration and hooks, bounds output, and contains the entire process tree.
Git links that traverse another link or a regular file before further path
components are refused rather than being rewritten with different traversal semantics.
The fetch uses an owned loopback CONNECT relay for the exact repository authority.
Git verifies end-to-end TLS; redirects and inherited proxy bypass are disabled.
Before forwarding each chunk, the relay enforces an aggregate bidirectional
transport budget of `maxSourceBytes + 1024 * maxSourceEntries + 1 MiB`, including
retries. It permits at most eight connections and 8 KiB CONNECT headers. Crossing
the budget closes the sockets and aborts the contained Git process tree. Git keeps
the compressed pack instead of unpacking fetched objects into loose files;
source entry and decoded blob bounds are checked separately during materialization.
This transport budget is a separate acquisition limit and can refuse an otherwise
small source if its protocol or metadata overhead exceeds the allowance.
Optional `{ signal, gitCredentials: { username, password } }` host controls remain
outside JSON. Credentials apply to the selected HTTPS origin; redirects are
disabled. No credential, detector environment or local source path enters the report.

The current adapters support one complete input unit per detector. Its exact
captured entries, requested output scope, resolved configuration, platform facts,
released adapter dependency bytes, rule material and execution profile identify
the unit. Successful units remain in an assessment when another detector fails,
refuses or is cancelled. Output projection, findings scope, annex byte binding and
report semantics are checked before admitting each detector's observation or annex.
Malformed or oversized output fails that detector and preserves admitted siblings.
Admission also enforces cumulative report, decoded artifact and encoded artifact
budgets, reserving bounded diagnostic space for remaining detector slots. Diagnostic
details remain generic rather than exposing vendor data. Failures leave their scope uncovered. A refused empty-source
detector can have complete empty coverage while the assessment remains partial.
Report completeness requires every detector to succeed with complete coverage.

Binding-gate's unit is its complete selected inventory, including containing
directories and the captured targets of selected file links. An unrelated source
file can change without invalidating that unit. Native source identity and
trust-lint bind the complete source tree: trust-lint reads repository-wide
license, secrets and artifact facts in addition to selected files. Their whole
tree must be reassessed after any captured input changes. Changing selected
membership reruns the complete affected unit; an old larger unit is never trimmed
or relabelled as current work. This release does not split arbitrary detectors
into independent file-level observations.

| Detector | Configuration | New assessment support |
| --- | --- | --- |
| `detector.aih-native` | `{}` | Native source identity observation; empty sources are explicitly refused by its definition |
| `detector.aih-binding-gate` | `{}` | Existing in-process binding inspectors; complete selected-closure reuse |
| `detector.aih-trust-lint` | `{internalScopes:[],mcpConfigPaths:[]}` | Existing in-process trust lint; whole-tree reuse; arrays follow the detector's published ordering and scope rules |
| `detector.semgrep` | `{}` | Existing bounded profiles; binds exact shipped Semgrep rule text; platform and prerequisites still apply |
| Cisco, SkillSpector, Snyk | Their existing published configuration | `rules-material-unavailable` until an exact released rule identity can be established |

Legacy candidate-producing profiles cannot produce this portable observation
format and are explicitly refused. Current profiles also refuse directory-link
captures when their analyzer snapshot cannot preserve that entry type. Such
refusals leave the shared source profile intact. Legacy root exports remain
available under their existing contracts. The new path has no Core commit/schema
lock, success-only publication projection, report TTL, signing or posting side effect.

Repeated calls can retain successful observations in a process-local handle:

```js
import { createRetainedObservationsV1, runScan } from "@aihq/scan/host";

const retained = createRetainedObservationsV1();
const first = await runScan(request, { retained });
const next = await runScan(request, { retained });
```

Scan owns the retained bytes. Cloning or deserializing the handle cannot establish
custody, and changing an earlier returned result cannot change those bytes. Each
lookup rechecks the original observation and annexes against the current complete
detector input and current resource limits. The bounded store evicts older units;
eviction causes fresh work. Observation age alone does not invalidate a unit.

A reused observation keeps its original body, observation ID, producer and
`startedAt`/`completedAt`. Its current result reference records `origin: "reused"`
and `fromScanId`; these fields do not change the observation body. Scan assembles
current source identity, requested detectors and coverage into a new assessment.
Reuse does not advance the time at which the work was observed. Fresh and reused
observations can coexist with explicit unavailable work in a partial assessment.

Durable sharing uses explicitly located `priorArtifacts` in the request and
independently selected `reuseTrust` in the host options. Imported candidates must
both authenticate and pass the supported detailed artifact reader before current
input matching. An unsigned, corrupt, unsupported, untrusted or unavailable
artifact produces a `reuse-miss` and current work. Trust comes from the caller's
host configuration, never from the artifact itself. Source Git credentials are
not forwarded to artifact URLs. Material-change delivery is a separate capability.

The three in-process profiles establish current detector and runtime identity
before lookup. External profiles whose complete tool identity is known only after
execution rerun with an explicit reason. Unknown rule material remains a refusal.
The implementation and legacy donor differences are recorded in
[observation reuse migration](observation-reuse-migration.md).

Readers validate the supported report's closed shape, source/configuration/
observation hashes, ordered unique membership, observation input, file-bound
findings, exact coverage partition and complete annex descriptors. `readReport`
requires canonical bytes and returns `annexBytes:"not-supplied"`.
`readArtifact` additionally checks every supplied annex byte and returns
`annexBytes:"checked"`. Both leave producer authenticity unchecked. Unsupported
detailed schemas return `unsupported-report` with the encountered schema and Scan ID;
narrow artifact authentication can still verify opaque report bytes independently.

Canonical JSON sorts object keys by UTF-16 code units and preserves array order.
Strings and keys must already be well-formed NFC. Control numbers are nonnegative
safe integers. Duplicate keys, lossy tokens, negative zero, accessors, malformed
UTF-8 and excessive depth are rejected. Native annex bytes retain their original
content. The Scan ID hashes `UTF8("aih.scan.report.v1\0") || canonicalReportBytes`
with a single NUL byte after the domain string. Signing, location and packaging
are outside this identity. Re-signing unchanged assessment bytes preserves the ID.

Default/ceiling source budgets are 100,000 entries and 256 MiB of file bytes;
request 2 MiB; report 16 MiB; each annex 16 MiB; decoded report plus annexes 64 MiB;
artifact 96 MiB; statement 128 KiB; nesting 512. The default detector timeout is
600,000 ms and the supported range is 100–3,600,000 ms. Callers may lower effective
budgets, which are recorded in the report. Resource failures are explicit;
evidence is never truncated into a complete result.

Versioned JSON Schema resources use `urn:aihq:scan:<name>:1.0.0` and JSON Schema
2020-12. Their declarative shapes accompany the byte-profile and digest/coverage
cross-field checks performed by the reader. Import schemas through
`@aihq/scan/schemas/<name>/1.0.0.json` for `request`, `run-result`, `report`, `artifact`
and `evidence-association`. [Artifact APIs](artifact-authentication.md) describe independent
construction and authentication.

Representative valid and invalid documents are also shipped at
`@aihq/scan/schemas/examples/1.0.0.json`.
