# Portable assessments

For the Unreleased compact `readSummary` and deterministic `selectAssessments`
operations, see [summary and latest matching evidence](summary-selection.md).
They derive from these same report/artifact readers without introducing another
signed format or scanner execution.

`@aihq/scan/contracts` publishes the installed package identity, exact supported
schema IDs, entry runtimes and JSON-compatible wire types. `@aihq/scan/read`
provides portable promise-based readers. `@aihq/scan/host` runs source acquisition
and detectors on Node `>=24.15.0 <25 || >=26.12.1 <27`.

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
40-hex commit. Scan checks named-repository reachability, then acquires that
explicit commit into an owned temporary object store and reconstructs only its
source from raw tree/blob objects. It verifies
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
available under their existing contracts; their status is listed in the
[legacy root table](../README.md#legacy-root-aihqscan). The new path has no Core commit/schema
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

`fromScanId` names the assessment from which Scan acquired the reusable bytes.
For process-local retention, this is the assessment that originally created the
stored unit. For an imported artifact, it is that authenticated artifact's Scan ID,
even if its own reference records an earlier reuse. It is an acquisition reference,
not a claim to have authenticated the observation's entire prior history.

Durable sharing uses explicitly located `priorArtifacts` in the request and
independently selected `reuseTrust` in the host options. Imported candidates must
both authenticate and pass the supported detailed artifact reader before current
input matching. An unsigned, corrupt, unsupported, untrusted or unavailable
artifact produces a `reuse-miss` and current work. Trust comes from the caller's
host configuration, never from the artifact itself. Source Git credentials are
not forwarded to artifact URLs. Material-change delivery is a separate capability.
Hosts must authorize the prior artifact locations they pass to Scan; the library
does not impose an application-specific filesystem or network access policy.

The three in-process profiles establish current detector and runtime identity
before lookup. External profiles whose complete tool identity is known only after
execution rerun with an explicit reason. Unknown rule material remains a refusal.
Implementation identity includes each local runtime module and the complete
installed trees of its imported packages, with their resolved runtime, optional
and peer dependencies. These package trees are conservative dependency units;
unrelated product modules and the application's whole lockfile are not input
identities. Unsupported or over-budget dependency material is an explicit
`implementation-material-unavailable` refusal for the affected detector.
Node startup conditions are part of implementation identity. Command-line
`--require` preloads bind their exact static module closure, parsed as JavaScript
syntax. Supported preloads load modules through direct literal `import`/`require`
calls; indirect loading, runtime code generation and behavior from untracked
runtime configuration are outside this host model. Preloads passed through
`NODE_OPTIONS` (`--require` or `-r`), `--import`, `--loader`/`--experimental-loader`,
and custom module registration hooks are currently unsupported. Nonliteral dynamic
module acquisition is also refused. These contexts produce an explicit refusal
for each affected detector, including fresh work and external detectors; they do
not produce observations with an unknown adapter identity.
Relative command-line preloads resolve from the working directory and must match
an already loaded startup module. Keep the launch working directory unchanged
before and during assessment; the loaded-module check cannot establish arbitrary
working-directory history before Scan was imported.
Run Scan from an immutable package installation and restart its process after
changing installed code or dependencies. In-place package replacement while Node
still holds previously loaded modules is outside the supported execution model.
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

## Content coverage

`readContentCoverage` answers whether a read report assessed an exact set of files
and which of its observations cover all of them. It takes a result returned by
`readReport` or `readArtifact` and the expected files as `{ path, sha256,
byteLength }` descriptors:

```js
import { readArtifact, readContentCoverage } from "@aihq/scan/read";

const read = await readArtifact(bytes);
const coverage = await readContentCoverage({
  read,
  descriptors: [{ path: "SKILL.md", sha256: "f818…d77", byteLength: 138 }],
});
// {
//   status: "matched", scanId, authenticity: "unchecked",
//   observations: [{
//     observationId, origin: "fresh",
//     detector: { detectorId, detectorVersion, adapterSha256, platform },
//     input: { rulesSha256, configurationSha256, profileId, profileSha256, scopeKind, targetPaths },
//     coverage: { coveredPaths }, detectorCoverage, findings, annexes,
//   }],
//   excluded: { "detector-not-succeeded": 0, "input-missing-descriptor": 0,
//               "coverage-incomplete": 0 },
//   detectorsWithoutCoverage: [],
// }
```

The result `status` is the source association:

| Status | Meaning |
| --- | --- |
| `matched` | Every descriptor equals a captured `file` or `file-link` entry by path, SHA-256 and byte length |
| `mismatched` | At least one descriptor has no equal captured file entry; `unmatchedPaths` lists their paths sorted and no observations are returned |
| `unavailable` | The read was `unsupported-report` or `invalid`, or the supplied read result failed revalidation (`reason`) |
| `invalid` | The descriptors or call input are outside the supported bounds |

An observation covers the descriptors only when its detector result succeeded,
its input entries contain every descriptor exactly, and its output coverage
includes every descriptor path. Every other observation is
counted once under the first failing reason in `excluded`; it is never silently
dropped. `detectorsWithoutCoverage` names requested detectors, including refused
detectors with no observations, that contributed no covering observation. A
covering observation returns all of its findings, including findings located at
other covered paths, and the report descriptors of its annexes ordered by ID.
The reader already requires every observation annex, including finding supporting
evidence, to resolve. The result makes no claim about annex bytes; `readArtifact`
checks them, and `readReport` has none to check.

The read result is revalidated as a closed supported report, and its Scan ID must
identify that report, so an altered result that no longer reads cannot claim coverage.
Descriptors are a nonempty array of at most `maxContentDescriptors` (10,000)
closed own-data objects with unique safe source-relative paths of at most 4,096
UTF-8 bytes, lowercase 64-hex SHA-256 digests and nonnegative safe integer
lengths. Inputs are plain objects of the calling realm, as for the readers.

The operation performs no filesystem, process or network access. It does not
authenticate the producer, and its result is not a review, approval or
qualification decision. Authenticate the artifact separately with
`authenticateArtifact` when producer identity matters.


### Independent coverage queries

`readContentCoverageBatch` is the finite alternative when a consumer needs many
independent descriptor groups over one report. Each group's descriptors remain a
conjunction. The function snapshots the query data and all read metadata/report
before its first asynchronous yield, validates the owned report and its Scan ID
once, then shares capture, observation-input and covered-path indexes within that
call. It keeps no persistent handle or global cache. `readContentCoverage` retains
its signature, result shape and fresh validation on every call.

```js
import { readContentCoverageBatch } from "@aihq/scan/read";

const batch = await readContentCoverageBatch({
  read,
  queries: [{ descriptors: memberA }, { descriptors: memberB }],
});
if (batch.status === "complete") {
  const first = batch.results[0];
  if (first.status === "matched") {
    const { observationIndexes, ...rest } = first;
    const singletonEquivalent = {
      ...rest,
      observations: observationIndexes.map(index => batch.observations[index]),
    };
  }
}
```

The closed envelope has exactly `read` and `queries`; each closed query has exactly
`descriptors`. `results[i]` corresponds to `queries[i]`, including duplicate queries
and invalid rows. Matched rows have the singleton fields with `observationIndexes`
in place of `observations`. Indexes refer to the shared `observations` table, which
contains each used observation once, in first-use order. Observation ordering
within each row matches the singleton. All findings, supporting annex descriptors,
origins, prior Scan IDs and detector coverage remain intact, including findings
outside the query paths. Every complete response is deeply readonly in the public TypeScript types and
deeply frozen at runtime;
clone data before editing it. Input mutation, output mutation and later calls
cannot change another row's answer.

Malformed envelopes, non-JSON/accessor/sparse/cyclic query data, and aggregate
resource overruns return `{ status: "invalid", diagnostics }` for the whole call.
No partial results or truncated success are returned. Ordinary invalid query shapes
or descriptors instead produce per-query `invalid` rows. Other valid rows still
run. Descriptor errors take precedence over read unavailability, as in the
singleton. A valid query over an invalid or unsupported read produces the same
`unavailable` reason/diagnostics as the singleton. Unsupported versions remain
unavailable. Supported read results are closed and revalidated, including semantic
identities and annex references; claimed authenticity and substituted Scan IDs
grant nothing. No caller `trusted` flag or frozen object bypasses admission.

The exported frozen `coverageBatchLimits` defines these whole-call bounds:

| Property | Limit |
| --- | ---: |
| `maxQueries` | 4,096 nonempty ordered queries |
| `maxDescriptorReferences` | 50,000 cumulative descriptor array entries, including duplicates/invalid queries |
| `maxRequestBytes` | 16 MiB of JSON-encoded `queries` UTF-8 bytes |
| `maxRequestDepth` | 8 nested edges from the `queries` array |
| `maxRequestNodes` | 300,000 visited values, counting repeated references separately |
| `maxClassificationWork` | 10,000,000 conservative units: (descriptor references + query count) � (detector results + observations) |
| `maxObservationAssociations` | 100,000 total matched-row observation indexes |
| `maxResponseBytes` | 32 MiB of JSON-encoded complete response UTF-8 bytes |

Every query still accepts up to `maxContentDescriptors` (10,000). Query shape,
aggregate reference/byte/depth/node bounds are checked before asynchronous report
admission. The work bound is checked after admission/indexing, before classification;
association/output bounds are checked incrementally before retaining each row or
shared table entry. Diagnostics use `resource-limit` for bounds and `invalid-input`
for malformed input. The report retains its existing independent report bounds.
Shared tables prevent full observation payload amplification; the association,
work and response bounds also cover adversarial repeated-path and detector-gap
amplification. These limits establish finite work, not a particular machine's
qualification duration. Real consumer capacity requires measured installed tests.

Batch coverage has the same exact file/file-link matching, first-failing-reason
counts and detector gaps as the singleton. Directories never match file content.
It performs no host access, authentication or qualification. Results remain
`authenticity: "unchecked"`; authenticate artifacts and apply inventory/scope and
qualification checks independently. Report/artifact/signature/Scan ID formats do
not change.

## Git request forms, limits and diagnostics

The `runScan` API accepts `source.repository` only as a credential-free `https://`
URL with a hostname, at most 2048 UTF-8 bytes, without a query, fragment, controls
or whitespace. A repository path and optional `.git` suffix are accepted, for
example `https://github.com/owner/repository.git`. `owner/repository`, local paths,
SCP syntax and non-HTTPS transports are refused by this API. Its `source.commit`
is exactly 40 lowercase hexadecimal characters naming a full SHA-1 commit object.
Short hashes, uppercase hashes, branches, tags, `HEAD` and SHA-256 object IDs are
refused before capture. The CLI's explicit ref-resolution convenience is separate;
`runScan` never resolves mutable refs.

Capture bounds apply to the whole pinned tree before selection, including
unselected entries. Lower `request.limits` values can tighten the source limits;
they cannot exceed the ceilings below. Git's command limits are fixed independently
of `detectorTimeoutMs`.

| Limit | Default / ceiling | What is counted |
| --- | --- | --- |
| `maxSourceEntries` | 100000 | Tree members, including directories and links |
| `maxSourceBytes` | 268435456 (256 MiB) | Decoded source bytes; snapshot capture also counts file-link target bytes |
| `gitTransportBytes` | 371884032 | Bidirectional relay bytes across retries; derived as `maxSourceBytes + 1024 * maxSourceEntries + 1048576` |
| `gitTransportConnections` | 8 | Relay connections across the acquisition |
| `gitConnectHeaderBytes` | 8192 | CONNECT header buffer |
| `gitRelayClientIdleMs` | 30000 before CONNECT; 600000 after connection | Client socket idle time |
| `gitRelayRemoteIdleMs` | 60000 | Upstream socket idle time |
| `gitCommandTimeoutMs` | 600000 per Git command | Elapsed subprocess time |
| `gitStdoutBytes` | 16777216 normally; 16 for shallow-state metadata; 1048576 for a commit object; 64 for a blob size; declared blob size for a blob | Raw Git stdout bytes per command |
| `gitStderrBytes` | 65536 | Raw Git stderr bytes per command, never echoed |
| `sourcePathBytes` | 4096 | UTF-8 bytes per source-relative path |

The bounded subprocess wrapper separately caps base64-encoded JSON stdout at
`ceil(gitStdoutBytes / 3) * 4 + 64` bytes (`maxStdoutBytes`), and its stderr at
65536 bytes (`maxStderrBytes`). The failed stream is named with its configured limit and observed byte count,
including the rejected chunk. Observed counts may be lower bounds because
reading stops at the bound.

A diagnostic result has no Scan ID. Every Git capture diagnostic's `detail` names
the failing step, such as `git init`, `git fetch`, `verify commit`, `validate tree`,
`read blob size`, `capture snapshot` or `cleanup`. Bound diagnostics use
`resource-limit` and name the limit, its value and the observed count or time.
For example, `Git capture step validate tree: maxSourceEntries exceeds limit 1;
observed 2` is actionable even if only one of those entries was selected.
`git-acquisition-failed` covers failed acquisition, invalid pinned material,
cancellation and capture I/O; it never repeats raw Git stderr, URLs or host paths.
`git-containment-failed` means process-tree cleanup could not be confirmed or
temporary capture material could not be removed. No assessment proceeds in that
case. Containment failure takes precedence over a simultaneous transport bound.
Request-form refusals remain `invalid-input` at phase `request` and explain the
accepted forms. These are diagnostic code/detail values within the existing
versioned result schemas; no new wire fields or format identifiers are introduced.


## Repository reachability

Before materializing Git content, Scan lists the named repository's branch/tag
refs, then fetches only that repository's
`refs/heads/*` and `refs/tags/*` into an owned temporary store and reads their
complete commit ancestry. Imported ref names and identities must match the listing;
a mismatch or movement leaves the check unchecked. Branch ancestors, lightweight tags and annotated tags
can establish membership. Object presence, a fork-network commit endpoint, a
pull-request ref or a fetch of the exact commit alone cannot establish it.
A completed check that does not contain the commit refuses capture with
`git-commit-unreachable`; no report or Scan ID is produced. Run-result `2.0.0`
records `reachability: "unreachable"` for that refusal.

A successful check records `reachability: "reachable"` in both report and run-result
`2.0.0`. If the independent check cannot complete, for example because its refs
are unavailable offline, its ancestry is shallow or malformed, or its bounded
output exceeds a limit, exact-commit acquisition can still proceed while the
shared transport budget remains available. Both
documents then record `reachability: "unchecked"`, with a
`git-reachability-unchecked` diagnostic naming the check and any encountered bound.
An unavailable check is never evidence of membership or non-membership. If exact
acquisition itself fails, its normal diagnostic refusal still applies.

The ref advertisement, ancestry fetch and exact-commit fetch share one aggregate
transport budget and connection bound, retaining the contained command runner above. Full history may exceed the
budget even for a small current tree; exhausting the shared transport budget
refuses acquisition with its named resource-limit diagnostic. No shallow
negative is treated as unreachable. Process containment failures and caller
cancellation stop acquisition. No captured content is executed. Request `1.0.0`
also receives the check and refusal, but its closed legacy documents retain their
original field shape; select request `2.0.0` for the explicit reachability field.
Reachability records the repository refs observed during this run; it does not
promise that those refs remain unchanged or establish approval or authenticity.

## npm sources

Use request `urn:aihq:scan:request:2.0.0` with either exact coordinates or an
independently pinned archive:

```js
const source = { kind: "npm", package: "@example/mcp-server", version: "1.2.3" };
// Or supply the archive's actual SHA-512 base64 digest:
const pinned = {
  kind: "npm",
  archive: { url: "https://example.invalid/server.tgz", integrity: "sha512-<base64 digest>" },
};
```

Pass `source` in the ordinary `runScan` request with selection and detectors.
Exact coordinates may also include `archive`. Without it, Scan reads only that
version's metadata from `https://registry.npmjs.org`, requires matching name and
version plus a SHA-512 archive pin, then verifies the compressed bytes before
extraction. Coordinates must also match the regular captured `package.json`.
The report preserves coordinates when supplied and always names the acquired
archive URL and integrity. An archive-only source makes no package-name claim.
Ranges, tags, shortened versions and other non-exact specifiers produce request
diagnostic `npm-version-not-exact` before any acquisition.

Acquisition uses credential-free HTTPS with redirects disabled and a shared
30-second deadline (also cancelled by the host `signal`). Ambient npm settings,
credentials, installation and lifecycle scripts are unused. Metadata is capped
at 1 MiB. Each archive download and expanded tar is bounded by
`maxSourceBytes + 1024 * maxSourceEntries + 2048` bytes; decoded file bytes and
all captured entries, including implicit directories and link targets' bytes,
also obey the ordinary source limits. Bounds apply before detector selection.

The archive is a gzip-compressed ustar tree under `package/`; the root prefix is
removed from captured paths. Regular files, directories and contained file or
directory symlinks are supported. Hard links, special files, extended headers,
duplicate paths, traversal, root `.git` metadata and links through links are
refused. No captured content executes. Each regular tar entry's execute bits
supply its own `executable` state on every platform; a file link takes its target's
state. The usual capture-profile-2 digests, observation identity, findings and
coverage rules apply. A refused detector leaves coverage incomplete and the
assessment partial.

`npm-integrity-mismatch` means the acquired compressed bytes differ from the pin.
`npm-containment-failed` names unsafe archive entries or failed temporary cleanup;
`npm-acquisition-failed` names unsuccessful acquisition, malformed archive or
package identity mismatch. Resource bounds retain `resource-limit` with the limit
and observed value. Failures return no Scan ID and omit upstream error text.
