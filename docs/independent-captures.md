# Independent Catalog capture batches

The maintainer producer accepts one to seven independently selected Catalog
captures through the existing freeze/run/publisher operation. Each capture keeps
its own inventory, material namespace, original report, Scan ID and detached
signature. There is no combined report or shared baseline. The existing
[singleton capture](catalog-capture.md) and exact seven-Git-source modes remain
available with their original schemas.

## Input and identity

Start with the singleton input fields and select schema
`urn:aihq:scan:catalog-capture-batch-input:1.0.0`. Add the required `batchLimits`
object and a `captureId` to every target:

```json
{
  "maxInputBytes": 268435456,
  "maxSourceBytes": 268435456,
  "maxSourceEntries": 100000,
  "maxDurationMs": 5400000
}
```

These are ceilings, not guaranteed resource needs. Every value must be a positive
safe integer no greater than its ceiling; duration must be at least 100 ms. The
ordinary per-capture limits also apply. `maxInputBytes` sums encoded envelope
lengths; source bytes and entries sum independent materialized roots, including
inferred directories. Shared paths in different captures count separately. Input
and frozen manifest remain bounded at 2 MiB each.

Targets all retain `repository: "samartomar/aih-catalog"`, a reviewed full commit,
whole-tree selection without exclusions, explicit trust-lint configuration and
their own immutable capture selector. `captureId` must match
`^[a-z0-9][a-z0-9-]{0,47}$`. Keys, asset IDs and envelope digests must be unique.
For example, `default`, `extensions`, `ecc`, `superpowers` and `anthropic` are
independent keys under the same real repository. Array order is frozen custody;
reordering a retained inventory or substituting a sibling artifact refuses.

Freeze emits `urn:aihq:scan:catalog-capture-batch-manifest:1.0.0`, retaining
`batchLimits`, each `captureId` and each independently checked descriptor closure.
The batch digest binds these fields. Run rechecks and materializes every selected
input before starting any detector or creating candidate output. A bad final input
therefore cannot leave apparently usable earlier assessments.

## Results, signing and failure custody

Target files use `targets/catalog--<captureId>/`. Producer inventory schema is
`urn:aihq:scan:catalog-capture-batch-inventory:1.0.0`; it adds `captureId` to each
ordinary target row and `termination` plus measured `durationMs` at the root.
Termination is `completed`, `cancelled` or `deadline-exceeded`. The monotonic
duration budget applies separately to freeze and run, bounds acquisition calls,
and aborts detector work. Graceful cancellation/deadline stops new targets and
preserves original completed/partial results plus diagnostic/no-ID unfinished
rows. Storage failure or forced runner loss can still prevent retention.
Interrupted output exits 2 and cannot enter candidate publication.

Candidate metadata and authenticated publication rows also retain `captureId`.
The signing selection uses
`urn:aihq:scan:catalog-capture-batch-signing-selection:1.0.0` and includes the key
on each selected assessment. Diagnostic rows have no Scan ID or signature. A
completed batch may retain truthful partial assessments without changing their
outcomes, timestamps, scope, annexes or coverage. Candidate validation refuses
terminated batches or measured duration above the frozen limit.

The existing protected signer retains seven statement slots and one environment
approval. It receives checked detached statements, predicates and the selected
list; no input capture, report/annex or supplied scanner installation enters that
payload. Trust and signer permissions remain independently maintained.

NONPUBLISHABLE recovery uses fixed artifact slots
`scan-refresh-NONPUBLISHABLE-capture-0` through `-6`, each containing the validated
keyed directory. The root index preserves keys, retained original digests and
explicit absent/refused files, including safe discovered capture directories if
manifest custody is damaged. Individual archives remain below 256 MiB; cumulative
retained original bytes are bounded at 2 GiB. No original is truncated to fit.
Ordinary measured candidate/final archive admission remains 768 MiB with a 2 GiB
expanded bound; input fit alone does not guarantee report transport fit.

## Operation counts and independent updates

For a ready selected batch, the successful hosted path is one freeze dispatch,
one run dispatch and one publisher dispatch: **three dispatches and one protected
approval**, with separate signatures/reports. Each input still needs its existing
immutable capture publication; this adds no shared upload transport. These counts
exclude retries, input publication and final maintainer report publication.

Dependencies can require multiple ready batches. The initial five-view Catalog
rollout first handles default, Extensions and Anthropic, then explicitly rebinds
and refreezes ECC and Superpowers against qualified Extensions. That is **two
waves, six successful dispatches and two protected approvals**. Generic five-target
capacity does not remove that dependency. Later maintenance explicitly selects
only changed/ready captures; unchanged release baselines and saved pins persist.

`tests/refresh/independent-batches.test.ts` exercises packed Scan public APIs with
five separate assessments plus a diagnostic sibling, mixed detector outcomes,
matching/mismatched inventories, detached fixture signing/authentication, subset
updates, reordering/substitution, aggregate refusal and interruption. Its portable
runtime boundary and disposable signing key are fixture evidence. The optional
`qualify` mode of its support scenario additionally uses explicitly installed
Catalog/Core public APIs for five independent baseline qualifications and sibling
substitution refusal. These proofs do not establish real-content detector runtime,
production signing or a qualified production baseline. Actual durations and
output sizes must be measured during separately authorized production operations.
