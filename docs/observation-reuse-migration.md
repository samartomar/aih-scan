# Observation reuse migration

This change extends the immutable assessment API with reuse of complete, relevant
observations. The owning delivery is
[Scan #86](https://github.com/samartomar/aih-scan/issues/86). Package publication
remains a separate release step.

The source baseline is `fc7560a87e6047ecfd58631d99469977349dff01`. The older
observation donors below were also inspected at
`efd4c4df59c5afd125b256d0a9ff7d5c5da0c9ab`; their affected source and assertions
had not changed from research donor
`05d2240f332e3fdfc7a5d7d7c0696e6a96261e5e` at that inspection.

| Source and assertions | Disposition | Verified public behavior |
| --- | --- | --- |
| `src/observation/native-observation-v1.ts`: immutable branded bytes, exact expected analyzer/config/platform context, fresh source checks; `tests/contracts/native-observation-v1.test.ts` | Retain strict identity and custody checks. Adapt the lookup from universal source/closure/snapshot hashes to the detector's complete relevant inputs. | Unchanged relevant inputs preserve original body, ID and times. Relevant changes rerun; an unrelated source change does not invalidate a selected closure. |
| `src/observation/observation-evidence-v1.ts`: domain-separated key/set hashing and bounded annex identity; `tests/contracts/observation-evidence-v1.test.ts` | Retain deterministic byte identity, ordering, multiplicity and exact annex checks under the assessment contract. | Reuse retains original supporting bytes; a changed, missing or substituted annex cannot supply reusable work. |
| `src/assessment/run.ts`: complete source capture, one result per detector, reliable sibling preservation and bounded candidate admission | Extend current assembly to admit eligible prior observations under the current source, selection and resource limits. Keep source integrity failure separate from detector failure. | Current coverage partitions remain exact. Removed members disappear, current unavailable work stays visible, and partial assessments retain reliable siblings. |
| `src/artifact/{host,read}.ts`: independent local authentication and supported detailed parsing | Reuse both boundaries for supplied artifacts; neither readability nor narrow authentication alone admits observations. | Unsigned, untrusted, corrupt, mismatched or unsupported imported work is an explained reuse miss followed by current work. |
| `tools/verify-baseline-publication-reuse.mjs` and `tests/baseline/publication-reuse.test.ts`: legacy age, exact publisher/request and all-or-none publication rules | These rules do not govern the new assessment reuse path. Historical publication APIs and evidence remain under their existing contracts. | Report age alone never invalidates an observation. Current reports can mix reused, fresh and unavailable detector work without changing old observation times. |

The original native-observation test intentionally invalidates a selected closure
after an unselected file changes. That assertion still describes the old donor;
the assessment API instead distinguishes selected-closure inputs from a detector
whose declared scope is the whole source tree. A complete input unit is never
trimmed into a smaller reused unit.

The new path does not import a legacy package, add a service, or run a production
signer. The public boundary checks are in:

- `tests/assessment/retained-observation-reuse.test.ts` and
  `retained-custody.test.ts`: preserved identity, immutable retained bytes,
  rejection of cloned handles, and current budget admission.
- `tests/assessment/selected-scope-reuse.test.ts`: unrelated versus relevant
  changes, removed membership, complete unit boundaries, file-link targets, and
  whole-tree trust checks under narrower output selection.
- `tests/assessment/prior-artifact-reuse.test.ts`: independent authentication and
  supported reading of the same acquired bytes; bounded file/HTTPS acquisition;
  invalid imports, changed detector inputs, and age-independent admission.
- `tests/assessment/adapter-isolation.test.ts`: real installed module changes
  invalidate their dependents, preserve unrelated work, and retain native annex
  parity with the existing runner, including file links.
- `tests/assessment/dependency-input-reuse.test.ts`: independently loaded package
  installations with changed parser bytes invalidate dependent imported work and
  preserve unaffected observations; missing dependency material is an explicit
  refusal, and changed startup conditions require current work.
- `tests/package-install-v2.test.ts` and its packed assessment consumer: retained
  and authenticated imported reuse through the actual installed public API.

The existing lost-snapshot-identity assertion in `tests/assessment/run.test.ts`
still requires an assembly diagnostic without a Scan ID. Its fault injection now
changes the captured snapshot through the explicit prior-artifact transport
boundary: the native adapter reads stable descriptors, so the former
`readFileSync` interception no longer reached that read. The integrity requirement
is unchanged.

The HTTPS tests control the fetch transport to exercise credential, redirect,
streaming, cancellation and byte-limit behavior; they do not establish live TLS
service availability. File acquisition checks its deadline between operations;
a synchronous OS filesystem call cannot itself be interrupted by that deadline.
A small timing fixture does not establish customer-scale performance or
file-level support for every detector.

## Representative delta measurement

`npm run build && node tools/measure-observation-reuse.mjs` measures an owned
temporary fixture of 129 files: one selected binding input and 128 unselected
1 KiB files. Each of seven rounds changes one unselected file. Binding-gate reuses
its complete selected unit, native source identity runs fresh over the changed
tree, and an unavailable detector remains explicitly refused. The report is partial.

On Windows x64, Node 24.19.0, on 2026-10-01, the empty-retention first run took
841.24 ms. Delta runs had a 645.87 ms median, compared with 706.37 ms when forcing
fresh detector work on the same changed source. Fresh/delta order alternated;
the process and filesystem caches stayed warm. These are one host's observed
end-to-end timings, including current source capture and report validation.
They do not promise the same speedup for other workloads or expensive external
detectors. The script checks the actual origins, preserved binding body/ID and
current unavailable accounting on every round.
