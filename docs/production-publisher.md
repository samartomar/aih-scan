# Report workflows and the default trusted publisher

Scan's own published results are produced by two manual workflows. Neither runs on a
push, pull request or merge; source integration does not dispatch them, change protected
settings or authorize signing. Results are stored and served by whoever runs the store;
these workflows only produce and sign the files.

## Default trusted publisher

`verifySummary` trusts only the signers the caller passes in `allowedSigners`. When the
caller passes none, the default list is `defaultSigners` from `@aihq/scan/contracts`: one
entry, `aihq-scan-production`, matched by certificate issuer, subject and these Fulcio
extensions:

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Subject (SAN) and build signer URI (`.9`), build config URI (`.18`) | `https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main` |
| Runner environment (`.11`) | `github-hosted` |
| Source repository (`.12`), ref (`.14`) | `https://github.com/samartomar/aih-scan`, `refs/heads/main` |
| Repository ID (`.15`), owner (`.16`), owner ID (`.17`) | `1336836161`, `https://github.com/samartomar`, `9993940` |
| Trigger (`.20`), visibility (`.22`) | `workflow_dispatch`, `public` |

Extensions are `1.3.6.1.4.1.57264.1.N`. A matching subject alone is not enough; every
listed extension must match. Passing `allowedSigners` replaces the default (an empty list
trusts nobody). Any other cryptographically valid signature is reported as "signed, not
by a trusted publisher". The workflow file path is part of this identity: renaming or
moving `scan-report-publisher.yml` changes what the default identity can sign.

## Candidate: `scan-report-candidate-upload.yml`

Dispatched with the exact reviewed sources JSON, whose SHA-256 must equal the repository
variable `SCAN_REPORT_SOURCES_SHA256`. Each source is a public GitHub repository at a full
commit (optionally one item path) or an npm package at an exact version
(`tools/publisher/candidate.mjs sources` validates them). The job packs the reviewed main
commit once, installs that tarball in a fresh consumer, provisions the locked SkillSpector
and Cisco runtimes from `tools/analyzers`, and runs the installed
`aih-scan scan <source> --origin published --json --out …` for every source in static
mode. It uploads the unsigned `scan-report-candidate` artifact (the output folders, each
source's scan result, the sources and the scanner tarball's SHA-256). It has read-only
repository permission and no OIDC token.

## Prepared local content and completed outputs

`tools/publisher/prepared.mjs` is maintainer tooling, separate from the published Scan API.
It handles ordinary item roots, editions, bundles, plugins and extracted entries through
the same explicit inventory. It never discovers a whole repository in place of an item,
executes submitted files, signs results or publishes them. Source content remains in the
operator's staging area; it is **not included in the candidate archive**.

### Reviewed manifest

Hash the exact UTF-8 JSON bytes as SHA-256. This tooling-only format does not change
`aih-scan-request/1` or signed summaries:

```json
{
  "format": "aih-scan-prepared/1",
  "scanner": {
    "name": "@aihq/scan",
    "version": "0.1.0",
    "tarballSha256": "<64 lowercase hexadecimal characters>"
  },
  "assessment": {
    "mode": "ai",
    "tools": ["aih-trust-lint", "skillspector"],
    "provider": "openai_compatible",
    "baseUrl": "https://api.deepseek.com",
    "model": "deepseek-flash",
    "modelTokenLimits": { "contextLength": 1048576, "maxOutputTokens": 393216 },
    "reasoningEffort": "none",
    "structuredOutputMethod": "function_calling",
    "credentialVariable": "DEEPSEEK_API"
  },
  "items": [{
    "path": "items/example",
    "scanKey": "git-sha1:<40 lowercase hexadecimal characters>",
    "files": [{ "path": "SKILL.md", "mode": "100644", "sha256": "<64 lowercase hexadecimal characters>" }],
    "labels": { "caller": "unsigned producer reference" },
    "source": { "locator": "https://example.com/immutable-source", "revision": "exact-source-revision" }
  }]
}
```

An optional top-level `"revision": 2` sets the summary revision for every key the manifest
scans, so a store can publish a newer result for a key it has already published (default `1`).
It must be a positive safe integer. It is part of the configuration identity: an explicit
value, including `1`, is a separate resume namespace, while omitting it keeps existing
identities. Every
result, export and import must carry exactly that revision. Scan does not see the store:
before publishing, the operator must check that the revision is greater than every revision
the same signer has published for each selected key. A result for one key may be published
once per revision; for example, static evidence as revision 2 and AI evidence as revision 3.
Withdrawals are unchanged: a withdrawal covers that signer's revisions 1 to
`throughRevision` for that key. A later revision needs this prepared route: the candidate
workflow's sources route runs the CLI, which writes revision 1.

Each item root is relative to the staging content directory; each file path is relative
to that root. Include the complete inventory, including support files, with `100644` or
`100755` modes. Item roots must not overlap. Links, special files, traversal, changed
bytes/modes, missing/extra files inside an item and wrong computed keys are refused.
Unselected item roots may remain in a shared staging directory so a pilot/subset can
later expand to the full manifest. On POSIX, actual executable bits must match; on
Windows the explicit portable mode list supplies the executable information the disk
cannot represent. Matching reads the actual bytes and uses the portable public reader.

`labels` and `source` are optional unsigned caller metadata. They never enter signed
summaries. Review them for public suitability before transferring a candidate. Different
references may have the same key only when their full path/mode/hash inventories agree.

The example is the DeepSeek non-thinking schema-response configuration described in
[analyzers.md](analyzers.md#deepseek-flash-on-windows). Other explicitly selected
`openai_compatible` HTTP models/endpoints and the analyzer's `function_calling`,
`json_mode` or `json_schema` controls can be requested without a provider substitution.
The operator must verify that those settings work together at that provider. Endpoints
require HTTPS, except explicit loopback HTTP.
Credential values are read from `credentialVariable` (default
`SKILLSPECTOR_COMPAT_API_KEY`) into each isolated child environment only; receipts and
worker request files contain the variable name, never its value. Other provider,
Python/Node loader, tracing, home configuration and credential environments are not
inherited (the signed-in CLI profiles below use the operator's `HOME`). Set explicit analyzer executable paths in `AIH_SCAN_SKILLSPECTOR` and, if
requested, `AIH_SCAN_SKILL_SCANNER`; install them using the locked analyzer instructions.

#### Static and signed-in agent-CLI assessments

A static assessment names only `mode` and `tools`:

```json
"assessment": { "mode": "static", "tools": ["aih-trust-lint", "skillspector"] }
```

A complete static result is publishing evidence: the summary has `coverage: complete` and
`origin: published`, SkillSpector ran in static mode at the pinned standard version, and every
requested tool is `pass`, `warn`, `fail` or `not-applicable`. Its receipt status is
`complete-static`. A partial static result stays `incomplete` and is refused, as before.

The prepared route accepts signed-in Claude and Kimi Code clients. Claude needs an
exact, pinned Claude model id (`claude-<family>-<version>`, optionally with a date snapshot,
for example `claude-opus-5-5`) and an explicit effort, and it names no HTTP, credential or
maintenance controls. Aliases such as `opus`, `fable` or `default`, and `-latest` names, are
refused: they name whatever the CLI or account resolves at run time.

```json
"assessment": {
  "mode": "ai",
  "tools": ["aih-trust-lint", "skillspector"],
  "provider": "claude_cli",
  "model": "claude-opus-5-5",
  "effort": "medium"
}
```

For Kimi Code CLI, set `provider` to `kimi_cli`, `model` to `kimi-for-coding`, and
`effort` to `low`, `high` or `max`. The selected account must support the model and
the chosen effort. Use the signed-in Kimi Code CLI and region described in
[analyzer setup](analyzers.md#skillspector). Eligibility binds the exact provider, model
and effort, and `client: { "name": "kimi", "version": "2.7.2" }`.

Select K3 with `model: "k3"` and `effort: "max"`. To group semantic security discovery
(SSD) tasks, include the explicit profile in the assessment.

```json
"assessment": {
  "mode": "ai",
  "tools": ["aih-trust-lint", "skillspector"],
  "provider": "kimi_cli",
  "model": "k3",
  "effort": "max",
  "profile": "adaptive-ssd/1"
}
```

The local coordinator collects ready SSD tasks from the pinned SkillSpector runtime.
Each grouped prompt carries separate keys and source lines. The planner fits groups
to its input and output allowances. Version 1 conservatively counts each serialized
UTF-8 byte as one input token. Its 32,768-token output planning allowance includes
16,384 tokens reserved for reasoning; these figures size groups and do not set the
provider's generation limit. Oversized detector segments split before inference.
Actual group width depends on the files ready at
dispatch, so even a large manifest can produce one-task requests. Each result goes
back to its original detector for validation and scoring. Other detectors run their
usual analysis. Related tasks share model context, which can influence findings and
severity. The effective profile is recorded on the SkillSpector AI result and is part
of the prepared configuration and checkpoint identity. Select items suitable for
sharing a model context in the same campaign.

Each isolated Claude child gets `SKILLSPECTOR_PROVIDER=claude_cli`, `SKILLSPECTOR_MODEL` and Scan's
`AIH_SCAN_AI_EFFORT` from the manifest, so no ambient model or effort applies. It also gets the
operator's own `HOME`, because the signed-in CLI reads its sign-in from there, and
`PYTHONNOUSERSITE=1`, so user site-packages under that home stay out of the analyzer. That is
the one exception to the private home that other profiles use: use a host and account
dedicated to this work. The pinned SkillSpector starts the CLI with `--setting-sources=`, no
tools, `dontAsk` permissions and no session persistence, so user settings, hooks and memory
files are not loaded. The invocation also disables skills and commands, uses an empty
tool list, and selects strict MCP configuration without adding a server. It does not
pass literal `--bare`: Claude CLI 2.1.330 documents that this mode skips subscription
OAuth and keychain reads. The prepared receipt does not measure plugin startup overhead.
With Claude CLI 2.1.330 an identical call carried about 0.7k input
tokens, against about 2.8k with setting sources enabled on the same account. Confirm this on
your host before a campaign. No credential value is read or recorded.

Scan resolves the real `claude` binary on `PATH`, records the version that binary reports, and
starts exactly that binary for every analysis call with its auto-updater disabled. A
campaign's keys therefore record one client version unless the operator changes the CLI
between keys; check that every published key names the same `client.version`. The route needs Linux or macOS (see
[analyzers.md](analyzers.md)). A result is complete AI evidence (`complete-ai`) only when the
signed summary records `via: cli`, `provider: claude_cli`, the manifest's exact model and
effort, and the `claude` client with the version it reported. There is no model or effort
fallback: a usage-limit refusal or any unfinished AI pass leaves the key `incomplete` for a
later retry on the same profile. Changing the model or effort creates a separate
configuration and resume namespace.

Compatible tasks can share a provider request within one prepared run while its workers
are active. Separate runs have independent queues. Scan applies the model's input and
output limits and verifies each key's result on resume. A response that would add a
finding or other model-written text to a key is checked again using only that key's
original task before the text can enter its report.

AI assessments may also set `llmConcurrency` to an explicit positive safe integer, for
example `"llmConcurrency": 24`. The helper passes it only to its isolated scan child as
SkillSpector's existing `SKILLSPECTOR_MAX_LLM_CONCURRENCY` setting. Omitting it preserves
the pinned upstream defaults of two concurrent requests for CLI providers and ten for HTTP providers. An ambient parent setting is not inherited. This controls
concurrent LLM requests within each item, separately from the per-key worker scheduling
below. There is no model-specific cap or timeout change. Static assessments must omit
all AI controls. The explicit value is part of the assessment/configuration identity:
changing it creates a separate resume namespace, while returning to the same profile
reuses its completed results. Older manifests without this optional field still work.

AI assessments may supply `"modelTokenLimits": { "contextLength": 1048576,
"maxOutputTokens": 131072 }`. Both fields are required positive safe integers, with
`maxOutputTokens` no larger than `contextLength`. The operator must verify these values
against the selected model's supported limits. They are model metadata, not a request to
change the model, reasoning effort, response method or tool deadline. The field applies
to HTTP and agent-CLI profiles, including `adaptive-ssd/1`. Without an override, the K3
profile uses the 262,144-token context available on every eligible tier and a planning
output budget of 32,768 tokens.

For each attempt the helper writes a nonsecret `model-registry.json` inside that child's
isolated scratch directory, containing only the exact selected model and these limits.
It passes the generated absolute path through upstream `SKILLSPECTOR_MODEL_REGISTRY`;
caller registry paths are not accepted, and ambient registry settings are not inherited.
The file is local attempt evidence, excluded from candidate archives. Omitting the
control uses the selected model's known registry limits and preserves the existing
configuration identity. For an uncataloged model or deployment alias, provide both
values so Scan can start inference.
Supplying or changing either limit creates a distinct configuration; completed results
are reused only when returning to the same profile. Static assessments reject it.

SkillSpector budgets input at 75% of context and output at the smaller of 25% of context
and `maxOutputTokens`, using integer truncation. The example gives an input budget of
786432 tokens and an output budget of 131072 tokens. A context of 32768 and output cap
of 16384 instead yields an output budget of 8192. Raising these limits may let the
provider generate more output and increase output-token cost; it does not reserve or
guarantee that output. For DeepSeek, verify current context/output capabilities with
the [model metadata](https://api-docs.deepseek.com/api/list-models/) and
[chat-completion controls](https://api-docs.deepseek.com/api/create-chat-completion/).
On the official DeepSeek HTTPS endpoint, Scan sends the selected output budget as
`max_tokens`. Other OpenAI-compatible endpoints retain their adapter's wire format.

### Local validation, parallel scan and resume

Install the reviewed scanner tarball in a fresh consumer with scripts disabled. The
helper checks every installed package file against that exact tarball before importing
only its public host/read/contracts modules. Use a supported Node version; no global
runtime or provider configuration changes are required.

```sh
node tools/publisher/prepared.mjs validate manifest.json "$MANIFEST_SHA" content consumer scanner.tgz
node tools/publisher/prepared.mjs scan manifest.json "$MANIFEST_SHA" content consumer scanner.tgz state 6
```

`scan` returns a new immutable receipt path/hash and completed, reused, pending, unique-key
and reference counts. Keep that receipt and its state directory. A static fallback in an AI
profile, a failed/cancelled analysis or partial coverage stays visible but cannot become
eligible publishing evidence. A clean risk label or process exit alone is insufficient.
Requested tools must have completed or be explicitly not applicable. In an AI profile the
primary AI tool must have actually run in AI mode with the selected provider/model (and, for
the Claude CLI, effort and client) and complete coverage; in a static profile it must have run
in static mode with complete coverage.
All risk labels are accepted; this is an evidence-completeness policy, not a risk gate.

Incomplete or failed results retain available unsigned host diagnostic `notes` in local
attempt receipts, checkpoints and execution receipts. The helper redacts the configured
credential value before recording notes, replaces control characters with spaces and
bounds them to 32 distinct notes of 4096 characters each. Notes explain partial outcomes;
they do not affect summaries, scores, eligibility or cryptographic trust. They are not
included in the completed-output candidate archive. Older records without notes remain
valid. Worker stderr is not persisted as a diagnostic log.

#### Diagnose coverage before retrying

When the goal is to close an incomplete AI assessment, first run the static profile on
the same captured bytes with the candidate scanner. If it reproduces a hard inspection
gap, resolve that gap before retrying AI. A successful static replay establishes static
coverage only. For a cost-sensitive retry, measure representative detector requests and
prompt volume offline, and check that live request counts and batch widths will be
observable before spending quota. Model limits bound a group; they do not bound the
total requests or input volume for an item.

Read the verified summary and the matching receipt entry together. The tool results,
`coverage`, `reason`, `notAnalysed` and available diagnostic notes measure different
things. For example, an unrouted text file can be checked for secrets and still be listed
in `notAnalysed`, independently of whether the routed checks completed. SkillSpector's
diagnostic line is bounded to eight details, so it cannot establish that adjacent causes
are absent.

| Observation | Recovery decision |
| --- | --- |
| `reference_missing` | Verify the referenced path against the exact prepared input. Correct a genuinely omitted companion through the owning source or declaration, then prepare the resulting key. A reference-only advisory stays visible when the analyzer confirms completeness or exact accounting attributes the remaining omissions to the disabled dependency OSV lookup with its recorded zero-second limit. |
| `static_parse_limit`, referenced content left uninspected, or degraded inspection | Reproduce using the same verified analyzer and bytes in static mode. A source correction or verified parser improvement can change the outcome. Repeating AI alone cannot repair a persistent static inspection gap. |
| Tool `not-run` with reason `timeout` | The published deadline is ten minutes for one tool on one item. Check static work, routed input, host pressure and the effective analyzer/provider configuration first. A timeout cannot establish which provider requests started, completed or incurred usage. |
| Provider, model or AI inspection failure | Confirm the provider, client version where applicable, model, effort and assessment profile. Reproduce configuration and batching capability offline where possible. A recovered static result is evidence about static inspection only. |

Record the provider, model and assessment profile when estimating a retry. Concurrency and model context length alone cannot establish request counts or account usage. Retain verified complete observations and select only the exact items that need recovery.

Concurrency defaults to available CPU parallelism. Optional arguments after concurrency
are estimated MiB per worker (default 512) and memory reserve MiB (default the larger
of 1 GiB or 10% of physical RAM). These are configurable scheduling estimates, not model
limits or campaign-size caps. Each launch immediately reserves its estimate because RSS
allocation lags process creation; subsequent waves recheck available memory. If memory
cannot support another worker and none is active, the helper returns explicit pending
keys for resume instead of waiting indefinitely. Measure the pilot's actual memory and
throughput before choosing campaign concurrency; leave other active work responsive.
Outstanding worker estimates remain reserved across refill waves, bounded by the
pool's observed starting headroom and current free memory. Taking the smaller budget
avoids subtracting all resident memory twice. A fully drained pool refreshes its headroom.

Each distinct key uses a separate output/temp root. Finished entries are atomically
checkpointed, with file data flushed before index replacement. Repeating the command,
expanding a pilot into the full manifest or changing labels reuses successful unchanged
keys after revalidating their summary, SARIF, configuration and actual inventory. Changed
bytes/paths/modes invalidate the affected key; changed scanner/assessment configuration
uses a separate cache namespace. Failed attempts remain in immutable attempt directories
and may be retried; successful output is never overwritten. An active invocation owns
the cache lock; a crashed same-host owner can be recovered after its PID is gone.

If a checkpoint write was interrupted, preserve its temporary files and attempt output.
Before another paid attempt, recover and revalidate any completed records without
starting analyzers or making provider requests:

```sh
node tools/publisher/prepared.mjs recover manifest.json "$MANIFEST_SHA" content consumer scanner.tgz state
```

`recover` reports recovered keys and ignored incomplete temporary JSON. Valid completed
temporary records are merged into the canonical checkpoint; conflicts are refused and
all evidence remains. Normal `scan` also performs this recovery before deciding which
keys need work.
Workers also persist an atomic per-attempt result receipt before sending the parent its
completion message. Recovery validates these receipts before scheduling paid work. For
older orphan attempts lacking a receipt, it can validate the original request's exact
configuration and actual completed summary/SARIF against the current inventory; missing
or partial output never establishes success. Unavailable legacy timing stays unknown.

For two machines, scan disjoint subset manifests with the same scanner/assessment and
copy each immutable receipt **with its relative output tree**, rather than copying a live
checkpoint index. Use the full manifest and local source inventory to validate a merge:

```sh
# receipts.json is an explicit JSON array of copied receipt file paths.
node tools/publisher/prepared.mjs merge manifest.json "$MANIFEST_SHA" content consumer scanner.tgz merged-state receipts.json
node tools/publisher/prepared.mjs scan manifest.json "$MANIFEST_SHA" content consumer scanner.tgz merged-state 6
```

The final command reuses merged complete keys and scans only missing keys. Conflicting
complete outputs for the same key are refused and retained for review. No shared service,
credential transfer or mutable cross-machine index is introduced.

### Output-only archive and checked hosted intake

Export all requested keys, or name an explicit JSON array of selected keys for a smaller
batch. No key is silently omitted:

```sh
node tools/publisher/prepared.mjs archive manifest.json "$MANIFEST_SHA" content consumer scanner.tgz "$RECEIPT_PATH" candidate.tar selected-keys.json
```

The returned archive, batch-manifest and receipt hashes bind the exact transfer. The
batch manifest retains the parent manifest digest. Export rechecks actual local bytes
with public `scanKeyOf` and portable `matchScan`, every summary, every referenced SARIF
digest and findings, the installed scanner and evidence eligibility. Its archive contains only
that manifest, an unsigned `execution: local` receipt, the scanner tarball and selected
summary/SARIF bytes. It excludes source content, worker requests, cache histories and
credentials. Import accepts the helper's bounded regular-file-only ustar transport;
links, special entries, duplicate/traversing paths, corrupted headers and unexpected
files are refused before any output is eligible.

The existing 512 MiB candidate archive bound remains. Scan's input limits apply per
item/request (500 MiB, 50,000 files), and its ten-minute per-tool/item limit remains.
The candidate job remains 120 minutes and signing jobs 30 minutes. Select explicit
smaller batches as needed for bytes and measured signing time; there is no new fixed
campaign or key-count cap. The legacy sources route retains its 64-descriptor limit.

The operator selects an already-authorized transfer location; this software creates no
release, tag or store. Hash and review this import descriptor, then provide its exact
bytes as the candidate workflow's `prepared_json` input and set the reviewed
`SCAN_REPORT_PREPARED_SHA256` variable under separate operation authority:

```json
{
  "format": "aih-scan-prepared-import/1",
  "url": "https://artifacts.example.com/immutable/candidate.tar",
  "allowedHosts": ["artifacts.example.com"],
  "archiveSha256": "<reviewed archive digest>",
  "manifestSha256": "<exported batch manifest digest>",
  "receiptSha256": "<exported receipt digest>"
}
```

The terminal-URL form retains its explicit host policy: public HTTPS, no URL
credentials/query parameters, public DNS answers pinned for the connection, and no
redirects. For a public GitHub Release asset, use this alternative transport in the
same `aih-scan-prepared-import/1` descriptor, replacing `url` and `allowedHosts`:

```json
"githubRelease": {
  "repository": "samartomar/aih-scan",
  "assetId": 123456789,
  "name": "reviewed-candidate.tar"
}
```

Select the actual immutable asset ID and name after separately authorized publication;
these example values are not an existing ingress. Intake fetches public asset metadata
without authentication, checks the repository-bound API URL, ID, name, uploaded state
and size, and accepts only the matching repository's GitHub browser-download path. It
allows at most one redirect to the GitHub release-assets download endpoint. The terminal
signed URL may contain a query, but URL credentials, fragments, non-443 ports, other
hosts, further redirects and private DNS answers remain refused. No token or cookie is
sent on any hop, and transport errors omit supplied URL/query values. The reviewed
archive digest and metadata size must match the downloaded bytes. `prepared-download
<descriptor.json> <descriptor-sha256> <new-archive-path>` on `candidate.mjs` supports a
read-only acquisition preflight without importing or executing archive code.

Both forms keep the existing 512 MiB archive bound and two-minute transport budget.
The budget now covers the whole acquisition, including metadata and the redirect,
so additional requests cannot each restart the existing timeout. Metadata is bounded
to 64 KiB. No location or private ingress policy is chosen automatically. The workflow
accepts exactly one of `sources_json` and `prepared_json`; its prepared branch validates
output bytes without provisioning analyzers or repeating paid inference.

Hosted validation checks the reviewed per-file path/mode/hash inventory against each
summary, expected key, scanner/configuration and parsed SARIF. It cannot reconstruct
untransferred source bytes or independently establish that local inference occurred.
The unsigned receipt says `local`; owner review authorizes signing those bytes. It is
never a claim of hosted analysis, a cryptographic signature or consumer trust by itself.
The signing workflow revalidates the entire prepared inventory and evidence eligibility before
selection. The existing candidate workflow/run/artifact custody checks, reviewed selection
digest, protected signer environment and default trusted signer identity remain in force.

## Signing: `scan-report-publisher.yml`

Dispatched with the reviewed candidate run ID and the SHA-256 of the reviewed selection
listing (`<sha256>  <path>` per `summary.json`, in path order). Repository variables name
the reviewed head, candidate run, artifact ID and digest, and selection digest; the
inputs must equal them.

1. `bounded-candidate` (read-only) first builds and packs the exact CLI, installs its
   runtime dependencies in a fresh folder from the committed lockfile
   (`npm ci --omit=dev --ignore-scripts`), unpacks the CLI there and uploads that runtime
   with its SHA-256 as a job output, all before any candidate step. It then checks the
   candidate run's custody with `tools/publisher/candidate.mjs check-run` (one successful
   first-attempt `workflow_dispatch` run of the candidate workflow on the reviewed main
   head, by `samartomar`, with exactly the selected unexpired artifact and digest),
   downloads the artifact by ID with digest checking, selects the reviewed summaries
   (`candidate.mjs select`, which refuses links, a changed summary or a different listing)
   and reads each with `aih-scan read`.
2. `signer` runs in the protected `scan-report-signing-prod` environment with
   `id-token: write` only. It checks out, installs and builds nothing: it checks the
   runtime's SHA-256 against the read-only job's output and runs only that CLI. It
   rechecks the listing and every summary digest, signs each
   summary with `aih-scan sign` (GitHub Actions OIDC, public Fulcio and Rekor), and
   verifies each bundle with `aih-scan verify` under the default signers, requiring
   `verified`, a trusted signer and no withdrawal. It uploads `scan-report-signed`: the
   summaries, their SARIF and `summary.sigstore` bundles (`aih-sigstore-keyless/1`
   messageSignature bundles).

Both jobs admit only public repository visibility, repository `samartomar/aih-scan`
(ID `1336836161`, owner ID `9993940`), `refs/heads/main`, this workflow ref, the reviewed
head, dispatcher and triggering actor `samartomar`, and the first run attempt. The sole
maintainer initiates the run and supplies the protected environment approval, including
for their own run; this does not establish independent human review. External actions are
pinned to full commits.

## Owner-controlled operations

Choosing sources, revisions and the store layout, setting the repository variables,
protecting the signing environment, dispatching either workflow and publishing signed
results are operations the owner authorizes separately. Clear the reviewed-head variable
after an authorized operation reaches a terminal state. Withdrawals
(`aih-scan-withdrawn/1`) are signed the same way with `aih-scan sign <withdrawn.json>`.

### Explicit static parser build

For a prepared static assessment using the
[reviewed parser wheel](../tools/analyzers/skillspector/maintenance/static/README.md),
set `AIH_SCAN_SKILLSPECTOR` and `AIH_SCAN_SKILLSPECTOR_STATIC_WHEEL` to the absolute
environment entry point and wheel paths. In the manifest, the static assessment can
add a `skillspector` object with the two exact fields `version` and `wheelSha256`
from `tools/analyzers/skillspector/maintenance/static/artifact.json`.

The helper verifies those pins and the installed analyzer before starting or reusing
work. Each selected summary must record the requested static analyzer version,
complete coverage and the reviewed input file inventory. The protected candidate
and publisher steps verify the exact manifest, installed Scan package, analyzer pin
carried by that package, and original summaries and SARIF. Only the output-only
archive enters that process. The wheel and the original local source files stay with
the operator. The signed summary records the analyzer version, and the reviewed
candidate carries the wheel digest and receipt binding. Omit the object to use the
standard 2.13.7 profile. TP4 and other AI controls are rejected in this static profile.

### Explicit TP4 maintenance capacity and producer transition

For the separately identified maintenance build described in
`tools/analyzers/skillspector/maintenance/README.md`, an AI assessment may add:

```json
"skillspector": {
  "version": "<exact version from maintenance/artifact.json>",
  "wheelSha256": "<exact wheelSha256 from maintenance/artifact.json>",
  "tp4": { "maxFiles": 512, "maxFindings": 512, "maxBatches": 512 }
}
```

The version/wheel hash must match the reviewed artifact; capacities are positive integers
up to 4096. Values above are examples, not guaranteed campaign sizing. Plan all relevant
sources, chunks and bytes before requesting paid inference. No control is inferred from
ambient variables; all three capacities and exact artifact identity are explicit and
bound into the resume configuration. The helper requires the exact reviewed wheel in
`AIH_SCAN_SKILLSPECTOR_WHEEL`, verifies its installed payload before running/reusing a
maintenance profile, and forwards only requested settings. Standard upstream 2.13.7 cannot
satisfy this profile: it retains a fixed finding capacity and does not emit the
maintenance resolved-capacity metadata. The previous 2.13.3 and 2.13.4 maintenance wheels
are not accepted for a new profile. Omitted profiles retain upstream defaults and existing
configuration identities. Incomplete results, findings/scoring and ten-minute tool deadline
are unchanged.

Completed outputs from an older producer remain unchanged and readable under their original
scanner/analyzer/configuration identities. The default workflows still use the scanner built
from the reviewed current main head. To validate one historical producer, supply the
same optional `producer_json` input to **both** workflows and independently set
`SCAN_REPORT_PRODUCER_SHA256` to the SHA-256 of those exact JSON bytes. Omit both the
input and variable for the original single-producer behavior. Each candidate run uses
one context; separate producers or assessment profiles retain separate runs and
selections. Do not merge cross-producer checkpoints or rewrite older results.

A reviewed context is:

```json
{
  "format": "aih-scan-producer-context/1",
  "sourceCommit": "<full reviewed Scan source commit>",
  "packageSha256": "<exact reviewed npm tarball digest>",
  "lockSha256": "<exact source package-lock.json digest>",
  "archiveSha256": "<output-only archive digest>",
  "manifestSha256": "<exported batch manifest digest>",
  "receiptSha256": "<exported receipt digest>",
  "selectionSha256": "<reviewed summary listing digest>"
}
```

This independent approval authorizes validation code from that exact source context;
it is not an allowlist of candidate-supplied executable packages. Before downloading a
candidate, each workflow checks out the named commit from this fixed Scan repository,
checks its origin, exact clean HEAD and lock digest, then builds and packs it in isolation.
A private home/cache and empty user/global npm and Git configurations keep ambient
GitHub, OIDC, SSH, provider credentials and Node loaders out of producer commands.
Dependencies use `npm ci --ignore-scripts`; only the reviewed `build` script runs, with
pre/post lifecycle hooks disabled. The built tarball must exactly match the reviewed
package digest. Runtime dependencies are installed from the same reviewed lock with
scripts disabled, and the installed package and dependency file inventory is sealed
and checked again before validation. A nonreproducible or mismatched package stops
intake; the helper does not substitute the archive's scanner.

Candidate import retains the independently approved context digest as provenance.
Publisher prepared-check requires the independently supplied matching context and
rechecks the original archive/manifest/receipt/package/selection identities, every
installed package file, dependency inventory, configuration and complete evidence.
Unknown contexts, changed runtime files or metadata swapped between phases fail closed.
The archived scanner is compared with the independent installed package before any of
its public modules are imported. The publisher always prepares the **current reviewed
main CLI** separately for reading, signing and default-signer verification. Historical
producer code never enters the protected OIDC signer job. The reviewed-main, maintainer,
first-attempt, candidate-run/artifact-digest, selection and environment checks remain.

This software does not upload assets, choose a result store, enable or dispatch
workflows, change protections, sign reports or establish trusted admission. Source,
package, transport and report selections still require concrete operator review;
production activation and protected human signing approval remain separately authorized.
