# Frozen Catalog input captures

Unreleased maintainer tooling for samartomar/aih-scan#114 adds one explicitly
selected input mode to the existing refresh producer. It assesses frozen Catalog
inventory and actual recipe/material bytes in their exact package-relative
namespace. The original seven-source `refresh-input:1.0.0` and
`refresh-manifest:1.0.0` remain unchanged. Do not mix modes in one batch.

## Prepare data without execution

First prepare and check Catalog content with Catalog's supported producer and
freeze C using `@aihq/catalog/reader.createContentInventory`. Stage its exact bytes
(including LF), recipes and materials under an explicit package root. This is
content preparation, before baseline qualification or final candidate packing.

From the reviewed Scan checkout, on Node `>=24.15 <25`:

```sh
node tools/refresh/catalog-capture.mjs /absolute/staged-package \
  release/content-inventory.json INVENTORY_SHA256 /absolute/new/catalog-capture.json
```

The helper exclusively creates canonical UTF-8 JSON and prints its SHA-256,
length and deterministic tag. Rerunning it against unchanged bytes produces the
same bytes. It reads bounded regular files only, rejects linked parent directories
and hard links, checks every declared file's length/digest, and loads no staged
code. Root and output are explicit local preparation arguments, never remote
acquisition input. Never use a Scan source checkout as a capture target.

The data envelope has exactly `schema`, `inventory` and `files`. Schema is
`urn:aihq:scan:catalog-capture:1.0.0`. `inventory` has `path`, `sha256`,
`byteLength`. Each sorted `files` row has exactly those three fields plus canonical
`bytesBase64`. Files are exactly the inventory plus every package member its
items declare (below); shared identical descriptors appear once. Missing/extra
files and conflicting declarations refuse. Binary material is preserved. No links,
executable flags, extraction instructions, scripts or paths to acquire additional
files are supported.

Inventory must retain Catalog's canonical JSON plus LF, package name
`@aihq/catalog`, no `baseline`, and one of these Catalog document-format pairs:

| Release document | Content inventory | Projection |
| --- | --- | --- |
| `urn:aihq:catalog:release:1.5.0` | `urn:aihq:catalog:content-inventory:1.0.0` | `urn:aihq:catalog:release-content:1.0.0` |
| `urn:aihq:catalog:release:1.7.0` | `urn:aihq:catalog:content-inventory:1.2.0` | `urn:aihq:catalog:release-content:1.2.0` |

Mismatched pairs, release 1.6.0 (inventory 1.1.0) and other formats refuse.
These are Catalog document schemas. They are distinct from the capture envelope
schema, the upstream source identities recorded inside the inventory, and the
Scan assessment and report versions.

Release 1.5.0 members are each item's `recipe` and `materials[].path`. Release
1.7.0 members are each item's single `recipe` or every entry of its `recipes`
transition map (exactly one of the two), plus every material by its package path:
legacy `path` or extended `packagePath`, never both. Extended members include the
item's behaviour file. A map entry may name only that item's content materials.
Cross-release dependency manifests and release-level sets are not package
members and are not captured. The helper checks byte closure, not Catalog's
complete semantic authoring contract; Catalog's reader and baseline gate remain
authoritative.

## Select immutable input transport

Publish the data envelope as the sole asset `catalog-capture.json` on an immutable,
published GitHub Release in `samartomar/aih-catalog`. Its tag must be
`catalog-capture-<envelope SHA256>`, a lightweight tag pointing directly to the
reviewed full Catalog source commit. Create the Release with `target_commitish`
set to that same full commit. Record its numeric Release ID and asset ID, exact
asset SHA-256 and length. A draft, mutable release, annotated/mismatched tag,
ambiguous asset collection or missing service digest refuses.

This Release is an **input capture**, not a qualified Catalog release candidate,
npm release, baseline, or safety claim. It needs no prior Scan assessment. Input
publication is an additional external operation requiring separate authorization;
this tooling never creates tags, releases or assets or changes immutable-release
settings. Later updates repeat the same preparation command and one input upload,
then explicitly select the new IDs/digest. Unchanged captures can reuse their
immutable input. No per-family source adapter or hand-authored file list is needed.

This transport reuses the existing bounded GitHub release-asset downloader and
numeric selectors. The existing Git input captures a whole Git tree; changing
its ref cannot represent a staged Catalog inventory and material namespace.
The generic local path is not a durable hosted input. An unrestricted URL/path
or uploaded executable is not added. Input data is not imported by the signer.

## Freeze and run through the maintained publisher

Use the ordinary [freeze/run commands](../tools/refresh/README.md) and
[production operation](production-refresh.md), with this input schema:

```json
{
  "schema": "urn:aihq:scan:catalog-capture-input:1.0.0",
  "scannerSourceCommit": "<reviewed full Scan commit>",
  "runtime": {"node":"v24.15.0","platform":"linux","architecture":"x64"},
  "profile": "independent-linux-v1",
  "limits": {"<all nine ordinary public limits>":0},
  "targets": [{
    "repository":"samartomar/aih-catalog",
    "ref":"<reviewed full Catalog source commit>",
    "selection":{"paths":"all","excludedPaths":[]},
    "trustLint":{"internalScopes":[],"mcpConfigPaths":[]},
    "capture":{
      "releaseId":"<positive numeric ID>",
      "assetId":"<positive numeric ID>",
      "sha256":"<envelope SHA256>",
      "byteLength":12345,
      "inventory":{"path":"release/content-inventory.json","sha256":"<inventory SHA256>","byteLength":1234}
    }
  }]
}
```

Replace placeholders and supply all nine limits from the ordinary contract;
the illustrative limits object above is not dispatchable. IDs are decimal strings,
digests lowercase 64-hex, commits lowercase 40-hex. Only this repository and one
target are accepted. Moving refs, alternate URLs/paths and exclusions refuse.

The capture envelope is at most 64 MiB encoded, including base64/descriptor
overhead. Inventory is at most 16 MiB/depth 32 and 10,000 items. Public source
entry/byte ceilings also apply, including containing directories. Control input
and frozen manifest are each at most 2 MiB. Relative paths are at most 4,096
characters and must be NFC; traversal, root `.git` components, control characters,
backslashes, reserved Windows names, trailing dot/space, file/directory conflicts
and case aliases refuse. Directory and executable mode identity is not supplied:
files are materialized as private regular data files with inferred directories.

Freeze resolves canonical repository identity and acquires/checks the selected
release, tag, sole asset and original bytes. Its
`urn:aihq:scan:catalog-capture-manifest:1.0.0` retains the same manifest fields as
the seven-source mode, with one Catalog target plus `capture`. This extends the
selector with sorted `files` descriptors (no encoded material). Its batch digest
binds all fields. A manifest exceeding 2 MiB refuses at freeze.

Run rechecks immutable input metadata and bytes before assessment/output creation,
creates an owned temporary data root and calls installed `runScan` with the
ordinary local capture request. It removes only that owned temporary root after
use. Artifacts have the existing report/artifact format and `source.kind: local`:
portable reports contain exact inventory/material capture identities, not a
fictional Git acquisition. The frozen manifest retains transport provenance
(Catalog repository/commit and release/asset IDs); the inventory itself carries
its original declared source provenance. Candidate and publication checks require
the report's entire file/directory capture to equal that frozen descriptor set.

Native, trust-lint, binding-gate and Semgrep retain their existing Linux profiles.
Cisco/SkillSpector unavailable rule material, Snyk outside-profile status and MCP
discovery limitations remain explicit. Every original requested detector terminal
outcome, timestamp, coverage/gap and annex survives candidate and publication
validation. Partial/all-failed assessments may be signed without becoming passes.
Cancellation retains a diagnostic/no-ID row and is not publication admission.
NONPUBLISHABLE Catalog originals use the existing separate failure-evidence path.

The same maintained workflow, reviewed-main admission, independent trust bytes,
signer identity and protected human approval apply. The signer receives only
detached statements and reviewed selection, not the capture or scanner code.
Exactly one target is signed in singleton capture mode; the seven-source mode
retains its seven targets. The separately selected
[independent capture batch mode](independent-captures.md) supports one to seven
keyed Catalog inventories through the same stages. Authentication still uses
independently selected trust.

## Delivery and runtime proof boundaries

`tests/refresh/operation.test.ts` installs a packed public Scan consumer and checks
capture matching/readability, original partial results, refused Semgrep coverage,
cancelled/no-ID work, input tampering, candidate checks, detached signing selection,
and publication assembly/authentication with a disposable **fixture** identity.
Deterministic boundary tests cover namespace, closure, resource and custody refusals.
A real Catalog release 1.7.0 inventory and its exact member bytes, copied from
public Catalog producer output, are fixtures under `tests/fixtures/catalog-capture-1.7/`.
The independent batch consumer captures that fixture next to release 1.5.0 inputs.
Portable Windows tests use labelled runtime/prerequisite boundaries; they do not
establish Linux execution or production signing.

Before actual Catalog baseline production, the maintainer must separately obtain:
the final checked frozen content and input capture publication authority; the
actual immutable input IDs/digest; reviewed Scan code on current main with exact
packed scanner/lock/installation identity; Linux x64 with the declared Node,
bwrap, uv and Python prerequisites; a bounded authorized freeze/run operation;
candidate/selection review; protected human signing approval; and independently
selected production trust plus installed-consumer authentication/baseline checks.
No workflow dispatch, trust mutation, signing, report publication or npm publication
is performed by implementation tests. Catalog's baseline gate must still validate
and bind the authentic artifact before qualifying and packing its final candidate.
