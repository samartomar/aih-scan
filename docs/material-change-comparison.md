# Compare declared material inventories

The Unreleased `@aihq/scan/host` API compares installation material independently
of scan findings. `compareMaterialInventories` accepts caller-declared inventories;
it does not scan a source, read report files, authenticate a producer or post issues.
Use Node `>=24.15.0 <25`.

```ts
import { compareMaterialInventories } from "@aihq/scan/host";
import type { MaterialInventory } from "@aihq/scan/contracts";

const after: MaterialInventory = {
  scanId: `scan:sha256:${"b".repeat(64)}`,
  projection: "aih-material-v1",
  complete: true,
  items: [{
    itemId: "skills/review",
    paths: [{ path: "skills/review/SKILL.md", sha256: "1".repeat(64) }],
    metadata: { install: "copy" },
  }],
};
const result = await compareMaterialInventories({
  sourceId: "https://github.com/example/skills",
  before: null,
  after,
});
if (result.status === "compared") {
  // Preserve this summary; delivery is a separate explicitly enabled call.
  console.log(result.materialChange);
} else {
  console.error(result.diagnostics);
}
```

The sample digests are fixture placeholders. Inventory producers supply the exact
published bytes' SHA-256 hashes, owner-declared installation metadata and Scan IDs.
The API validates declarations; it does not establish their truth or authenticity.

`sourceId` is an already canonical credential-free HTTPS Git repository URL with a
nonempty source-relative repository path, no query, fragment, trailing slash or
`.git` suffix. Canonical spelling uses the URL's serialized host and port spelling;
the API rejects alternatives rather than merging them silently. For a local
source, explicitly assign `local:<label>`, where the label starts with an ASCII
letter or digit and continues with up to 249 letters, digits, dots, underscores or
hyphens. Keep that label stable across machines. A filesystem path is never a
source identity.

Each item declares a stable NFC source-relative POSIX `itemId`, unique published
paths with lowercase 64-character content hashes, and explicit `metadata` JSON.
Paths and item IDs cannot traverse, contain a backslash, drive prefix, control
character or `%?#:`. Empty `paths` is valid for a metadata-only item. The material
owner decides which installation fields belong in metadata. Findings, severity,
counts, scan timestamps, Scan IDs, source-wide commits and delivery details belong
outside that declaration; the API does not infer installation metadata from reports.
Unknown item or inventory fields are refused.

The only accepted projection is `aih-material-v1`. For each item the digest is
`SHA256(C({paths:[{path,sha256}],metadata}))`, where published paths are sorted by
JavaScript UTF-16 code-unit order and `C` is Scan's existing canonical JSON profile.
Metadata object keys are canonicalized; metadata array order remains significant.
Changing bytes or declared metadata changes the digest even when counts stay equal.
Changing only a report's findings or Scan ID leaves the material digest unchanged.

With `before:null`, known after items produce reliable initial additions, including
items in a partial inventory. With an existing baseline, an addition requires
complete before membership. A removal requires both inventories to be complete.
An item present on both sides can still be compared in partial inventories.
Declare unavailable item material in `uncomparedItemIds`; those items produce no
change. This list can include an ID whose item is omitted. `complete` declares
complete membership accounting; it does not override item-specific uncertainty.
Missing items whose absence is unproven are added to the output's uncompared list.

The result carries schema `urn:aihq:scan:material-change:1.0.0`, stable source and
projection identities, nullable `beforeScanId`, `afterScanId`, completeness and
sorted uncompared IDs, sorted additions/removals/modifications, exact before/after
digests and diagnostic limitations. Modified digests must both exist and differ.
Changes and uncompared IDs cannot overlap. The summary is an immutable snapshot.

The schema is exported at `@aihq/scan/schemas/material-change/1.0.0.json` and listed
in portable `contractSupport`. Runtime validation additionally enforces canonical
URL spelling, NFC/UTF-8 rules, ordering, side relationships and digest inequality.
All input values must be plain strict JSON, using nonnegative safe integer numbers.
Accessor, symbol, hidden and extra properties, malformed Unicode, sparse arrays and
ambiguous identities are refused. Limits are 2 MiB canonical bytes and cumulative
text bytes, 100,000 JSON nodes, nesting depth 32, 4,096 items/changes/uncompared IDs
and 4,096 paths per item. Invalid input returns safe diagnostics without effects.

For each change, the [explicit delivery API](material-change-handoff.md) derives
`change:sha256:` plus the hash of canonical
`{domain:"aih.scan.material-change.v1",sourceId,materialProjection,itemId,kind,beforeSha256,afterSha256}`.
Its item key hashes canonical `{domain:"aih.scan.material-item.v1",sourceId,itemId}`.
Compared Scan IDs and diagnostics remain context outside both identities.
