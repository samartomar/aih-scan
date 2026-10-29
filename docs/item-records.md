# Item records

`recordItems({ artifact, items, severityProfile })`, `verifyItemRecord(record,
artifact, item, severityProfile)`, `readItemRecord(value)` and
`itemIdentity(value)` are portable exports of `@aihq/scan/read`. `artifact` is a
result of `readArtifact` or `readReport`; Scan revalidates it, including its Scan
ID, before deriving coverage. These operations perform no host access or
authentication.

## Item descriptor

```ts
{
  frameworkId: string, itemId: string,
  contentSha256: string, behaviourSha256: string,
  kind: string, payload: Json, requirements: Json, dependencies: Json,
  materials: {
    materialId: string,
    relPath: string,       // relative to the item; the path the content lines name
    capturePath?: string,  // path in the artifact's capture; defaults to relPath
    sha256: string, byteLength: number,
    executable: true | false | "unknown",
    role: "content" | "behaviour"
  }[]
}
```

Material IDs, `relPath` values and capture paths must be unique. `#payload` is
reserved. Exactly one material is the behaviour file. Tool identifiers,
installation locations and support claims are outside this interface.

Scan recomputes the item's identity from its own fields and refuses any
difference. The Catalog contract defines this identity:

- `contentSha256` is SHA-256 over one UTF-8 line `relPath\tsha256\n` per
  content material, sorted bytewise.
- `behaviourSha256` is SHA-256 over the canonical JSON (keys sorted, no
  whitespace) of `{ kind, payload, requirements, dependencies, materials:
  <the content lines>, executable: { relPath: executable } }`.
- The behaviour file's bytes are the canonical JSON of the same value without
  `materials`, plus LF.

A mismatch returns `{ coverage: "invalid", diagnostics }`. A behaviour file that
differs from the declared fields gives `behaviour-mismatch`; differing hashes
give `item-identity-mismatch`. `itemIdentity` exposes this computation.

## Record

A record is `urn:aihq:scan:item-record:1.0.0`, exactly as the contract
publishes it:

```ts
{
  scanId, createdAt, evidenceKey,
  subject: { frameworkId, itemId, contentSha256, behaviourSha256 },
  authenticity: "unchecked",
  materials: { materialId, relPath, sha256, byteLength, executable: boolean, captured: boolean }[],
  completion: "complete" | "partial",
  coverage: "matched" | "mismatched" | "unavailable" | "invalid",
  severityProfile: "<id>@sha256:<SHA-256 of the profile's canonical JSON>",
  detectors: {
    id, version, outcome, coverage, exclusions: string[],
    findings: { error, warning, note, unavailable },
    suppressed: { rule, count, reason }[]
  }[]
}
```

### The `#payload` pseudo-material

The materials end with a pseudo-material for the payload: `{ materialId:
"#payload", relPath: "#payload", sha256, byteLength, executable: false, captured }`.
Its digest and length are those of the payload's canonical JSON.

The behaviour file embeds that JSON, and its bytes were checked against the
declared fields. So the payload is captured and scanned exactly when the
behaviour file is. A capture of a recipe or source file alone cannot cover an MCP
server definition or a hook command.

### Coverage

| Material state | Item `coverage` |
| --- | --- |
| Not captured at its capture path, or other bytes or length | `mismatched` |
| Declared `true`/`false`, captured as the other bit | `mismatched` |
| Capture holds no bit (profile 1, Windows) | `unavailable` |
| Declared `unknown`, capture holds a bit | that bit is recorded |
| Every material and `#payload` match | `matched` |

`captured` says whether the capture holds the material's exact bytes. A `matched`
record's `executable` is always the bit the capture holds. Otherwise it is the
declared bit, or `false` when none is declared, and the coverage says that no bit
was established. A record is never `matched` for an item without materials.

Each requested detector appears with its `id` and with `version` from its
observation inputs (`unavailable` without observations). Its `coverage` is:

- `unavailable`, with exclusion `detector-<outcome>`, when the detector did not
  succeed;
- the item's own coverage, with its reasons, when the item is not `matched`;
- `matched` when successful observations of that detector cover every material
  with matching bytes and modes;
- otherwise `unavailable`, with a `not-covered` exclusion naming the materials.

### Findings and evidence key

Findings belong to the item only when both their location path and file digest
match one of its materials; others stay at release level. The severity profile
maps native levels to the four counts; unmapped levels count as `unavailable`.
Its suppressions are counted by rule and reason, never dropped.

`evidenceKey` is SHA-256 over the canonical JSON of `{ contentSha256,
behaviourSha256, detectors: [{ id, version, rulesSha256, profileSha256 }] }`,
sorted by `id`. It is the same for a replay or an independent re-scan. It is a
grouping key, never proof.

## Verification and reading

`verifyItemRecord` re-derives the record from the artifact for the item, under
the named severity profile, and compares all three:

- `not-covered`: the artifact lacks the item's exact bytes, the record's subject
  differs (a relabelled record or a different `behaviourSha256`), or its
  materials list other bytes;
- `differs`: any other field differs, or the record is malformed;
- `same`: the record is exactly equal.

`readItemRecord` reads a stored record. A record may carry `schema`, but any
schema other than this one is refused as `{ code: "SCHEMA_UNSUPPORTED", path:
"$.schema", encountered, supported }`. A field the contract does not define is
refused as `unknown-field`, with the field's JSON path.

All inputs are snapshotted before asynchronous work. Batch limits match the
coverage reader:

| Limit | Value |
| --- | --- |
| Items | 4096 |
| Materials per item | 10000 |
| Material references in total | 50000 |
| Request bytes | 16 MiB |
| Response bytes | 32 MiB |
| Observation associations | 100000 |
| Classification work units | 10000000 |

The schema and golden fixtures are exported at
`@aihq/scan/schemas/item-record/1.0.0.json` and
`@aihq/scan/schemas/item-record/1.0.0.fixtures.json`. The fixtures are real Catalog
release 1.7 items with their exact bytes. They include the fixture's
`severityProfile`; see [fixture provenance and replay](contract-fixtures.md).
