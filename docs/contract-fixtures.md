# Contract fixtures

Each supported Scan contract has a schema-adjacent JSON fixture export. These
are test data for consumers of the pinned Scan package. They add no evidence
format and make no authentication, native execution or production claims.

| Contract ID (`urn:aihq:scan:` prefix) | Version | Fixture export (`@aihq/scan/schemas/` prefix) | Accept | Refuse code |
| --- | --- | --- | --- | --- |
| `request:1.0.0` | 1.0.0 | `request/1.0.0.fixtures.json` | grill-me request | `invalid-input` |
| `run-result:1.0.0` | 1.0.0 | `run-result/1.0.0.fixtures.json` | recorded assessment | `schema-invalid` |
| `report:1.0.0` | 1.0.0 | `report/1.0.0.fixtures.json` | recorded report | `invalid-input` |
| `artifact:1.0.0` | 1.0.0 | `artifact/1.0.0.fixtures.json` | unsigned recorded artifact | `invalid-artifact` |
| `evidence-association:1.0.0` | 1.0.0 | `evidence-association/1.0.0.fixtures.json` | reference to recorded Scan ID | `schema-invalid` |
| `material-change:1.0.0` | 1.0.0 | `material-change/1.0.0.fixtures.json` | changed grill-me bytes | `invalid-input` |
| `detector-definition:1.0.0` | 1.0.0 | `detector-definition/1.0.0.fixtures.json` | supplied disallow-eval definition | `invalid-input` |

Every fixture document carries `contractId`, `contractVersion`, `provenance` and
`cases`. Each case has `name`, `value`, `expectation` (`accept` or `refuse`) and
`code` (null for acceptance). `value` is the contract document to validate; the
wrapper is fixture metadata, not a Scan format. `schema-invalid` labels a failed
JSON Schema validation in the test harness, not a product diagnostic. The run
result and evidence association have no standalone public reader; test them
against their exported schemas. Other refusal codes are checked through the
corresponding public operation as well as schema validation.

The artifact's invalid case carries `validation: "reader"`: its corrupt annex is
structurally valid JSON but must fail the public artifact reader's byte bindings.
Schema validation alone cannot establish those bindings.

## Data and replay

The grill-me stress data derives from
[`mattpocock/skills` at d81f3a183412e71a5b1e84ca21bc1a35eea03a60](https://github.com/mattpocock/skills/tree/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/productivity/grill-me).
The request fixture includes the exact SKILL.md, agents/openai.yaml and MIT
LICENSE bytes, with source paths, lengths and SHA-256 digests. The report,
assessment and unsigned artifact preserve the recorded capture on October 23,
2026. The material-change fixture compares that capture with the stress variant
that changes SKILL.md's description while retaining its name. Its `comparison`
field contains the exact input inventories used to produce the valid summary.
The detector-definition fixture uses Scan's existing public
[`examples/detector-definitions`](../examples/detector-definitions) example and
includes its exact rules in `rulesBase64`.

To replay a request, decode its `materials` into a fresh temporary directory and
replace only `source.path` (`/fixtures/grill-me`) with that directory's absolute
path. Never scan a source checkout. Public CI checks material hashes and verifies
the resulting capture matches the recorded capture. Only the in-process native
and trust-lint detectors run. The supplied Semgrep definition is admitted with
its exact rules, but its native runtime is not invoked by this proof.

Load fixture data by its public specifier, for example:

```js
import { readFileSync } from "node:fs";
const fixture = JSON.parse(readFileSync(new URL(import.meta.resolve(
  "@aihq/scan/schemas/report/1.0.0.fixtures.json"
)), "utf8"));
```

Run `npm test -- tests/package-install-v2.test.ts` for the outside-workspace
packed-install proof. It validates all seven fixture pairs using the exact
exported draft-2020-12 schemas, checks semantic refusals through public APIs,
and proves original content matches while changed bytes do not. Ajv is a pinned
development dependency of the test consumer; it adds no Scan runtime dependency.
The package-support and public-boundary tests pin the exports. Ordinary public
CI includes this test through its full validation route for package/schema changes.

`contractSupport` remains the closed `urn:aihq:package-support:1.0.0` declaration
without fixture fields. Referencing fixtures from a later support declaration
belongs to samartomar/aih-scan#130. The one-off cross-package `checkContracts`
receipt from samartomar/aih-core#102 is an additional merge gate for
samartomar/aih-scan#128; repository checks alone do not satisfy it.

## Executable capture contracts (2.0.0)

Request, run-result and report `2.0.0` schemas and golden documents are exported
beside the `1.0.0` schemas at `@aihq/scan/schemas/<name>/2.0.0.json` and
`2.0.0.fixtures.json`. These are document versions, not package release promises.
`tools/generate-assessment-v2-schemas.mjs` owns the new schemas (build first);
`tools/generate-assessment-v2-fixtures.mjs` derives specimens from the existing
real grill-me fixture materials. Neither generator rewrites the legacy documents.
Mode variants are explicit contract specimens, not native Windows execution or
repository reachability evidence. The packed consumer additionally exercises
local modes, links, resource limits, observation reuse and a fixture Git executable
at the process boundary, without contacting a remote repository.
