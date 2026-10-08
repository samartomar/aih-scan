# Independent refresh maintainer contract

`refresh.mjs` uses the packed installed `@aihq/scan/contracts`, `/host` and `/read`
interfaces. It does not sign or publish reports. Use separate processes for freeze
and run, with an immutable scanner installation made from the reviewed tarball and
retained dependency lock. Changing an installation requires a new process and batch.

```sh
node tools/refresh/refresh.mjs freeze --input input.json \
  --scanner-tgz /path/to/scan.tgz --scanner-install /path/to/consumer \
  --out /path/to/new-manifest.json
# Review the exact manifest before execution.
node tools/refresh/refresh.mjs run --manifest /path/to/new-manifest.json \
  --scanner-tgz /path/to/scan.tgz --scanner-install /path/to/consumer \
  --out /path/to/new-candidates
```

Outputs are exclusively created. Keep candidate directories outside the scanner
source checkout. Exit 0 means complete assessments for every target; exit 1 retains
truthful partial or diagnostic results; exit 2 refuses the operation. An incomplete
output after a storage failure is retained for inspection and cannot be published.

The input schema is `urn:aihq:scan:refresh-input:1.0.0`. Its exact fields are
`schema`, `scannerSourceCommit`, `runtime`, `profile`, `limits` and `targets`.
`scannerSourceCommit` records the reviewed full lowercase 40-hex scanner source
commit; its relationship to the built tarball is the operator's reviewed build
record. The operation verifies the exact tarball files against the installation
and binds the complete installed dependency tree. No npm release is required.

`runtime` has `node`, `platform` and `architecture`. This profile requires an exact
Node 24 version at least 24.15.0, `linux` and `x64`. Freeze may run on a different
supported preparation host, but run must match the declared tuple exactly.
`profile` is `independent-linux-v1`. `limits` contains all nine public Scan limit
fields; limits may be lowered within the public ceilings. The statement budget
must be at least 1,024 bytes to accommodate this profile's detached statement.

`targets` has exactly these entries, in this order:

1. `mattpocock/skills`
2. `affaan-m/ECC`
3. `anthropics/skills`
4. `obra/superpowers`
5. `nextlevelbuilder/ui-ux-pro-max-skill`
6. `DietrichGebert/ponytail`
7. `samartomar/aih-extensions`

Each target has exactly `repository`, `ref`, `selection` and `trustLint`.
`ref` is a reviewed `refs/heads/...` name or a full lowercase commit. Freeze checks
GitHub's exact canonical repository identity without redirects and resolves each
branch once. A supplied full commit remains that exact commit. Run never resolves
moving refs. `selection` has `paths: "all"` and explicit `excludedPaths`. Exclusions
cannot bypass full-tree capture budgets. `trustLint` has explicit `internalScopes`
and `mcpConfigPaths`; the public detector's configuration and source checks remain
authoritative. An empty MCP input list establishes no MCP server coverage.

The four fixed requests are native identity (`in-process-native-v1`), trust lint
(`in-process-trust-lint-v1`), binding gate (`in-process-binding-gate-v1`) and Semgrep
(`linux-namespace-uv-v1`). Native and trust lint bind the whole captured tree;
binding gate and Semgrep operate on the complete selected inventory. Every
request's applicable paths, exclusions and uncovered paths remain in its report.
Semgrep requires `/usr/bin/bwrap`, `/usr/local/bin/uv`, the shipped pinned analyzer
lock and available Python. Analyzer acquisition may use the network; execution
uses the existing namespace containment and no network. Native identity's empty
findings make no security claim. Cisco and SkillSpector rule-material coverage is
unavailable; Snyk is outside this profile. No vendor parity is implied.

The frozen schema is `urn:aihq:scan:refresh-manifest:1.0.0`. Fields are `schema`,
`batchId`, `createdAt`, `scanner`, `runtime`, `profile`, `limits`,
`unavailableCoverage` and `targets`. Scanner fields are `name`, `version`,
`sourceCommit`, `tarballSha256` and `installationSha256`. Each target has
`repository`, `repositoryUrl`, `reviewedRef`, `commit`, `selection` and `detectors`.
Each detector has `detectorId`, `profileId` and `configuration`. The batch ID is
`batch:sha256:` followed by the SHA-256 of canonical manifest bytes with `batchId`
omitted. Frozen documents use canonical UTF-8 JSON with sorted object keys.
Unknown fields, duplicate JSON keys, lossy numbers and malformed strings refuse.

The candidate directory contains `manifest.json`, `inventory.json` and
`targets/<owner>--<repo>/result.json` for every source. Valid assessments additionally
contain `artifact.json`, `statement.json` and `candidate.json`. Artifacts are
unsigned and include original annex bytes. Statements are detached canonical
in-toto statements prepared through the installed host API. The per-target schema
is `urn:aihq:scan:refresh-candidate:1.0.0`; its fields are `schema`, `batchId`,
`repository`, `commit`, `scanId`, `artifactSha256`, `statementSha256` and
`resultSha256`.

The inventory schema is `urn:aihq:scan:refresh-inventory:1.0.0`. Its fields are
`schema`, `batchId`, `manifestSha256`, `createdAt`, `scanner`, `runtime`, `profile`,
`unavailableCoverage` and `targets`. Every target row has `repository`, `commit`,
`status`, `resultPath`, `resultSha256`, `diagnostics`, `detectors` and `measurements`.
Assessment rows add `scanId`, `completion`, `authenticity: "unsigned"`,
`artifactPath`, `artifactSha256`, `statementPath`, `statementSha256` and
`candidatePath`. Diagnostic rows have no assessment identity or candidate paths.
Paths are relative to the candidate directory.

Each detector row has `detectorId`, `profileId`, `outcome`, `coverage` and
`diagnostics`. Assessment outcomes and coverage come from the detailed artifact
reader. Before a reliable assessment exists, all requested detectors are `not-run`
with null coverage and the source diagnostics. Detector rows retain the reviewed
profile order; readers should match the report's canonical detector arrays by ID.
Measurements have `durationMs`, `sourceEntries`, `sourceBytes`, `reportBytes`,
`annexBytes` and `artifactBytes`; unavailable values are null. Targets execute
serially and failures preserve other retained target results.

Publication must revalidate the frozen manifest, every exact candidate digest,
reader-checked source tuple, selection, configuration, detector outcomes and
annexes. Unsigned custody records provide no publisher trust or cutover acceptance.
The dedicated Linux fixture proof runs with
`AIH_SCAN_REFRESH_LINUX_PROOF=1 npx vitest run tests/refresh/operation.test.ts`
after the declared analyzer prerequisites are installed. Fixture evidence is
separate from an authorized real seven-source production operation.
