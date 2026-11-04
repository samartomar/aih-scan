# AIH Scan (`@aihq/scan`)

Scan assesses AI agent content — skills, agents, commands, rules, hooks and MCP
configurations — from the exact bytes it is given. It reads the content without running
it, sends each file to the standard tools that cover it, and returns standard results:
SARIF 2.1.0 findings, a short summary and a risk score.

- **Anyone can bring their own content**: a folder, a public repository or one item in
  it, a local clone of a private repository, an npm MCP package (public, or a tarball you
  downloaded) or remote MCP configuration.
- **Scan informs; it never blocks.** No function, command or exit code refuses an
  installation because of a score. `--fail-at` is the caller explicitly asking for a
  failing exit at a risk threshold. Input, integrity and resource-limit refusals still
  apply.
- **Supplied content never runs.** Scan never runs a supplied file, command, hook or
  package script and never installs packages; an npm tarball is unpacked only as files to
  read. Remote MCP servers are never contacted.
- **Results are addressed by content.** Each item's scan key is the Git tree hash of its
  folder, so identical bytes and modes share a key wherever they appear.

`0.1.0` is the replacement package and the sole unreleased target. It does not read or
produce the formats of earlier `@aihq/scan` versions (see [CHANGELOG.md](CHANGELOG.md)).

## Install

```sh
npm install --save-exact @aihq/scan@0.1.0
```

Node `>=24.15.0 <25 || >=26.12.1 <27`. The built-in aih-trust-lint baseline needs nothing
else. SkillSpector 2.13.3 (primary) and the optional Cisco skill-scanner 2.3.2 run as
installed native CLIs; [docs/analyzers.md](docs/analyzers.md) has the pinned installs.
Without SkillSpector a scan still completes, reports SkillSpector as `not-run`
(`unavailable`) and its coverage as `partial`.

## Command line

```text
aih-scan scan <folder> [options]
aih-scan scan <owner/repo | https-url | item-link> [--ref <name>] [options]
aih-scan scan npm:<package>@<version> [options]
aih-scan scan npm-file:<package.tgz> [options]
aih-scan scan mcp-url:<url> [options]                      config only
     options: [--tools skillspector,aih-trust-lint[,cisco]] [--mode static|ai] [--origin published|local]
              [--kinds hook,skill] [--internal-scope @scope] [--json] [--quiet] --out <new-folder>
aih-scan advisories <folder | summary.json | owner/repo | https-url | npm:package@version | npm-file:package.tgz>
              [--internal-scope @scope] [--private] [--include-private]
aih-scan read <summary.json>                               print the summary
aih-scan findings <summary.json> --key <scanKey>           print one key's one-liners
aih-scan verify <summary.json> --bundle <file>             check a published result's signature
aih-scan sign <summary.json>                               sign with your own identity
Optional: --fail-at CAUTION | DO_NOT_INSTALL               exit 1 at or above that label
```

Beyond that summary, the commands also accept: several `scan` targets in one run (one
`--out` folder); `--origin` defaulting to `local` (pass `--origin published` for a public
source you publish results for); `--json` on `advisories`, `read`, `findings`, `verify`
and `sign`; `--ref` on `advisories` for a Git target; `--fail-at` on `read`;
`--signers`, `--trusted-root` and repeatable `--withdrawn <file> --withdrawn-bundle <file>`
on `verify`; and `--bundle`, `--trusted-root`, `--fulcio-url` and `--rekor-url` on `sign`.
`aih-scan <command> --help` prints each command's options; `aih-scan --help` lists every
command's usage line.

| Exit | Meaning |
|---|---|
| 0 | Finished, complete or partial (partial is shown, never a failure) |
| 1 | Only with `--fail-at`, when the stored label reached it |
| 2 | Could not scan or read: bad input, unreadable source, a limit exceeded, no output |
| 130 | Cancelled (SIGINT/SIGTERM); finished results are kept |

```sh
aih-scan scan ./team-skills --out ./scan-out
aih-scan scan obra/superpowers --ref main --kinds skill,hook --out ./scan-out
aih-scan read ./scan-out/git-sha1-<hex>/summary.json
aih-scan findings ./scan-out/git-sha1-<hex>/summary.json --key git-sha1:<hex>
```

A source scan returns one result per item found, one for the remaining files and a
roll-up. [docs/scan-sources.md](docs/scan-sources.md) covers every source form, what is
fetched, item discovery, pins and refusals. `scan` writes into a new `--out` folder, one
folder per scan key (`git-sha1-<hex>/summary.json` and `sarif/<sha256>.sarif`).

Static mode (the default) makes no network call during the scan; the only fetches are a
source route's public Git clone or npm tarball, before the scan. `--mode ai` adds
SkillSpector's AI pass with the AI you already set up, says where the content goes before
scanning, and falls back to static with "AI not available here" when nothing is set up.

## Library

Three entry points, six functions. No function throws on bad input: every result has a
`status` (`ok`, `refused` with a reason, `invalid`, `unsupported-version`). `readable`,
`trusted` and `coverage` are always kept apart.

```text
@aihq/scan/host        (Node)
  scan(request, { outDir, signal?, internalScopes? })  → Promise<{ status, results, rollup? }>
  matchScan(summaryOrVerified, folderPath)             → Promise<{ status, matches, coverage, signer }>

@aihq/scan/read        (browser-safe: no Node globals or built-ins)
  readSummary(bytes)                                   → { status, summary }
  readFindings(summary, sarifBytes, scanKey)           → Promise<{ status, findings }>
  verifySummary(bytes, bundle, allowedSigners?, { trustedRoot, withdrawn, withdrawnBundle }?)
                                                       → Promise<{ status, verified, withdrawn, signer, summary }>
  matchScan(summaryOrVerified, files)                  → Promise<{ status, matches, coverage, signer }>
  checkAdvisories(dependencies, { internalScopes })    → Promise<{ status, checkedAt, results }>

@aihq/scan/contracts   (portable data and validators)
  formats, schemas, routing (aih-scan-routing/1), scoring (aih-risk/1), codes (aih-codes/1),
  limits, verification (aih-sigstore-keyless/1), defaultSigners, sigstoreTrustedRootText
```

`readFindings`, `matchScan`, `verifySummary` and `checkAdvisories` return Promises
because they use WebCrypto or `fetch`; `readSummary` is synchronous.

```js
import { scan } from "@aihq/scan/host";
import { matchScan, readFindings, readSummary, verifySummary } from "@aihq/scan/read";

const run = await scan(
  { format: "aih-scan-request/1", origin: "local", source: { format: "aih-scan-source/1", type: "folder", path: "./team-skills" } },
  { outDir: "./scan-out" },
);
for (const result of run.results) console.log(result.kind, result.path, result.scanKey, result.status);

const read = readSummary(summaryBytes);              // { status: "ok", summary }
const findings = await readFindings(read.summary, sarifBytes, read.summary.scanKey);
const verified = await verifySummary(summaryBytes, bundleBytes);   // default trusted publisher
const match = await matchScan(verified, files);       // files: [{ path, mode, bytes }]
// { status: "ok", matches: true, coverage: "complete", signer: { identity, trusted } }
```

`matchScan` takes the signer only from the exact object `verifySummary` returned; a copy or
a hand-built look-alike matches with `signer: null`.

The request (`aih-scan-request/1`) carries either a `source` (`aih-scan-source/1`) or
caller-prepared `items` (`[{ path, executable?, label? }]`), plus `origin`, and optional
`kinds`, `tools` and `mode`. With `items` Scan hashes each folder exactly as given and
returns one result per folder. JSON Schemas are exported as
`@aihq/scan/schemas/aih-scan-request-1.json`, `…/aih-scan-source-1.json`,
`…/aih-scan-summary-1.json` and `…/aih-scan-withdrawn-1.json`, and as `schemas` from
`/contracts`.

## Results

- **Summary** (`aih-scan-summary/1`): one scan key, its revision and origin, the scanner,
  routing and scoring versions, `score`, `label`, `coverage` (with `reason` when partial),
  every file's path, mode, part and SHA-256, each tool's version, mode, result and counts,
  `notAnalysed` files (with `secretsChecked`), the SARIF files by SHA-256 and the declared
  `dependencies`. It holds no source, Catalog name, framework or item id.
- **SARIF 2.1.0**: one run per tool; every result carries `scanKey`, `part`, `code`
  (`aih-codes/1`), `severity` and `confidence`.
- **Scoring** (`aih-risk/1`): CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5 points (INFO is
  informational: listed in SARIF and counts, zero points), cross-tool
  deduplication, per-rule diminishing weights, confidence, ×1.3 for code, rounded and
  capped at 100. SAFE 0–20, CAUTION 21–50, DO NOT INSTALL 51–100; a partial SAFE result is
  stored as CAUTION and shown as `CAUTION (partial)`; nothing routable is NOT ASSESSED.
- **Coverage** is measured against the tools routed for each part: `complete` when every
  routed tool ran, `partial` with a reason when one failed, timed out, was unavailable or
  was not selected. Cisco never counts toward coverage.

The routing table, scoring rules, codes and limits are exported from `/contracts` and
listed in [CONTRACTS.md](CONTRACTS.md).

## Signing and verification

`aih-scan sign` signs a summary (or a withdrawal, `aih-scan-withdrawn/1`) with your own
keyless Sigstore identity and writes a `messageSignature` bundle. `verifySummary` checks a
summary and its bundle offline against the pinned Sigstore public-good trust snapshot
(shipped as `trust/sigstore-trusted-root.json` and `sigstoreTrustedRootText`) or a
`trustedRoot` you supply. Signers you list in `allowedSigners` are trusted; the default
list holds AIHQ's publishing workflow (`defaultSigners`). Any other valid signature is
"signed, not by a trusted publisher". A withdrawal covers that signer's revisions 1 to
`throughRevision`; a withdrawn result is never trusted. See
[docs/verification.md](docs/verification.md).

## Advisories

`checkAdvisories` (and `aih-scan advisories`) ask OSV live about declared dependencies.
They are never signed, never part of a scan and never change a score. Internal scopes and
version ranges are never sent; the CLI treats folders, `npm-file:` and summaries as
private unless `--include-private`. See [docs/advisories.md](docs/advisories.md).

## Limits

Published in `/contracts` (`limits`): source size 500 MB, 50,000 files, 50 MB per file,
path length 1,024, folder depth 64, 20,000 items found — over any of them the scan is
`refused`, writes nothing and exits 2. One tool on one item has 10 minutes; past that the
tool is `not-run` (`timeout`) and the item `partial`. A limit is never SAFE and never an
empty clean result.

## Boundaries

Scan knows nothing about Catalog items, policies, people or the Workbench. Callers build
item folders and extracted entries, choose which summaries and coverage they accept and
which signers they allow, keep withdrawal and revision knowledge, and own
acknowledgements and presentation. Store operators assign revisions and isolate the
scanning host. Whether to install belongs to the person or organization.

## Development and releases

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers local checks and analyzer setup;
[RELEASING.md](RELEASING.md) and [VERSIONING.md](VERSIONING.md) cover releases. The
manual report workflows are described in
[docs/production-publisher.md](docs/production-publisher.md).

## License

[Apache-2.0](LICENSE)
