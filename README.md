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

`0.1.0` is the replacement package. Use its versioned Scan formats for new
content assessments. [CHANGELOG.md](CHANGELOG.md) documents the replacement
contract and links to the historical release records.

## Install

```sh
npm install --save-exact @aihq/scan@0.1.0
```

Node `>=24.15.0 <25 || >=26.12.1 <27`. The built-in aih-trust-lint baseline needs nothing
else. SkillSpector 2.13.7 (primary) and the optional Cisco skill-scanner 2.3.2 run as
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
aih-scan review <summary.json> [--mcp]                     saved coverage and findings
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

### Start with static evidence

Scan the collection once, then choose a result by its printed item path, scan key and
summary path. Keep the summary and its `sarif/` directory together. Substitute the
chosen scan key for `git-sha1:<hex>` below.

```sh
aih-scan scan ./team-skills --mode static --out ./scan-static
key='git-sha1:<hex>'
summary="./scan-static/git-sha1-${key#git-sha1:}/summary.json"
aih-scan read "$summary"
aih-scan findings "$summary" --key "$key"
```

The read commands use the saved evidence without starting analyzers. Use `--json` on
either command to pass the result to another program. Check the summary's coverage,
reason, tool modes and unanalysed files alongside the findings. An empty findings list
can accompany partial coverage. An analyst can review the saved results and selected
source excerpts without running Scan again. That review leaves the recorded scan
coverage and tool modes unchanged.

If you need the full SkillSpector AI pass, use a new output directory and pass the
single skill folder that owns the selected result. Use the same file bytes and modes
as the static scan, and compare the new scan key with the original. AI mode runs static
checks again and sends the selected content to your configured AI. Check the resulting
tool mode and coverage to see what completed.

```sh
aih-scan scan ./team-skills/reviewed-skill --mode ai --out ./scan-ai
```

SkillSpector 2.13.7's optional `mcp` command exposes `scan_skill`. It scans a target
anew and requests the AI pass by default (`use_llm: true`). Use the saved-report
command below to review an existing result.

### Review one saved report

Run `aih-scan review "$summary"` to get `{ status: "ok", summary, findings }` as JSON
on standard output. It checks the summary and each referenced SARIF file before
returning a result, including the SHA-256 pinned for that file and the scan key in
its findings. Use `aih-scan verify` separately to authenticate a publisher's signature.

For an assistant that supports local stdio MCP, add this server to the client's
configuration once. Substitute the absolute path to the selected `summary.json`.
Keep the summary with its SARIF files. Change the path and restart the server to
review another item.

```json
{
  "mcpServers": {
    "scan-review": {
      "command": "aih-scan",
      "args": ["review", "/path/to/summary.json", "--mcp"]
    }
  }
}
```

If the client cannot resolve `aih-scan` on its PATH, set `command` to the absolute
path to Node and insert the installed package's `dist/cli.js` as the first argument.
The server loads one snapshot at startup. `get_coverage` returns the recorded
coverage, tool outcomes and a page of unanalysed files. `list_findings` pages the
same findings as the JSON command. Each takes only `cursor` and `limit`, defaults
to five entries, and returns at most ten. Start at `cursor: 0` and follow `nextCursor`
until it is `null`.

Both modes work from saved evidence without starting an analyzer or provider.
The assistant can send findings it reads to its own model provider. Coverage stays
as recorded in the original result. For clients without MCP support, run the JSON
command and pass the saved output to your review tool.

One review accepts at most 128 MiB of summary and SARIF bytes in total and up to
100,000 findings. It refuses linked paths and files that change during a read.
For larger results, use `read` for the summary and `readFindings` from the library
for one SARIF file at a time.

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

For the same static-first workflow in Node, call `scan` with `mode: "static"` and use the
chosen result's `summaryPath`. Read each SARIF file listed in that summary. `readFindings`
checks the SARIF digest and scan key on each read.

```js
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { readFindings, readSummary } from "@aihq/scan/read";

export async function reviewSummary(summaryPath) {
  const read = readSummary(await readFile(summaryPath));
  if (read.status !== "ok") throw new Error(`Summary: ${read.status}`);
  const { summary } = read;
  const findings = [];
  for (const { path } of summary.sarif) {
    const bytes = await readFile(join(dirname(summaryPath), path));
    const result = await readFindings(summary, bytes, summary.scanKey);
    if (result.status !== "ok") throw new Error(`Findings: ${result.status}`);
    findings.push(...result.findings);
  }
  return { summary, findings };
}
```

For an optional full AI pass on the selected item, pass `mode: "ai"` and a single
`items` entry with its exact folder path. Keep the static run in its own output folder.

The request (`aih-scan-request/1`) carries either a `source` (`aih-scan-source/1`) or
caller-prepared `items` (`[{ path, executable?, label? }]`), plus `origin`, and optional
`kinds`, `tools`, `mode` and `revision`. `revision` is the positive integer written into
each summary (default `1`): the signer's nth result for that key, chosen by the store
operator. Scan cannot see a store, so it does not check earlier revisions. With `items`
Scan hashes each folder exactly as given and returns one result per folder. JSON Schemas are exported as
`@aihq/scan/schemas/aih-scan-request-1.json`, `…/aih-scan-source-1.json`,
`…/aih-scan-summary-1.json` and `…/aih-scan-withdrawn-1.json`, and as `schemas` from
`/contracts`.

## Results

The [Catalog Scan coverage report](https://github.com/samartomar/aih-catalog/blob/main/docs/scan-coverage.md)
lets you look up a Catalog item or edition and find any published report for its exact Scan key.

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
