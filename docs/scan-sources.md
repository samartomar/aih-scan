# Scanning sources

`aih-scan scan` and `scan(request, { outDir })` from `@aihq/scan/host` accept a
source (`aih-scan-source/1`) or caller-prepared `items`. This page covers sources:
which forms exist, what is fetched, how items are found and what each result pins.

## Source forms

| Command-line target | Descriptor | Fetched before scanning | Pin in each result |
|---|---|---|---|
| `<folder>` | `{ "type": "folder", "path": "…" }` | nothing | `{ type, path, item, commit? }` |
| `owner/repo`, `https://…` with `--ref <name>` | `{ "type": "git", "repo": "https://…", "ref": "main" }` | one public commit over HTTPS | `{ type, repo, ref?, commit, item }` |
| `https://github.com/<owner>/<repo>/tree/<ref>/<path>` (or `/blob/`) | `{ "type": "git", "repo": "…", "ref": "…", "path": "…" }` | the same commit; only files under `path` are read | as above |
| — | `{ "type": "git", …, "path": "skills/x", "kind": "skill" }` | as above | one item at that path |
| `npm:<package>@<exact-version>` | `{ "type": "npm", "package": "…", "version": "1.2.3", "kind": "mcp" }` | registry metadata and its tarball | `{ type, package, version, tarballSha256 }` |
| `npm-file:<package.tgz>` | `{ "type": "npm-file", "path": "…", "kind": "mcp" }` | nothing | `{ type, path, package, version, tarballSha256 }` |
| `mcp-url:<url>` | `{ "type": "remote", "url": "…", "kind": "mcp" }` | nothing; the endpoint is never contacted | `{ type, url }` |

A target that exists as a local path is always a folder; `owner/repo` is read as
a GitHub repository only when no such local path exists.

Pins are unsigned and appear only in the scan result, never in a summary or
SARIF. A folder that is a local clone also records its checked-out commit, read
from `.git` as data; its remote address is never read or recorded.

## Public and private content

- **Public repositories and packages**: name them directly. Git runs HTTPS only,
  with credential helpers, askpass programs, prompts, hooks, redirects and ambient
  Git configuration disabled, and with only an allowlisted environment and a private
  empty home folder, so no `~/.netrc` or user configuration is read; a repository that needs credentials is refused as
  `source-unavailable`. The CLI and `validateSource` accept the same repository URLs:
  `https://` with a host and an optional path, and no credentials, query, fragment,
  spaces or control characters. Scan does not refuse loopback, link-local or private
  hosts; when a request can come from someone else, run Scan where its network access
  is limited to the hosts you intend. A full commit given as `--ref` must be reachable from an
  advertised branch or tag. npm packages are fetched by exact version, checked
  against the registry's sha512 integrity and read as files: no npm client,
  install, lifecycle script or server start ever runs.
- **Private repositories**: clone with your own access, then scan the clone as a
  folder. Scan never asks for, stores or records credentials.
- **Private or internal packages**: download the tarball with your own access,
  then scan it with `npm-file:`. Nothing is fetched.
- **Remote MCP servers**: `mcp-url:` scans configuration only. The URL becomes one
  file, `.mcp.json` (mode `100644`), holding
  `{"mcpServers":{"remote":{"url":URL}}}` plus one LF, with the URL kept exactly
  as given. A consumer that builds the same file gets the same key and the same
  `matchScan` answer.

Fetches happen before the scan. The result's `acquisition` says whether the source
was fetched; the scan itself runs nothing supplied and, in static mode, makes no
network call. [analyzers.md](analyzers.md) describes the installed SkillSpector and
optional Cisco skill-scanner runs, AI mode and what each sends where.

## Items found

On the source route Scan finds items by their usual layouts anywhere in the
source, including copies such as `.kiro/skills` or `docs/ja-JP/skills`:

| Kind | Recognised as |
|---|---|
| `skill` | a folder holding `SKILL.md`: the whole folder |
| `agent` | a `.md`, `.json` or `.toml` file directly under a folder named `agents` |
| `command` | a `.md` file directly under a folder named `commands` |
| `rule` | a file under a folder named `rules` at any depth, `.cursor/rules/*.mdc`, `.kiro/steering/*.md` |
| `hook` | a folder named `hooks` holding `hooks.json` (the whole folder); elsewhere `hooks.json` alone |
| `mcp` | a `.mcp.json` or `mcp.json` file; or an `npm`, `npm-file` or `remote` source |

Each file belongs to one item: the outermost skill folder owns everything inside
it (nested skills, rules and agents included), then a hooks folder, then single
files (`hooks.json` and MCP configs first, then rules, agents, commands). Every
other file, `plugin.json` and `marketplace.json` included, is part of the
remaining files. Each item gets the key it would have if handed over as a folder
(a single-file item is a one-file folder), so identical copies share a key and are
scanned once, and changing one item never changes another's key.

## Results and roll-up

A source scan returns one result per item found (`kind`, source-relative `path`,
`scanKey`, `summaryPath`, `sarifPaths`, `source`), one `remaining-files` result
(path `.`) when files remain, and a `rollup`:

- `label`: the highest risk label among the results, the remaining files
  included; NOT ASSESSED when no result has a risk label, never SAFE.
- `items`, `partial`, `notAssessed`: counts over the scanned results.
- `found`: items found by kind; `remainingFiles`: files outside every item.
- With `kinds`, unselected items and the remaining files are not scanned, are
  counted in `notSelected`, and the roll-up is `partial` with reason
  `not selected`. Each scanned item keeps its own coverage.

## Refusals

Every source is held to the same rules as a folder: regular files only (links,
hard links, devices and submodules are refused), valid names, and the published
limits (files, one file's size, source size, path length, folder depth, items
found). A refused source returns `status: "refused"` with the reason (for example
`link`, `file-size`, `source-unavailable`, `source-integrity`,
`commit-unreachable`, `path-not-found`, `not-a-package`), writes nothing and exits 2.

`.git` is left out of every source at every depth (a folder, a Git tree or an npm
archive); it is never read, hashed or scanned. A valid name is well-formed Unicode
without C0/C1 or bidirectional control characters, without a backslash (a path
separator on Windows) and not a URL or drive-letter path; other characters, such as a
zero-width joiner or a colon inside a name, are allowed.

Readers are stricter about the paths they show. `readFindings` refuses a finding
whose location contains a format character (such as a zero-width joiner), a line or
paragraph separator, or a URL-like scheme prefix (`javascript:`, `data:`, `mailto:`,
`https:`). It returns "Findings don't match this scan" instead. A file named
`notes:1.md` at the top of an item is scanned, but its findings are not shown by a
reader; `docs/notes:1.md` is shown.

## Names a host cannot write

Each item is copied into a read-only working copy before it is scanned. When the
host cannot write an item's names, that item's result is `invalid` and the other items
are still scanned: on Windows `reserved-name` (device names such as `CON` or
`aux.md`, the characters `< > : " | ? *`, a name ending in a dot or space); on
Windows and macOS `case-collision` (paths that differ only by letter case, on macOS
also by Unicode normalisation). Any other failure to write the working copy is
`refused` with `snapshot-failed`.

## Modes

A file is executable (`100755`) or normal (`100644`). The disk decides where it
records modes. Where it does not (Windows), a folder that is a clone (a `.git` folder
directly inside it) takes each tracked file's mode from Git's index, read as data
without running Git; otherwise an item's `executable` list, otherwise normal.
