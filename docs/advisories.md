# Checking live dependency advisories

Known vulnerabilities are not part of a scan. A scan lists the dependencies its content
declares (`summary.dependencies`, versions exactly as written) and never asks an advisory
service. `checkAdvisories` and `aih-scan advisories` ask [OSV](https://osv.dev) live, as a
separate step you choose. Their output is unsigned, is never written into a summary or SARIF
and never changes a score, label or coverage. The code `trust.known-vulnerability` appears only
in advisory results.

## Library: `checkAdvisories` (`@aihq/scan/read`)

```js
import { checkAdvisories } from "@aihq/scan/read";

const result = await checkAdvisories(summary.dependencies, { internalScopes: ["@acme"] });
// { status: "ok", checkedAt: "2026-11-01T09:00:00Z", results: [
//   { ecosystem: "npm", name: "ws", version: "8.18.0", file: "package.json", state: "none-known" },
//   { ecosystem: "npm", name: "x", version: "1.0.0", file: "package.json", state: "vulnerable",
//     code: "trust.known-vulnerability",
//     advisories: [ { id: "GHSA-…", severity: "HIGH", summary: "…", fixedIn: "1.0.1" } ] },
//   { ecosystem: "npm", name: "@acme/tools", version: "1.0.0", file: "package.json",
//     state: "not-checked", reason: "internal scope" } ] }
```

It is browser-safe (it uses only `fetch`) and returns a Promise. It checks what you give it:
whether to submit the dependencies of private content is your choice.

- One result per dependency, in input order; `file` is echoed when supplied. Identical package
  versions are asked once.
- `none-known`: the service answered and listed no current advisory. Withdrawn advisories are
  skipped.
- `vulnerable`: each advisory carries its `id`; `severity` (as the advisory database states
  it, for example `HIGH` or `MODERATE`), `summary` (the advisory summary, else its details,
  sanitized and cut to the finding-text limit) and `fixedIn` only when the advisory supplies
  them. A fixed version is never guessed: with several fixed versions it is the lowest release
  above the checked version when all compare as plain dotted numbers, otherwise omitted.
- `not-checked` with a reason: `internal scope` (an npm package under one of `internalScopes`),
  `no exact version` (a range, tag, URL, path, alias or missing version), or `advisory service
  unreachable`. If the service fails, times out or answers malformed data, the status is still
  `ok` and every entry that would have been sent is `not-checked`; there is never an empty,
  clean result.
- Never sent: packages under `internalScopes` and versions that are not exact. Exact means a
  full npm semantic version (`1.2.3`, prerelease/build allowed) or a pinned PyPI version
  (`==2.31.0` sends `2.31.0`). Only the package name, ecosystem and exact version are sent:
  never file paths, other dependencies, credentials or cookies.
- Requests: `POST https://api.osv.dev/v1/querybatch`, then `GET /v1/vulns/<id>` for each
  advisory found, without credentials, referrer or redirects. Options `endpoint` and `fetch`
  select another OSV-compatible service or HTTP client; `signal` cancels (`refused`,
  reason `cancelled`). Malformed input or options are `invalid`.

## Command: `aih-scan advisories`

```
aih-scan advisories <folder | summary.json | owner/repo | https-url | npm:package@version | npm-file:package.tgz>
                    [--internal-scope @scope]... [--private | --include-private] [--ref <name>] [--json]
```

The command reads the target the same way `scan` does (nothing in it is run), lists its
declared dependencies (`package.json`, `requirements*.txt`, `npx`/`uvx` MCP entries) and applies
privacy defaults:

| Target | Default |
|---|---|
| Public repository (`owner/repo`, https URL, GitHub item link) | checked |
| `npm:<package>@<version>` | checked |
| Folder (including a local clone of a private repository) | private: nothing sent |
| `npm-file:<package.tgz>` | private: nothing sent |
| `summary.json` (a summary carries no source) | private: nothing sent |

For a private target the command prints the dependencies it found and sends nothing;
`--include-private` sends their exact public versions. `--private` treats a public target as
private (the repository or package is still fetched to list its dependencies, but nothing is
sent to the advisory service). Giving both flags is invalid. Internal scopes and version ranges
are never sent in any mode.

`--json` prints `{ status, source, private, checked }` plus either `dependencies` (nothing was
sent) or the `checkAdvisories` result (`checkedAt`, `results`). Exit codes: 0 finished
(advisories found or not, service reachable or not), 2 bad input or unreadable target, 130
cancelled. An unreachable service is also reported on stderr.
