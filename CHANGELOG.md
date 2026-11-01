# Changelog

## 0.1.0 (unreleased)

`0.1.0` replaces the earlier `@aihq/scan` package with one content-assessment contract. It
is not a compatibility extension of the historical `0.5.0` and earlier packages: nothing
they read or wrote is accepted, and no compatibility reader is shipped.

### Added

- Three entry points: `@aihq/scan/host` (`scan`, `matchScan`), `@aihq/scan/read`
  (`readSummary`, `readFindings`, `verifySummary`, `matchScan`, `checkAdvisories`; browser
  safe) and `@aihq/scan/contracts` (formats, JSON Schemas, routing, scoring, codes, limits,
  the verification profile, the default trusted signer and the pinned Sigstore trust
  snapshot). JSON Schemas are also exported as `@aihq/scan/schemas/<format>-1.json`.
- Formats `aih-scan-request/1`, `aih-scan-source/1`, `aih-scan-summary/1` and
  `aih-scan-withdrawn/1`; SARIF 2.1.0 with one run per tool; rules
  `aih-scan-routing/1`, `aih-risk/1`, `aih-codes/1` and `aih-scan-limits/1`.
- Content-addressed scan keys: the Git tree hash (`git-sha1:` / `git-sha256:`) of each
  item folder, read from a read-only working copy; every file's SHA-256 is checked before
  a result is matched to content.
- Sources: folders and local clones, public Git repositories and items in them, npm
  packages by exact version, downloaded npm tarballs and remote MCP configuration (never
  contacted). Item discovery for skills, agents, commands, rules (steering included),
  hooks and MCP configs, with remaining files and a roll-up.
- Tools: the built-in aih-trust-lint baseline on every scan, SkillSpector 2.13.2 as the
  primary analyzer (static by default, optional AI pass through the caller's own setup)
  and the optional Cisco skill-scanner 2.3.2 second opinion; locked runtimes in
  `tools/analyzers`.
- Signing and verification profile `aih-sigstore-keyless/1`: `aih-scan sign` writes a
  Sigstore `messageSignature` bundle; `verifySummary` verifies offline, separates
  signature validity from signer trust and applies withdrawals through `throughRevision`.
- Live OSV advisories through `checkAdvisories` and `aih-scan advisories`, with
  privacy-aware defaults; never signed and never part of a score.
- Config routing for JSON and TOML hook and MCP entries (for example a Codex
  `config.toml` `[mcp_servers.*]` table), using the pinned pure-JS `smol-toml` runtime
  dependency.
- CLI: `scan`, `advisories`, `read`, `findings`, `verify` and `sign`, with exits 0
  (finished, complete or partial), 1 (only with `--fail-at`), 2 (could not scan or read)
  and 130 (cancelled).

### Removed

- The root `@aihq/scan` entry and every legacy export; the V2 assessment, artifact,
  report, run-result, item-record, item-summary, material-change, detector-definition,
  evidence-policy and severity-profile formats and schemas.
- The identity-only `aih-native` detector; attestation V1 and V2; baseline-vet
  publication; Cisco shards and OCI capture; Semgrep, Snyk agent-scan, the Cisco MCP
  scanner and the binding gate; Docker and Bubblewrap analyzer runtimes.
- The `capture`, old `sign`/`verify`, `baseline-*` and `project-core-evidence` commands;
  `--detector`, `--mcp-config`, `--artifact` and `--fail-on-findings` (replaced by
  `--tools`, discovery, `--out` and the opt-in `--fail-at`).
- The `@sigstore/*` and `zod` runtime dependencies.

Historical published versions and tags are kept unchanged as release history; see
[RELEASING.md](RELEASING.md).
