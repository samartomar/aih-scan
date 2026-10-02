# Changelog

## Unreleased

- Add `aih-scan scan <directory>` to assess a local directory from the command line.
  It runs the native and trust-lint detectors by default or the detectors you name,
  discovers MCP configuration inside the target or reads `--mcp-config` and
  `--internal-scope` inputs, and prints a human summary or `--json` run result.
  `--artifact` saves an unsigned portable artifact that is read back before success;
  detector annexes stay separate and a selected detector that cannot run is reported
  as refused. Exit codes are 0, 1, 2 and 130; a first `SIGINT` or `SIGTERM` cancels
  and reports, a second exits immediately.
- `aih-scan scan` also accepts an `https://` Git URL or a GitHub `owner/repo`
  (a local path with that spelling still wins). The default `HEAD`, or a branch,
  tag or full commit named with `--ref`, is resolved to one full commit through
  the hardened Git runner, then assessed through the existing pinned Git
  acquisition. The summary and stderr report the commit; the JSON result and
  artifact carry it in `report.source` without a schema change. URLs with
  credentials, queries or fragments, other Git transports, ambiguous or invalid
  refs and SHA-256 repositories are refused with exit 2 without echoing the URL.
  `--mcp-config` applies to local directories only.

- Add strict material inventory comparison, portable `MaterialChange` contracts
  and a versioned schema. Compare published content and declared installation
  metadata independently of findings; partial inventory never proves removal.
  Add an explicitly enabled GitHub handoff that preserves human text, closed
  dispositions and retry data independently of artifact operations.

- Reuse complete unchanged detector observations through Scan-managed retained
  handles or independently authenticated supported prior artifacts. Preserve
  original evidence and observed times while rebuilding current partial reports.
  Binding-gate uses selected-closure inputs; native and trust-lint retain whole-tree
  scope. Changed inputs rerun the complete affected unit.
- Require complete installed adapter identity for fresh and reused observations.
  Startup contexts with unsupported preload or loader hooks now explicitly refuse
  detector work; see the assessment API and observation reuse migration notes.
- Add Scan-owned assessment contracts and versioned JSON Schema resources, portable
  report/artifact readers, and explicit Node host APIs for scanning, preparation,
  attachment, local signing and offline authentication.
- Preserve reliable partial outcomes and bind complete report/annex bytes to an
  immutable Scan ID. Producer authentication is separate from detailed reading.
- Adopt bounded Sigstore v0.3 bundles with independent keyless publisher and
  organization Ed25519 trust paths. Prepare an inactive production publisher;
  production protection, signing and conformance remain activation requirements.
- Set the host runtime to Node `>=24.15.0 <25`. Existing consumers upgrading package
  bytes must meet this range. Assessment clients import `@aihq/scan/host` and
  `@aihq/scan/read`; the retained root V2 entry is outside the new assessment flow.
- Verify the packed assessment consumer independently of a Core installation.
  Legacy exact-Core checkout gates are removed from default Scan CI; retained
  runner containment and artifact custody checks continue.

No package version or authenticated report publication is implied by these entries.
