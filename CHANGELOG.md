# Changelog

## Unreleased

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
