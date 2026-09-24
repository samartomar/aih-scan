# Parity fixtures (verbatim copies, do not edit)

These files are unmodified copies of W2's parity capture. They are data. The
parity tests replay them and never regenerate or rewrite them.

- `trust-parity/`: Core's `tests/fixtures/trust-parity/` on the `sep-scan`
  worktree, captured at Core commit `80120883aa4cc1ed01a0efe4b5cdc2cf4cb94157`
  (see `trust-parity/golden/metadata.json`). It holds the case list, the
  corpus, the per-case goldens and the recorded Snyk Agent Scan outputs.
- `transcripts/<environment>/<case>/<detector>.json`: W2's runner transcripts
  (`evidence/W2/golden-capture/transcripts/`) for the `cisco`,
  `mcp-scanner` and `skillspector` detectors. Every process call Core's
  engine made is recorded with its argv, cwd, exit code and output, and paths
  are placeholdered as `<root>` and `<tmp>`.

Semgrep transcripts are not copied, because no semgrep engine is in phase B1
scope. Snyk runner transcripts are not copied either: on the capture host
Snyk was never executed (no `SNYK_TOKEN`), and its parity comes from
`trust-parity/recorded/`.
