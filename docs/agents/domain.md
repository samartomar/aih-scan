# Domain documentation

This repository uses a single product vocabulary. Before exploration, read the root `GLOSSARY.md` when present and the relevant README and public architecture documentation. Use the defined terms consistently in issues, specifications, tests and reviews.

Repository instructions govern the maintained decision location. Keep private engineering plans and decision records outside public product files; public documentation must remain independently useful. Do not invent a second decision authority.

Missing glossary or ADR files do not block work. Create entries lazily when terms or consequential trade-offs are resolved, rather than scaffolding empty documents. If a proposal contradicts an accepted decision, identify the conflict before changing its authority.

## Core terms

- **Scan key**: the Git tree hash (`git-sha1:` / `git-sha256:`) of one item folder as Scan
  read it; results are addressed by it. Not a commit, item id or tool version.
- **Item**: a skill folder, single-file agent, command or rule, a hooks folder or config,
  or an MCP config — found on the `source` route or handed over on the `items` route.
- **Remaining files**: source files outside every found item, scanned as one more result.
- **Roll-up**: a source's highest risk label and its partial, NOT ASSESSED and
  not-selected counts.
- **Part**: the one routing class of a file (`text`, `code`, `config`, `dependencies`), or
  not analysed.
- **Coverage**: `complete` when every tool routed for each part ran; `partial` with a
  reason otherwise. Separate from risk and from signer trust.
- **Risk label**: SAFE, CAUTION, DO NOT INSTALL or NOT ASSESSED inside a summary. A
  **request label** is the caller's unsigned name for an item, echoed only in scan results.
- **Summary**: the `aih-scan-summary/1` document for one scan key and revision.
- **Signer / trusted publisher**: the certificate identity of a verified signature;
  trusted only when it matches the caller's allowed signers (default `defaultSigners`).
- **Withdrawal**: an `aih-scan-withdrawn/1` document signed by the same signer, covering
  revisions 1 to `throughRevision` of one key.
- **Advisory**: a live OSV result from `checkAdvisories`; never part of a scan or score.

Scan informs; it never approves, admits or blocks an installation.
