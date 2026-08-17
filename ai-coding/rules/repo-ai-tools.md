# Repository AI tools

Never run an installed aih-scan against this checkout. `npm run repo:init`
creates ignored local helper projections and indexes; first inspect
`node tools/repo-ai-tools.mjs setup-codex --dry-run`.

Use Token Savior for compact read-only orientation. Use Serena for exact symbols
and semantic edits. Use code-review-graph once for broad-impact review context;
it is advisory, so warn once and continue if it is unavailable. Use
codebase-memory-mcp for find, trace, and recall. Token Optimizer is on-demand
only (`token-optimizer-report` or `token-optimizer-coach`), never a routine
gate.

The local Codex projection exposes narrow allowlists only: Serena has symbol and
semantic-edit tools, Token Savior has six orientation tools, code-review-graph
has impact/review tools, and codebase-memory-mcp has graph/retrieval tools.
