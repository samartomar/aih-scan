# Codex adapter

Codex reads `AGENTS.md`, then `ai-coding/RULE_ROUTER.md`. `npm run repo:init`
uses the native Codex plugin lifecycle for ECC and writes the ignored
project-local `.codex/config.toml` with narrow MCP tool allowlists. Never run an
installed aih-scan against this checkout.
