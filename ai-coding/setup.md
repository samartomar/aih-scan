# Setup

Never run an installed aih-scan against this checkout. Install dependencies,
inspect the local helper mutation plan, then initialize it:

```powershell
npm install
node tools/repo-ai-tools.mjs setup-codex --dry-run
npm run repo:init
npm run repo:doctor
```

`repo:init` uses the native Codex ECC plugin lifecycle, writes only an ignored
`.codex/config.toml` projection, installs helper pins in a user cache, populates
external graph/memory indexes, and configures `.githooks`. Start a new Codex
task after setup so it loads the projection.
