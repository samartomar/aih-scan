## Start here

Read `ai-coding/RULE_ROUTER.md`, then load the smallest routed rule set for the
task. Verify decisions against source and tests, not local helper output.

## Self-hosting boundary

Never run an installed aih-scan against this checkout. Once a scanner CLI
exists, use temporary fixture roots for its product behavior. Maintain this
repository canon manually and use direct repository checks here.

## Working agreement

- State the smallest verifiable change before editing.
- Write and run a failing test before implementation changes.
- Validate hostile input at boundaries and fail closed on ambiguity.
- Keep credentials, machine paths, generated projections, and tool indexes out
  of committed files.
- Helper tools are advisory. If unavailable or stale, warn once and continue
  from source and tests.
