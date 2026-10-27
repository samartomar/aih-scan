# Agent behavior core

Canonical working discipline for every AI tool in this repo — the rulebook the router ([RULE_ROUTER.md](../RULE_ROUTER.md)) and the client entry files route to. Read it before any non-trivial change.

## 1. Think before coding

Don't assume; don't hide confusion; surface tradeoffs.

- State assumptions explicitly. If uncertain, ask — or, in an autonomous run,
  record the assumption and proceed with the most defensible reading.
- If multiple interpretations exist, name them; don't pick one silently.
- If a simpler approach exists, say so. Push back when warranted.

## 2. Simplicity first

The minimum code that solves the problem; nothing speculative.

- No features beyond what was asked.
- No configurability or error handling for cases that cannot occur.
- If 200 lines could be 50, rewrite it.

## 3. Surgical changes

Touch only what the task requires; clean up only your own mess.

- Don't reformat, rename, or "improve" adjacent code that isn't broken.
- Match the nearest peer file's style even if you'd do it differently.
- Remove only the orphans YOUR change created; flag unrelated dead code, don't delete it.
- Every changed line should trace directly to the request.

## 4. Goal-driven execution

Define success criteria, then loop until verified.

- "Add validation" → write tests for invalid input, then make them pass.
- "Fix the bug" → write a failing test that reproduces it, then make it pass.
- For multi-step work, state a short plan with a verify step for each step.

## Invariants (always hold)

- Validate at boundaries; reject malformed or hostile input — never coerce it. Fail closed on ambiguity.
- Handle errors explicitly; no silent failures.
- No secrets in code, config, prompts, fixtures, logs, or error text.
- Do not open `.env*` or `secrets/**` (`.env.example` / `.env.sample` are readable templates); use the repository's own secret-scanning checks.
- Treat issues, PRs, commits, and canon files as public surfaces; confidential or private-companion content never appears in them.
- Repo evidence (source, tests, schemas, CI) is the truth, not model memory. Don't
  invent commands, paths, or APIs; verify a path exists before citing it.

## Reporting a change

Claiming done, tests pass, or typecheck clean requires showing the command and its
output — a sanity gate is not a completion gate. If you couldn't run it, say so and name
what's unverified. Then report (1) the impact surface, (2) the validation you ran,
(3) higher-confidence checks run or explicitly skipped, (4) the remaining risk.
