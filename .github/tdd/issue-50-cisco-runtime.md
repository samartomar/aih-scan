# Issue 50 Cisco runtime TDD evidence

Source: public installed-acceptance defect `#50`.

## Journeys

1. A repository-level Cisco scan recursively discovers nested `SKILL.md` files.
2. A successful process cannot yield evidence when Cisco skipped a malformed or
   crashing skill, or when its scanned count differs from sealed-source discovery.
3. A long hostile analyzer diagnostic preserves its useful head and tail without
   multiline terminal or CI-log control injection.
4. Hosted Linux executes the exact production Bubblewrap, Python, uv, and Cisco
   path and receives non-empty SARIF.

## RED

- `npm test -- --run tests/baseline/runtime-v1.test.ts` failed because the
  repository runtime used Cisco's single-skill `scan` command.
- The same focused command failed after adding the partial-coverage and diagnostic
  safety cases: Cisco's JSON coverage sidecar was not requested, skipped skills
  were accepted, and raw newlines and terminal escapes reached the error message.

## GREEN

- `npm test -- --run tests/baseline/runtime-v1.test.ts`: 8 passed.
- `npm run typecheck`: passed.
- `npm run lint`: passed.
- Normal pre-commit gate: 254 passed, 19 existing skips.
- Hosted production command-shape probe:
  <https://github.com/samartomar/aih-scan/actions/runs/33441212740>.

The current PR head must also pass its hosted production probe and complete
release preflight before merge. Public-installed acceptance remains the closing
gate for issue `#50`.
