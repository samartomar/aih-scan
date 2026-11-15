# aih-scan

This repository builds the `@aihq/scan` content-assessment package (`/host`, `/read`,
`/contracts` and the `aih-scan` CLI). Scan reads supplied content without running it and
returns results that inform; it never qualifies, approves, admits, installs, activates or
blocks a subject.

[README.md](README.md) owns public usage and contract navigation.
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) owns contributor checks and helper setup;
[RELEASING.md](RELEASING.md) owns release requirements.
Before changing or operating the report workflows, read
[docs/production-publisher.md](docs/production-publisher.md); the publisher workflow's
path is part of the default trusted signer identity.

## Safety boundaries

Never run an installed aih-scan against this checkout. Exercise source and built
product CLI behavior only against temporary fixture roots. Use direct repository
checks for this tree. Validate boundary input and fail closed on ambiguity. Do not
read or print .env values, credentials, or local tool caches.

Source, tests, and verified release evidence establish behavior. Navigation helpers
are optional; stale or unavailable indexes must not block ordinary work. Maintain
this file manually. Update generated artifacts through their owning scripts.

## Engineering workflow

Use Matt Pocock's engineering skills for planning, implementation, debugging, and
review. Use /ask-matt for that flow and /ask-sam for the complementary Extensions
layer. Commit locally when authorized, then run Matt's /code-review against a fixed
base and the originating requirements before merge; that skill reads committed
changes. /ship handles launch readiness. Preserve the project gates below.

For maintainer assignments, keep the coordinating session in its supplied
workspace and target this Git root explicitly for commands and edits. Load these
product rules from that session. Public contributors can use this repository
independently; private startup routing stays outside public files.

Public work uses fully qualified samartomar/aih-scan#<number> references and explicit
--repo samartomar/aih-scan on gh issue commands. Keep public text public-safe; never copy
private plans or private links into this repository. Category and semver labels do
not imply triage readiness. Inspect live labels before proposing new mappings.

Accepted bugs/enhancements, including internally discovered work, use an owning
Scan issue before implementation; reuse an existing report for the same outcome.
At pickup identify that issue, the actual source/worktree and whether the output
is scanner software or a report. Link the PR and actual delivery evidence on the
issue. A new report/Scan ID does not alone require a new `@aihq/scan` version.
Routine successful refreshes use CI/output records; actionable recurring failures
reuse an owning issue. Keep confidential reports in the verified private route.

Before closeout verify the issue reflects merged versus available behavior. When
release is required by acceptance, retain it as pending until verified; otherwise
name the remaining release owner and follow-up. Public records stand alone. Any
private maintainer instructions travel through an explicit private handoff.

Local work does not authorize pushes, tracker writes, PRs, merges, signing, or
publication. Carry any explicit authorization through its agreed scope.

## Workflow references

Use the managed Matt Pocock skills and Extensions within this repository's rules.
Keep upstream skills in their managed installation, unchanged by repository cleanup.

- [Issue routing](docs/agents/issue-tracker.md): owning delivery issue and intake.
- [Triage](docs/agents/triage-labels.md): existing label roles and mappings.
- [Domain documentation](docs/agents/domain.md): vocabulary and decision homes.
