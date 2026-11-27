# aih-scan

**Hard rule for maintainer sessions.** This checkout belongs to a larger maintainer workspace. Start every session at that workspace's root and target this repository from there; never start one here. Create no worktree of this repository alone: a needed worktree is created under the workspace root, with the session still at that root.

The workspace owns workflow, issue routing, triage, delivery and release process. This file holds only this repository's own rules; outside contributors without the workspace follow the public documentation and these rules.

This repository builds the `@aihq/scan` content-assessment package (`/host`, `/read`, `/contracts` and the `aih-scan` CLI). Scan reads supplied content without running it and returns results that inform; it never qualifies, approves, admits, installs, activates or blocks a subject.

[README.md](README.md) owns public usage and contract navigation. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) owns contributor checks and helper setup; [RELEASING.md](RELEASING.md) owns release requirements; [docs/agents/domain.md](docs/agents/domain.md) defines Scan's terms. Before changing or operating the report workflows, read [docs/production-publisher.md](docs/production-publisher.md); the publisher workflow's path is part of the default trusted signer identity.

- Never run an installed aih-scan against this checkout. Exercise source and built product CLI behavior only against temporary fixture roots. Use direct repository checks for this tree.
- Validate boundary input and fail closed on ambiguity. Do not read or print .env values, credentials, or local tool caches.
- Update generated artifacts through their owning scripts.
- State whether an output is scanner software or a report. A new report/Scan ID does not alone require a new `@aihq/scan` version.
