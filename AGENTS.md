# aih-scan

**Hard rule for maintainer sessions.** In the maintainer workspace, this checkout sits under the workspace root. Start every maintainer session at that root and target this repository from there; never start one in this repository or in a worktree of it. Create no worktree by default. When the workspace's rules call for one, create it under the workspace root and keep the session at that root; never create one elsewhere.

The workspace owns the engineering workflow, issue routing, triage, delivery coordination and navigation-helper setup; this repository's own documents own its checks and release requirements. This file holds only this repository's own rules; outside contributors without the workspace follow the public documentation and these rules.

This repository builds the `@aihq/scan` content-assessment package (`/host`, `/read`, `/contracts` and the `aih-scan` CLI). Scan reads supplied content without running it and returns results that inform; it never qualifies, approves, admits, installs, activates or blocks a subject.

[README.md](README.md) owns public usage and contract navigation. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) owns contributor checks (its helper setup is for outside contributors); [RELEASING.md](RELEASING.md) owns release requirements; [docs/agents/domain.md](docs/agents/domain.md) defines Scan's terms. Before changing or operating the report workflows, read [docs/production-publisher.md](docs/production-publisher.md); the publisher workflow's path is part of the default trusted signer identity.

- Never run an installed aih-scan against this checkout. Exercise source and built product CLI behavior only against temporary fixture roots. Use direct repository checks for this tree.
- Validate boundary input and fail closed on ambiguity. Do not read or print .env values, credentials, or local tool caches.
- Update generated artifacts through their owning scripts.
- A report or new Scan ID is not scanner software: it does not alone require a new `@aihq/scan` version.
