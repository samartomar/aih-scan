# Versioning and release trains

`@aihq/scan` uses Semantic Versioning on its public CLI, package exports, evidence
formats, verdicts, and exit codes. Every merged PR carries exactly one of:

- `semver:none` — docs, tests, CI, or maintainer tooling that needs no new package bytes;
- `semver:patch` — a compatible defect or security correction;
- `semver:minor` — an additive public capability or evidence/verdict change; or
- `semver:major` — an incompatible CLI, API, schema, or evidence change.

`semver:none` work rides the open train but cannot start or bump a package cut. The
highest package-bearing label in a coherent train determines the version. Related fixes
accumulate in one release PR; an immediate hotfix train is reserved for security defects,
installation blockers, evidence corruption, data loss, or comparable installed-user harm.

Merge, cut, candidate publication, installed acceptance, and stable promotion are
separate effects. A tag publishes immutable bytes under npm `next` and creates a
prerelease GitHub Release. It never changes `latest`. Public installed acceptance must
exercise the exact registry candidate with its compatible Core and Catalog baseline.
Only a separate full-SHA owner authorization may promote the same bytes to npm `latest`
and stable GitHub Release status; promotion never rebuilds or republishes.

The promoted stable train is the supported default. A candidate or larger version number
is not by itself an upgrade instruction; release notes classify adoption as no action,
recommended, required by date, or security urgent.
