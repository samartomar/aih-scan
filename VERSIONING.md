# Versioning and release trains

`@aihq/scan` uses Semantic Versioning on its public CLI, package exports, versioned
formats (`aih-scan-*/N`, `aih-risk/N`, `aih-codes/N`), risk labels and exit codes. Format
identifiers, not package versions, decide what a reader accepts. Every merged PR carries
exactly one of:

- `semver:none` — docs, tests, CI, or maintainer tooling that needs no new package bytes;
- `semver:patch` — a compatible defect or security correction;
- `semver:minor` — an additive public capability or a compatible result change; or
- `semver:major` — an incompatible CLI, API, schema or format change.

`0.1.0` is the replacement package and the sole unreleased target: it replaces the
historical `0.5.0` and earlier packages and their formats rather than extending them.

`semver:none` work rides the open train but cannot start or bump a package cut. The
highest package-bearing label in a coherent train determines the version. Related fixes
accumulate in one release PR; an immediate hotfix train is reserved for security defects,
installation blockers, evidence corruption, data loss, or comparable installed-user harm.

Merge, cut, candidate publication, installed acceptance, and stable promotion are
separate effects. A tag publishes immutable bytes under npm `next` and creates a
prerelease GitHub Release. It never changes `latest`. Public installed acceptance must
exercise the exact registry candidate from fresh consumers. Only a separate full-SHA
owner authorization may promote the same bytes to npm `latest` and stable GitHub Release
status; promotion never rebuilds or republishes. Consumer applications' own acceptance is
theirs and is not a Scan release gate.

The promoted stable train is the supported default. A candidate or larger version number
is not by itself an upgrade instruction; release notes classify adoption as no action,
recommended, required by date, or security urgent.
