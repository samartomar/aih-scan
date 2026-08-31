# Git and CI discipline

Never run an installed aih-scan against this checkout. Review the full diff and
run direct repository checks before committing. Local commits are allowed when
requested; pushing, publishing, creating remotes, pull requests, and GitHub
changes require separate explicit approval.

The local pre-commit hook runs typecheck, lint, and tests. Any CI added here may
perform only read-only verification and must not run repository initialization.

Every PR carries exactly one `semver:none|patch|minor|major` label. Repository-only
changes marked `semver:none` cannot start a release. Package-bearing work accumulates
in one coherent train. The tag workflow publishes only under npm `next`; public
installed acceptance and separate owner authorization precede promotion of the same
bytes to `latest`.
