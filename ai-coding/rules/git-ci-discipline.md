# Git and CI discipline

Never run an installed aih-scan against this checkout. Review the full diff and
run direct repository checks before committing. Local commits are allowed when
requested; pushing, publishing, creating remotes, pull requests, and GitHub
changes require separate explicit approval.

The local pre-commit hook runs typecheck, lint, and tests. Any CI added here may
perform only read-only verification and must not run repository initialization.
