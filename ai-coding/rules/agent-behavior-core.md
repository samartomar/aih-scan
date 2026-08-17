# Agent behavior core

Never run an installed aih-scan against this checkout. Use temporary fixture
roots for product behavior when a CLI exists.

- Think before coding: identify the smallest testable behavior.
- Keep edits surgical and avoid speculative product work.
- Validate boundary inputs and fail closed on ambiguity.
- Do not read or print `.env` values, credentials, or local tool caches.
- Treat repository source and tests as evidence; helper output is advisory.
