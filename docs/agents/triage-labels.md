# Triage labels

Use the five default triage roles, mapped exactly to labels of the same name (mapping accepted by the owner on 2026-10-23). Preserve the existing tracker taxonomy alongside them.

| Skill role | Tracker label |
| --- | --- |
| `needs-triage` | `needs-triage` |
| `needs-info` | `needs-info` |
| `ready-for-agent` | `ready-for-agent` |
| `ready-for-human` | `ready-for-human` |
| `wontfix` | `wontfix` |

Use at most one canonical triage state on an issue. Classification, category and version-impact labels (such as `enhancement` or `semver:*`) do not imply readiness and are kept independently. Recheck live labels before mutation. A missing label blocks that label edit, not work on an agreed issue.
