# Explicit GitHub material handoff

`deliverMaterialChange` is a separate promise-based Node operation in
`@aihq/scan/host`. The caller chooses `enabled: true`, a target
`{owner, repository}`, and an explicit bearer `credential`. It accepts the
validated `MaterialChange` returned by `compareMaterialInventories`.
No credential is discovered from the environment, Git, a CLI or a user store.
The credential authorizes delivery to the chosen tracker; it does not
authenticate the report producer.

```ts
import { deliverMaterialChange } from "@aihq/scan/host";

const delivery = await deliverMaterialChange({
  summary: materialChange,
  enabled: true,
  target: { owner: "example", repository: "material-maintenance" },
  credential: suppliedGitHubCredential,
});
```

Scan, read, artifact preparation, signing, authentication and publication are
independent calls. Delivery receives summary identities, never source file
contents, findings or installation metadata. Failure leaves the published report
and artifact intact.

The result has `results`, one entry per change, and safe invocation `diagnostics`.
Each entry returns `changeId`, `status` (`created`, `updated`,
`closed-disposition`, or `failed`), optional validated `issueUrl`, and safe
`diagnostics`. Any failed entry retains `retryableSummary`, the full exact
validated input snapshot, including entries delivered earlier. Configuration
refusals also retain it, even for an empty change list. Invalid summary input
rejects with a safe `ContractError` (`invalid-input` or `resource-limit`). An
enabled, correctly configured empty summary is a no-op and returns empty results
and diagnostics.

The adapter searches all relevant issue pages using `state=all`, oldest first, so
issues created during the lookup append rather than shifting earlier pages. It
excludes pull requests and matches exact body markers rather than titles. One
matching open issue updates only the managed section, preserving surrounding
human text. One matching closed issue remains closed. A different change creates
a new issue linked to the highest-numbered prior issue for the same item.
Duplicate exact matches fail that change before mutation.

The managed-section check is conservative. Any listed issue whose body contains
a malformed or duplicated managed section or marker fails the whole lookup
before mutation, even if it concerns another item. An operator repairs or
removes that section, then retries the retained summary. An exact change marker
paired with a different item key fails only that change.

The lookup admits at most 20 pages of 100 entries, and pull requests count
toward those pages. A larger tracker refuses with `incomplete-lookup`. The
lookup also has an 8 MiB cumulative issue-body budget and an adapter bound of
256 KiB of UTF-8 per issue body, so long non-ASCII human text is admitted. The
default HTTP adapter caps each response at 2 MiB. Each transport operation has a
10-second deadline and the invocation has a 60-second deadline. Incomplete
lookup never becomes permission to create. The injected transport must honor its
AbortSignal to stop its own in-flight work. See GitHub's
[issues API](https://docs.github.com/en/rest/issues/issues) and
[pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api).

After the first failed or uncertain create or update, the invocation attempts no
further mutation. Later changes that would need one return `failed` with
`not-attempted`. Changes whose outcome follows from the completed lookup alone,
such as a closed disposition or an ambiguous match, still report. A timed-out
mutation may still have committed; the caller-driven retry searches markers
first.

The section delimiters are `<!-- aihq-scan-managed:v1 -->` and
`<!-- /aihq-scan-managed:v1 -->`. Inside are the exact identity comments
`<!-- aihq-scan-change:v1 <changeId> -->` and
`<!-- aihq-scan-item:v1 <itemKey> -->`. Human text outside those delimiters is
retained byte-for-byte when updating. Display text is escaped so supplied labels
cannot manufacture markers or mentions. New issue titles use the bounded change
identity. Updating a managed section retains its existing safe prior-item link.

Serialize calls in the configured maintainer workflow. Lookup followed by create
does not provide atomic uniqueness across publishers. A failed or uncertain
create returns `failed`; retry the retained summary through the same API, which
searches markers before creating again. No automatic retries, persistent queue,
service or background work is provided. Operators resolve ambiguity explicitly.

`transport` optionally injects the external `GitHubTransport` SDK boundary for
testing or a caller-owned adapter. The default adapter uses only
`https://api.github.com`, supplies the explicit bearer credential and refuses
redirects. All transport responses are untrusted. Successful HTTP status alone
does not establish delivery; malformed issue data fails safely.

GitHub responses are third-party human content, not AIHQ contract data. Their
strings need not be NFC, and finite numbers follow the strict parser's ordinary
number-loss policy. Well-formed UTF-8, duplicate-key refusal and nesting bounds
still apply.

GitHub treats owner and repository names case-insensitively and returns their
canonical case. A returned issue URL must be exactly
`https://github.com/<owner>/<repository>/issues/<number>` for the configured
target, compared ignoring ASCII case, with the matching number and no port,
userinfo, query or fragment. Results report GitHub's URL.

Refused HTTP statuses map to safe codes from the status line and headers only:
`unauthorized`, `forbidden`, `rate-limited`, `not-found` or `invalid-response`.
Diagnostic text never includes credentials, raw server bodies or dependency
errors.
