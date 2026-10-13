# Supplied detector definitions

A host can add an organization detector without editing Scan's built-in registry.
Supply a closed JSON definition and its exact UTF-8 Semgrep rule bytes through
`runScan(request, { detectorDefinitions })` from `@aihq/scan/host`. The request uses
the definition's stable `detectorId`, empty configuration, and
`profileId: "host-process-uv-v1"`. The definition's `version` identifies the author's
rule revision. It is separate from the actual Semgrep version recorded in native
evidence. See `examples/detector-definitions` for a runnable host example.

The portable `DetectorDefinitionV1` type is exported by `@aihq/scan/contracts` and
its JSON Schema by `@aihq/scan/schemas/detector-definition/1.0.0.json`. Definitions
declare only an ID, revision, supported adapter/profile, and exact rule SHA-256 and
byte length. They cannot declare executable commands, callbacks, environment
changes, dependencies, or arbitrary profiles. The host supplies rule bytes, not
rule paths. Scan snapshots every bundle before capture, verifies valid UTF-8 and
the exact hash/length, and refuses unknown fields, duplicate IDs, built-in ID
shadowing, and unsupported adapters or profiles before any detector effect.

The first adapter is `semgrep-sarif-v1`, using Scan's existing pinned Semgrep and uv
host runtime. Rules are limited to 1 MiB and a call to 64 definitions. The host
profile has no isolation and cannot enforce network denial; its existing explicit
runtime prerequisites still apply. Rules are data for the supported analyzer, not
a new execution authority. Invalid Semgrep syntax becomes a detector failure.

Observations retain the custom detector ID and definition version. The complete
canonical definition is domain-separated into adapter identity, and rule identity
is the SHA-256 of the supplied bytes. Scope conservatively includes the complete
captured tree. Supplied external detectors always execute fresh: Scan cannot yet
establish all external tool/runtime byte identities before execution. A changed
definition or failed external sibling does not invalidate otherwise eligible
built-in observations. External reuse requires a future explicit runtime-identity
contract; identical reported version strings alone are insufficient.
