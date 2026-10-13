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

## Run, read and handle failure

After building and installing a packed candidate in a disposable consumer, copy
`examples/detector-definitions` beside it and run `node scan.mjs /path/to/fixture`.
Use a temporary fixture tree. The example imports only supported package exports.
A second compatible definition changes the JSON ID/revision and exact rule bytes;
it uses the same adapter, without Core or Catalog changes.

A definition with a changed digest but unchanged bytes, a built-in detector ID,
an unknown adapter/profile, or nonempty request configuration returns a
`diagnostic` in the `request` phase before source capture. A supported definition
with unavailable uv returns a partial assessment with a `refused` detector.
Python discovery/availability or acquisition failure, invalid rule syntax, or
unsuccessful analyzer output produces `failed`. Inspect
`status`, `report.completion`, each detector's `outcome` and `diagnostics` before
interpreting observations. Zero findings and successful parsing grant no approval.

```js
import { prepareArtifact, runScan } from "@aihq/scan/host";
import { readArtifact } from "@aihq/scan/read";

const result = await runScan(request, { detectorDefinitions: [{ definition, rules }] });
if (result.status === "assessment") {
  const artifact = await prepareArtifact({
    report: result.report,
    annexes: result.annexes.map(({ id, bytesBase64 }) => ({
      id, bytes: Uint8Array.from(Buffer.from(bytesBase64, "base64")),
    })),
  });
  const parsed = await readArtifact(artifact.bytes);
  // Reading checks report/annex byte bindings. Authenticity is still unchecked.
}
```

Authentication is a separate host operation:
`authenticateArtifact({ bytes: artifact.bytes, expectedScanId: artifact.scanId, trust })` checks attestations
against independently selected keys/publisher policy. An unsigned artifact is
not authenticated; reading or attaching an attestation does not select trust.
See [artifact authentication](artifact-authentication.md) for complete trust and
failure examples. Source association then compares the checked evidence with
exact source/material identities; authentication alone does not prove that the
subject matches. A consumer may associate optional evidence through Core's
supported evidence boundary. Missing, refused or unauthenticated optional Scan
evidence does not create a mandatory Catalog or setup gate.

## Reuse custody

`createRetainedObservationsV1()` creates an opaque, process-local handle for
eligible successful built-in observations. Passing the same handle on a later
`runScan` still captures the current source and verifies all relevant bindings.
A JSON clone is refused as custody. Across processes, name prior artifact locations
in the request and supply independently selected `reuseTrust`; unsigned, untrusted,
changed or unsupported observations produce an explicit reuse miss and fresh work.
Preserve the original observation ID/time when reuse succeeds. This does not add
external analyzer reuse: supplied Semgrep definitions always execute fresh.
