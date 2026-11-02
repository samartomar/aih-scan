# Contracts published by `@aihq/scan`

Every format and rule set this package produces or reads across a package boundary, the
source that defines it, and what a reader returns for a version it does not know.
Compatibility follows these identifiers, never package versions. The source is the
contract; `tests/contracts-v1/contracts-doc.test.ts` checks that every identifier below is
the one the source exports and that every named source file exists.

No function throws on bad input. Every result has `status`: `ok`, `refused` with a reason,
`invalid`, or `unsupported-version` — the last for a document whose `format` names a known
family at another version (for example a summary whose format is `…/2`). Scan results inform; none of
them approves or blocks an installation.

## Documents

| Format | Defined in | Published schema | Reader | Unknown version |
|---|---|---|---|---|
| `aih-scan-request/1` | `src/contracts/validate.ts` (`validateRequest`) | `schemas/aih-scan-request-1.json` | `scan`, `validateRequest` | `unsupported-version`; `scan` writes nothing |
| `aih-scan-source/1` | `src/contracts/validate.ts` (`validateSource`) | `schemas/aih-scan-source-1.json` | `scan`, `validateSource` | `unsupported-version` |
| `aih-scan-summary/1` | `src/contracts/validate.ts` (`validateSummary`) | `schemas/aih-scan-summary-1.json` | `readSummary`, `matchScan`, `verifySummary` | `unsupported-version` |
| `aih-scan-withdrawn/1` | `src/contracts/validate.ts` (`validateWithdrawn`) | `schemas/aih-scan-withdrawn-1.json` | `verifySummary` (withdrawals), `validateWithdrawn` | the withdrawal does not apply and is reported |
| SARIF 2.1.0, one run per tool | `src/host/assess.ts` | — | `readFindings` | refused unless the summary pins its SHA-256 |
| Sigstore bundle v0.3, `messageSignature` | `src/read/sigstore/bundle.ts` | — | `verifySummary` | v0.1/v0.2/v0.4 `unsupported-version`; DSSE, bare keys and in-bundle chains `refused` (`unsupported-profile`) |

## Rules and data (`@aihq/scan/contracts`)

Every runtime export of `@aihq/scan/contracts` is listed in the Export column below, and
nothing else is exported; `tests/contracts-v1/contracts-doc.test.ts` checks both directions.

| Identifier | Export | Defined in | Meaning |
|---|---|---|---|
| Format identifiers | `formats` | `src/contracts/formats.ts` | The identifiers in this file; compatibility follows them |
| Documents above | `schemas`, `validateRequest`, `validateSource`, `validateSummary`, `validateWithdrawn` | `src/contracts/schemas.ts`, `src/contracts/validate.ts` | The JSON Schemas and the validators that add the cross-field rules a schema cannot express |
| `aih-scan-routing/1` | `routing`, `routeFile`, `toolsForPart`, `kinds`, `optionalTools` | `src/contracts/routing.ts` | One part per file (Config, Dependencies, Code, Text, else not analysed), the tools per part, the source-route item layouts, the item kinds and the tool names a request may select |
| `aih-risk/1` | `scoring`, `scoreFindings`, `storedLabel`, `displayLabel`, `failAtReached`, `riskLabelForScore`, `severityOf` | `src/contracts/risk.ts` | Points, cross-tool deduplication, diminishing weights, confidence, code multiplier, rounding, cap, labels and the coverage adjustment; `riskLabelForScore` is the score-only label and `severityOf` the severity a finding is scored at (`INFO` scores zero points) |
| `aih-codes/1` | `codes`, `scanCodes`, `advisoryCodes`, `toolRuleCodes`, `toolCategoryCodes`, `codeForRule`, `isScanCode` | `src/contracts/codes.ts` | Every tool rule maps to one code; an unmapped rule is `trust.unmapped-rule` and still scored; `trust.known-vulnerability` appears only in advisory results |
| `aih-scan-limits/1` | `limits` | `src/contracts/limits.ts` | Input limits (refused, exit 2), the per-tool time limit (`not-run`, `timeout`) and output bounds of the readers (summary, SARIF, Sigstore bundle and trusted-root bytes; finding text) |
| Untrusted text | `sanitizeText` | `src/contracts/text.ts` | The rule readers apply to text they return: control, format and separator characters removed, length cut to a limit |
| `aih-sigstore-keyless/1` | `verification`, `defaultSigners`, `sigstoreTrustedRootText` | `src/contracts/verification.ts`, `src/contracts/sigstore-trusted-root.ts` | The only accepted signature profile, its encodings and algorithms, the default trusted publisher and the pinned Sigstore trust snapshot (also shipped as `trust/sigstore-trusted-root.json`) |
| Scan key `git-sha1:` / `git-sha256:` | `scanKeyOf`, `SCAN_KEY_PATTERN`, `keyFolderName` | `src/contracts/git-tree.ts` | The Git tree hash of the folder handed over (`scanKeyOf` resolves to `{ status: "ok", scanKey }` or a problem: unsafe paths `refused`, repeated paths, file-and-folder clashes and bad modes `invalid`, no WebCrypto `refused` `crypto-unavailable`); storage folders write the colon as a hyphen |
| Package identity | `packageIdentity` | `src/public/package-identity.ts` | The package name and version that produce `scanner` in a summary |

## Results and statuses

| Result | Where | Meaning |
|---|---|---|
| `ok`, `refused`, `invalid`, `unsupported-version` | every function | see above |
| `cancelled` | `scan` result and item results; the CLI exits 130 | The caller's signal (or Ctrl-C) stopped the run; finished results are kept, unfinished items are `cancelled` |
| `refused` `items-not-scanned` | `scan` | At least one item was not scanned (refused, invalid or cancelled); the others are kept |

## Entry points

| Entry | Contents | Runtime |
|---|---|---|
| `@aihq/scan/host` | `scan`, `matchScan(summaryOrVerified, folderPath)` | Node |
| `@aihq/scan/read` | `readSummary`, `readFindings`, `verifySummary`, `matchScan(summaryOrVerified, files)`, `checkAdvisories`, `FINDINGS_MISMATCH_MESSAGE` (the only text shown when findings do not match a scan) | browser-safe: no Node globals or built-ins |
| `@aihq/scan/contracts` | the data and validators above | browser-safe |
| `@aihq/scan/schemas/*.json` | the four JSON Schemas above | data |
| `aih-scan` | `scan`, `advisories`, `read`, `findings`, `verify`, `sign` | Node CLI |

There is no root (`@aihq/scan`) entry. Earlier formats (report, artifact, item-record,
run-result, attestation V1/V2, baseline-vet) are neither read nor produced.
