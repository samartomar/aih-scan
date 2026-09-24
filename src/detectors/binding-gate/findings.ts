import { codeUnitCompare, deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import { isSourceRelativeUriV1, TRUST_LINT_UNTRUSTED_URI_V1 } from "../trust-lint/findings.js";
import type { FileTypographyVerdictV1 } from "./visible-typography.js";

/**
 * Finding/report model and SARIF 2.1.0 emission for `detector.aih-binding-gate`,
 * the Scan port of Core's `src/binding/scan-gate.ts` FAST-tier inspectors.
 *
 * Parity contract with Core: one SARIF result per finding (Core's
 * multiplicity), `ruleId` = Core's finding code (`binding.*` inspector codes,
 * or the trust-lint check code for the content-risk / suspicious-execution
 * dimensions), `message.text` = Core's detail unchanged, and under
 * `properties["aih-binding-gate/v1"]` everything else Core's `ScanFinding`
 * holds at detection time: `dimension`, `severity`, `coverage`, and on
 * content-risk findings the acceptance pin (`path`, `contentSha256`) plus
 * the per-file typography fact (`typography` or `dottedIBlocking`).
 * Core rebuilds each `ScanFinding` from those fields alone. The location is
 * the exact source-relative POSIX path and 1-based line where the finding
 * names a file. Severity uses Core's `DANGER_SEVERITY`/`GRADED_SEVERITY`
 * maps verbatim.
 *
 * What stays in Core (C2a decision 3): source resolution, digest checks
 * (including the identity-coverage report), acceptance matching, rollup,
 * closure classification, the typography overlay and the gate decision.
 */

export const BINDING_GATE_MAX_SCAN_BYTES_V1 = 512 * 1024;
export const BINDING_GATE_STRUCTURE_MAX_FILE_BYTES_V1 = 50 * 1024 * 1024;
export const BINDING_GATE_STRUCTURE_MAX_FILES_V1 = 20_000;
export const BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1 = 50;

/** Core's caps, grouped for capability/facts publication. */
export const BINDING_GATE_CAPS_V1 = Object.freeze({
  maxScanBytes: BINDING_GATE_MAX_SCAN_BYTES_V1,
  structureMaxFileBytes: BINDING_GATE_STRUCTURE_MAX_FILE_BYTES_V1,
  structureMaxFiles: BINDING_GATE_STRUCTURE_MAX_FILES_V1,
  maxFindingsPerDimension: BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1,
});

export type BindingGateSeverityV1 = "info" | "low" | "medium" | "high" | "critical";
export type BindingGateCoverageV1 = "complete" | "incomplete";

/**
 * One FAST-tier finding. Mirrors the detection-relevant fields of Core's
 * `ScanFinding` (`code`, `severity`, `detail`, `coverage`, and the
 * acceptance-pin `path` where Core sets one — content-risk findings only).
 * `location` is the SARIF locator (§1.4): present on every finding that names
 * a file, line 1 for Core's file-level findings (Core's `ScanFinding` carries
 * no line), and the trust-lint line for lint-derived findings.
 */
export interface BindingGateFindingV1 {
  readonly code: string;
  readonly severity: BindingGateSeverityV1;
  readonly detail: string;
  readonly coverage: BindingGateCoverageV1;
  /** Core's `ScanFinding.path` — set ONLY where Core sets it (content risk). */
  readonly path?: string;
  /** Core's `ScanFinding.contentSha256` acceptance pin — content risk only. */
  readonly contentSha256?: string;
  /** `classifyFileTypography(path, text)` — `trust.hidden-unicode` content risk only. */
  readonly typography?: FileTypographyVerdictV1;
  /** `fileHasBlockingTypographyChar(path, text, "\u0130")` — `trust.visible-unicode` only. */
  readonly dottedIBlocking?: boolean;
  readonly location?: Readonly<{ uri: string; startLine: number }>;
}

/** Core's `DimensionReport`: one D12 dimension's outcome. */
export interface BindingGateDimensionReportV1 {
  readonly dimension: string;
  readonly status: "produced" | "missing";
  readonly reason?: string;
  readonly findings: readonly BindingGateFindingV1[];
}

// Core's scan-gate.ts severity tables, verbatim: danger codes block at every
// posture; graded content findings surface at medium; anything else is medium.
const DANGER_SEVERITY: Readonly<Record<string, BindingGateSeverityV1>> = {
  "trust.malicious-code": "critical",
  "trust.prompt-injection": "high",
  "trust.hidden-unicode": "high",
};
const GRADED_SEVERITY: Readonly<Record<string, BindingGateSeverityV1>> = {
  "trust.external-egress": "medium",
  "trust.visible-unicode": "medium",
};

/** Core's `findingFromCode` severity resolution (`code ?? "trust.finding"`). */
export function bindingGateSeverityForCodeV1(code: string | undefined): BindingGateSeverityV1 {
  const resolved = code ?? "trust.finding";
  return DANGER_SEVERITY[resolved] ?? GRADED_SEVERITY[resolved] ?? "medium";
}

// -- SARIF 2.1.0 emission ------------------------------------------------------

export interface BindingGateSarifResultV1 {
  readonly ruleId: string;
  readonly level: "error" | "warning" | "note";
  readonly message: Readonly<{ text: string }>;
  readonly properties: Readonly<{
    "aih-binding-gate/v1": Readonly<{
      dimension: string;
      severity: BindingGateSeverityV1;
      coverage: BindingGateCoverageV1;
      path?: string;
      contentSha256?: string;
      typography?: FileTypographyVerdictV1;
      dottedIBlocking?: boolean;
    }>;
  }>;
  readonly locations?: readonly Readonly<{
    physicalLocation: Readonly<{
      artifactLocation: Readonly<{ uri: string }>;
      region: Readonly<{ startLine: number }>;
    }>;
  }>[];
}

export interface BindingGateSarifV1 {
  readonly $schema: string;
  readonly version: "2.1.0";
  readonly runs: readonly [
    Readonly<{
      tool: Readonly<{
        driver: Readonly<{
          name: "aih-binding-gate";
          version: "1.0.0";
          informationUri: string;
          rules: readonly Readonly<{
            id: string;
            name: string;
            shortDescription: Readonly<{ text: string }>;
          }>[];
        }>;
      }>;
      properties: Readonly<{
        "aih-binding-gate/v1": Readonly<{
          format: "aih-binding-gate-report";
          version: 1;
          dimensions: readonly Readonly<{
            name: string;
            status: "produced" | "missing";
            reason?: string;
            findingCount: number;
          }>[];
        }>;
      }>;
      results: readonly BindingGateSarifResultV1[];
    }>,
  ];
}

/**
 * Result bound: at least Scan's snapshot entry bound. Core caps nine
 * dimensions at 50 findings but not the two content dimensions, so a
 * finding-dense tree must still complete; above the bound the run fails
 * closed rather than emitting a partial list.
 */
const MAX_SARIF_RESULTS = 100_000;
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/samartomar/aih-scan";

const RULE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  "binding.binaries.blob": "binary/executable blob in the source tree",
  "binding.hooks.dir": "file under a hooks/ surface",
  "binding.hooks.settings": "settings file declares hook events",
  "binding.licenses.missing": "no LICENSE file or package.json license field found",
  "binding.mcp.declaration": "MCP server declaration in the source tree",
  "binding.network-update": "network or auto-update shape in a text surface",
  "binding.scripts.install-script": "install/setup script that executes on install",
  "binding.scripts.present": "script files present in the source tree",
  "binding.structure.file-count": "source tree exceeds the structure file-count limit",
  "binding.structure.large-file": "unusually large file in the source tree",
  "binding.telemetry": "telemetry/analytics marker in a text surface",
  "binding.write-destinations": "write destination outside the source tree",
  "trust.external-egress":
    "authenticated external request using an environment-provided credential",
  "trust.finding": "unclassified trust finding",
  "trust.hidden-unicode": "invisible/control Unicode can smuggle model-readable instructions",
  "trust.malicious-code": "bundled script matches a raw malicious-code shape",
  "trust.prompt-injection": "prompt-injection or secret-exfiltration instruction",
  "trust.visible-unicode": "ordinary visible Unicode on a trust surface",
};

function sarifLevel(severity: BindingGateSeverityV1): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "note";
}

/** Core's boundary URI rule; anything else is written as `untrusted-document`. */
function sarifUri(uri: string): string {
  return isSourceRelativeUriV1(uri) ? uri : TRUST_LINT_UNTRUSTED_URI_V1;
}

/**
 * Projects dimension reports into a frozen SARIF 2.1.0 document, in report
 * order and finding order (Core's multiplicity). A `missing` dimension emits
 * no results; it is recorded under `runs[0].properties` so Core's gate can
 * mint its own incomplete-coverage finding (rollup/decision stay in Core).
 */
export function bindingGateReportsToSarifV1(
  reports: readonly BindingGateDimensionReportV1[],
): BindingGateSarifV1 {
  const resultCount = reports.reduce((total, report) => total + report.findings.length, 0);
  if (resultCount > MAX_SARIF_RESULTS)
    throw new TypeError("binding-gate: finding count exceeds the SARIF result bound");
  const codes = [
    ...new Set(reports.flatMap((report) => report.findings.map((finding) => finding.code))),
  ].sort(codeUnitCompare);
  const results: BindingGateSarifResultV1[] = [];
  for (const report of reports) {
    for (const finding of report.findings) {
      let locations: BindingGateSarifResultV1["locations"];
      if (finding.location !== undefined) {
        if (!Number.isSafeInteger(finding.location.startLine) || finding.location.startLine < 1)
          throw new TypeError("binding-gate: finding start line must be a positive integer");
        locations = [
          {
            physicalLocation: {
              artifactLocation: { uri: sarifUri(finding.location.uri) },
              region: { startLine: finding.location.startLine },
            },
          },
        ];
      }
      results.push({
        ruleId: finding.code,
        level: sarifLevel(finding.severity),
        message: { text: finding.detail },
        properties: {
          "aih-binding-gate/v1": {
            dimension: report.dimension,
            severity: finding.severity,
            coverage: finding.coverage,
            ...(finding.path === undefined ? {} : { path: finding.path }),
            ...(finding.contentSha256 === undefined
              ? {}
              : { contentSha256: finding.contentSha256 }),
            ...(finding.typography === undefined ? {} : { typography: finding.typography }),
            ...(finding.dottedIBlocking === undefined
              ? {}
              : { dottedIBlocking: finding.dottedIBlocking }),
          },
        },
        ...(locations === undefined ? {} : { locations }),
      });
    }
  }
  const document: BindingGateSarifV1 = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "aih-binding-gate",
            version: "1.0.0",
            informationUri: INFORMATION_URI,
            rules: codes.map((code) => ({
              id: code,
              name: code,
              shortDescription: { text: RULE_DESCRIPTIONS[code] ?? code },
            })),
          },
        },
        properties: {
          "aih-binding-gate/v1": {
            format: "aih-binding-gate-report",
            version: 1,
            dimensions: reports.map((report) => ({
              name: report.dimension,
              status: report.status,
              ...(report.reason === undefined ? {} : { reason: report.reason }),
              findingCount: report.findings.length,
            })),
          },
        },
        results,
      },
    ],
  };
  return deepFreezeStrictJsonV1(structuredClone(document)) as BindingGateSarifV1;
}
