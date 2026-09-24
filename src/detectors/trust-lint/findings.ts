import { codeUnitCompare, deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";

/**
 * The Core check codes this detector emits, exactly as Core's trust scan names
 * them. They double as the SARIF `ruleId` of every emitted result. Grading
 * (posture warn/deny mapping), acknowledgements and MCP policy decisions stay
 * in Core — every detection here is a raw `fail`-grade finding.
 */
export type TrustLintCheckCodeV1 =
  | "secrets.plaintext-detected"
  | "mcp.config-invalid"
  | "mcp.hardcoded-secret"
  | "trust.auto-exec-hook"
  | "trust.dependency-confusion"
  | "trust.external-egress"
  | "trust.hidden-unicode"
  | "trust.malicious-code"
  | "trust.permission-risk"
  | "trust.prompt-injection"
  | "trust.typosquat"
  | "trust.unpinned-dependency"
  | "trust.visible-unicode";

/**
 * One native trust detection. Mirrors the detection-relevant fields of Core's
 * `Check` (`src/internals/verify.ts`): same `name`, `detail`, `code`,
 * `location` and `fingerprint` strings Core produces, with the verdict fixed
 * to the raw pre-grading `fail`.
 */
export interface TrustLintFindingV1 {
  readonly name: string;
  readonly verdict: "fail";
  readonly detail: string;
  readonly code: TrustLintCheckCodeV1;
  readonly location: Readonly<{ uri: string; startLine: number }>;
  readonly fingerprint: string;
}

export interface TrustLintSarifV1 {
  readonly $schema: string;
  readonly version: "2.1.0";
  readonly runs: readonly [
    Readonly<{
      tool: Readonly<{
        driver: Readonly<{
          name: "aih-trust-lint";
          version: "1.0.0";
          informationUri: string;
          rules: readonly Readonly<{
            id: string;
            name: string;
            shortDescription: Readonly<{ text: string }>;
          }>[];
        }>;
      }>;
      results: readonly Readonly<{
        ruleId: string;
        level: "error";
        message: Readonly<{ text: string }>;
        partialFingerprints: Readonly<{ "aih-content-finding-v1": string }>;
        locations: readonly Readonly<{
          physicalLocation: Readonly<{
            artifactLocation: Readonly<{ uri: string }>;
            region: Readonly<{ startLine: number }>;
          }>;
        }>[];
      }>[];
    }>,
  ];
}

export const TRUST_LINT_DETECTOR_ID_V1 = "detector.aih-trust-lint";

const MAX_SARIF_RESULTS = 4096;
const MAX_SARIF_MESSAGE_LENGTH = 4096;
const MAX_SARIF_PATH_LENGTH = 1024;
const MAX_SARIF_FINGERPRINT_LENGTH = 512;
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/samartomar/aih-scan";

const RULE_DESCRIPTIONS: Readonly<Record<TrustLintCheckCodeV1, string>> = {
  "secrets.plaintext-detected": "plaintext secret material on disk",
  "mcp.config-invalid": "MCP config path could not be safely inspected",
  "mcp.hardcoded-secret": "hardcoded secret literal inside an MCP config file",
  "trust.auto-exec-hook": "manifest or hook that can execute automatically",
  "trust.dependency-confusion": "direct dependency uses a configured internal scope",
  "trust.external-egress":
    "authenticated external request using an environment-provided credential",
  "trust.hidden-unicode": "invisible/control Unicode can smuggle model-readable instructions",
  "trust.malicious-code": "bundled script matches a raw malicious-code shape",
  "trust.permission-risk": "manifest grants a broad or sensitive permission",
  "trust.prompt-injection": "prompt-injection or secret-exfiltration instruction",
  "trust.typosquat": "direct dependency is distance 1 from a popular package name",
  "trust.unpinned-dependency": "direct dependency is not pinned to an exact version",
  "trust.visible-unicode": "ordinary visible Unicode on a trust surface",
};

function sarifUri(uri: string): string {
  const normalized = uri
    .replace(/\\/g, "/")
    .replace(/^(?:\.\/)+/, "")
    .replace(/\/{2,}/g, "/");
  const hash = normalized.indexOf("#");
  const path = hash === -1 ? normalized : normalized.slice(0, hash);
  const fragment = hash === -1 ? "" : normalized.slice(hash + 1);
  const safePath =
    path.length > 0 &&
    path.length <= MAX_SARIF_PATH_LENGTH &&
    !path.startsWith("/") &&
    !/^[A-Za-z]:\//.test(path) &&
    !/[\\?%:]/.test(path) &&
    !path.endsWith("/") &&
    path.split("/").every((part) => part.length > 0 && part !== "." && part !== "..");
  // Core addresses MCP server description fields with a `#mcpServers.<name>.description`
  // virtual suffix on the config file path; that suffix is kept when well formed.
  const safeFragment = hash === -1 || /^[A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_.-]+)*$/.test(fragment);
  if (!safePath || !safeFragment) return "untrusted-document";
  return normalized;
}

function sarifMessage(detail: string): string {
  return detail.length > MAX_SARIF_MESSAGE_LENGTH
    ? detail.slice(0, MAX_SARIF_MESSAGE_LENGTH)
    : detail;
}

/**
 * Projects detections into a frozen SARIF 2.1.0 document: one result per
 * detection (Core's multiplicity), `ruleId` = Core's check code, location =
 * source-relative POSIX path + startLine, level `error` (Core applies posture
 * grading on top of this raw signal). The content-bound fingerprint is carried
 * as a partial fingerprint so Core's acknowledgement identity stays stable.
 */
export function trustLintFindingsToSarifV1(
  findings: readonly TrustLintFindingV1[],
): TrustLintSarifV1 {
  if (findings.length > MAX_SARIF_RESULTS)
    throw new TypeError("trust-lint: finding count exceeds the SARIF result bound");
  const codes = [...new Set(findings.map((finding) => finding.code))].sort(codeUnitCompare);
  const document: TrustLintSarifV1 = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "aih-trust-lint",
            version: "1.0.0",
            informationUri: INFORMATION_URI,
            rules: codes.map((code) => ({
              id: code,
              name: code,
              shortDescription: { text: RULE_DESCRIPTIONS[code] },
            })),
          },
        },
        results: findings.map((finding) => {
          if (finding.fingerprint.length > MAX_SARIF_FINGERPRINT_LENGTH)
            throw new TypeError("trust-lint: fingerprint exceeds the SARIF bound");
          if (!Number.isSafeInteger(finding.location.startLine) || finding.location.startLine < 1)
            throw new TypeError("trust-lint: finding start line must be a positive integer");
          return {
            ruleId: finding.code,
            level: "error" as const,
            message: { text: sarifMessage(finding.detail) },
            partialFingerprints: { "aih-content-finding-v1": finding.fingerprint },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: sarifUri(finding.location.uri) },
                  region: { startLine: finding.location.startLine },
                },
              },
            ],
          };
        }),
      },
    ],
  };
  return deepFreezeStrictJsonV1(structuredClone(document)) as TrustLintSarifV1;
}
