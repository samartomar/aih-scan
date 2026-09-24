import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";

/**
 * The Core check codes this detector emits, exactly as Core's trust scan names
 * them — the closed set of 13 `TRUST_LINT_RULES` (C2a §2.3). They double as
 * the SARIF `ruleId` of every emitted result. Grading (posture warn/deny
 * mapping), acknowledgements and MCP policy decisions stay in Core — every
 * detection here is a raw `fail`-grade finding.
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

/** Where an MCP server description finding came from (C2a §2.3). */
export interface TrustLintMcpDescriptionV1 {
  /** The declared config path, as sent in `detectorOptions.mcpConfigPaths`. */
  readonly configPath: string;
  /** `mcpServers`, `servers` or `mcp`. */
  readonly mapKey: string;
  /** The raw server map key (not `safeMcpName`-normalized). */
  readonly server: string;
}

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
  /** Present only on MCP server description lint findings (§2.2(5)). */
  readonly mcpDescription?: TrustLintMcpDescriptionV1;
}

/** `runs[0].properties["aih-trust/v1"]` (C2a §2.6). */
export interface TrustLintRunFactsV1 {
  readonly trustDocumentCount: number;
  readonly repositoryLicenseFile: string | null;
}

export interface TrustLintLintLineV1 {
  readonly line: number;
  readonly codes: readonly string[];
}

/** Per-file classification facts (C2a §2.6). */
export interface TrustLintFileFactsV1 {
  readonly strictUnicodeSurface: boolean;
  readonly legalText: boolean;
  readonly unicodeRisk: Readonly<{ category: string; code: string; reason: string }> | null;
  readonly lintLines: readonly TrustLintLintLineV1[];
  readonly yr4CorepackIntegrityOnly?: true;
}

/** A file above the fact bound, or one that could not be read. */
export interface TrustLintUnreadableFileFactsV1 {
  readonly unreadable: true;
}

export interface TrustLintArtifactV1 {
  readonly uri: string;
  readonly facts: TrustLintFileFactsV1 | TrustLintUnreadableFileFactsV1;
}

/** The SARIF property/fingerprint key Core reads (`TRUST_LINT_FINGERPRINT_KEY`). */
export const TRUST_LINT_PROPERTY_KEY_V1 = "aih-trust/v1";
export const TRUST_LINT_DETECTOR_ID_V1 = "detector.aih-trust-lint";
/** Fallback artifact URI for a path that is not source-relative (Core's `safeUri`). */
export const TRUST_LINT_UNTRUSTED_URI_V1 = "untrusted-document";

export interface TrustLintSarifResultV1 {
  readonly ruleId: TrustLintCheckCodeV1;
  readonly level: "error";
  readonly message: Readonly<{ text: string }>;
  readonly locations: readonly [
    Readonly<{
      physicalLocation: Readonly<{
        artifactLocation: Readonly<{ uri: string }>;
        region: Readonly<{ startLine: number }>;
      }>;
    }>,
  ];
  readonly fingerprints: Readonly<{ "aih-trust/v1": string }>;
  readonly properties?: Readonly<{
    "aih-trust/v1": Readonly<{ mcpDescription: TrustLintMcpDescriptionV1 }>;
  }>;
}

export interface TrustLintSarifV1 {
  readonly version: "2.1.0";
  readonly runs: readonly [
    Readonly<{
      tool: Readonly<{ driver: Readonly<{ name: "aih-trust-lint"; version: "1.0.0" }> }>;
      properties: Readonly<{
        "aih-trust/v1": Readonly<{ format: "aih-trust-lint-facts"; version: 1 }> &
          TrustLintRunFactsV1;
      }>;
      artifacts: readonly Readonly<{
        location: Readonly<{ uri: string }>;
        properties: Readonly<{
          "aih-trust/v1": TrustLintFileFactsV1 | TrustLintUnreadableFileFactsV1;
        }>;
      }>[];
      results: readonly TrustLintSarifResultV1[];
    }>,
  ];
}

/**
 * Result bound: at least Scan's snapshot entry bound, so a finding-dense tree
 * Core scans completes instead of failing on the count. Above it the run
 * fails closed rather than emitting a partial result list.
 */
const MAX_SARIF_RESULTS = 100_000;

/**
 * Core's boundary rule for a SARIF artifact URI (`isSourceRelativeSarifUriV1`
 * in Core's `src/trust/trust-lint-sarif.ts`): a source-relative POSIX path,
 * with no leading `/`, drive letter, scheme, backslash, or empty, `.` or `..`
 * segment. Core refuses the whole result on any other URI, so a location that
 * fails it is written as {@link TRUST_LINT_UNTRUSTED_URI_V1}, the name Core's
 * own lint already uses for an unsafe path.
 */
export function isSourceRelativeUriV1(uri: string): boolean {
  if (uri.length === 0 || uri.includes("\\") || uri.startsWith("/")) return false;
  if (/^[A-Za-z]:/.test(uri) || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(uri) || /^file:/i.test(uri))
    return false;
  return !uri.split("/").some((part) => part === ".." || part === "." || part.length === 0);
}

function resultOf(finding: TrustLintFindingV1): TrustLintSarifResultV1 {
  if (!Number.isSafeInteger(finding.location.startLine) || finding.location.startLine < 1)
    throw new TypeError("trust-lint: finding start line must be a positive integer");
  if (finding.fingerprint.length === 0)
    throw new TypeError("trust-lint: every finding carries a fingerprint");
  const uri = isSourceRelativeUriV1(finding.location.uri)
    ? finding.location.uri
    : TRUST_LINT_UNTRUSTED_URI_V1;
  return {
    ruleId: finding.code,
    level: "error",
    message: { text: finding.detail },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: finding.location.startLine },
        },
      },
    ],
    fingerprints: { "aih-trust/v1": finding.fingerprint },
    ...(finding.mcpDescription === undefined
      ? {}
      : { properties: { "aih-trust/v1": { mcpDescription: { ...finding.mcpDescription } } } }),
  };
}

/**
 * Projects detections, run facts and per-file facts into the frozen SARIF
 * 2.1.0 document Core reads (C2a §2.3, §2.6): one result per detection in
 * emission order, `ruleId` = Core's check code, `message.text` = Core's
 * ungraded detail, `fingerprints["aih-trust/v1"]` = Core's content
 * fingerprint, `properties["aih-trust/v1"].mcpDescription` on MCP description
 * results only; `runs[0].properties["aih-trust/v1"]` holds the run facts and
 * `runs[0].artifacts[]` one entry per file of the sealed tree.
 */
export function trustLintSarifV1(input: {
  readonly findings: readonly TrustLintFindingV1[];
  readonly runFacts: TrustLintRunFactsV1;
  readonly artifacts: readonly TrustLintArtifactV1[];
}): TrustLintSarifV1 {
  if (input.findings.length > MAX_SARIF_RESULTS)
    throw new TypeError("trust-lint: finding count exceeds the SARIF result bound");
  const document: TrustLintSarifV1 = {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "aih-trust-lint", version: "1.0.0" } },
        properties: {
          "aih-trust/v1": {
            format: "aih-trust-lint-facts",
            version: 1,
            trustDocumentCount: input.runFacts.trustDocumentCount,
            repositoryLicenseFile: input.runFacts.repositoryLicenseFile,
          },
        },
        artifacts: input.artifacts.map((artifact) => ({
          location: { uri: artifact.uri },
          properties: { "aih-trust/v1": artifact.facts },
        })),
        results: input.findings.map(resultOf),
      },
    ],
  };
  return deepFreezeStrictJsonV1(structuredClone(document)) as TrustLintSarifV1;
}
