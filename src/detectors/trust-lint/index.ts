import { scanTrustDependencyNamesV1 } from "./depnames.js";
import { trustLintRunFactsV1, trustLintTreeArtifactFactsV1 } from "./facts.js";
import {
  isSourceRelativeUriV1,
  type TrustLintFindingV1,
  type TrustLintSarifV1,
  trustLintSarifV1,
} from "./findings.js";
import { buildTrustLintTreeV1, type TrustLintTreeV1 } from "./inventory.js";
import {
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  scanTrustUnicodeDocumentV1,
  shouldScanTrustDocV1,
} from "./lint.js";
import { scanNativeMaliciousCodeV1 } from "./malicious-code.js";
import { scanTrustManifestsV1 } from "./manifest.js";
import { scanMcpServerDescriptionsV1 } from "./mcp-description.js";
import { type TrustLintDetectorOptionsV1, validateTrustLintDetectorOptionsV1 } from "./options.js";
import { isMaliciousCodeScanFilePathV1 } from "./script-files.js";
import { scanMcpConfigSecretsV1, scanPlaintextSecretsV1 } from "./secrets.js";

/**
 * `detector.aih-trust-lint` — Core's native trust/security findings, ported
 * from Core's `src/trust/**` detection layer (C2a §2). Pure analysis: no
 * external process, no network.
 *
 * {@link runTrustLintV1} is the engine function behind the request Core sends
 * (`subject.sourceRoot`, `subject.selectedClosurePaths`, `detectorOptions`,
 * `signal`). It validates the subject and the options at the boundary (typed
 * refusals, nothing coerced), computes the findings in Core's order (§2.2),
 * the run and per-file facts (§2.6), and returns the SARIF 2.1.0 document and
 * its exact UTF-8 bytes (§2.3).
 *
 * Grading, posture, acknowledgements, the trust inventory itself and MCP
 * policy (`mcp.policy-denied`, incoming-MCP classification) stay in Core —
 * every finding here is the raw pre-grading `fail` detection.
 */

/** Refusal reasons; the B2 wiring maps them to Core's reasons of the same names. */
export type TrustLintRefusalReasonV1 = "detector-options-invalid" | "subject-requirement-unmet";

export type TrustLintRunOutcomeV1 =
  | Readonly<{ kind: "completed"; sarif: TrustLintSarifV1; sarifText: string }>
  | Readonly<{ kind: "refused"; reason: TrustLintRefusalReasonV1; detail: string }>
  | Readonly<{
      kind: "failed";
      stage: "execution";
      detail: string;
      cause?: "cancelled";
    }>;

export interface TrustLintRunRequestV1 {
  /** `subject.sourceRoot`: absolute realpath of the sealed root. */
  readonly sourceRoot: string;
  /** `subject.selectedClosurePaths`: Core's trust inventory, in Core's order. */
  readonly selectedClosurePaths: unknown;
  /** Required: exactly `{ internalScopes, mcpConfigPaths }` (§2.1). */
  readonly detectorOptions: unknown;
  readonly signal?: AbortSignal;
}

/** At least Scan's snapshot entry bound (C2a §1.3). */
const MAX_SELECTED_PATHS = 100_000;
const MAX_DETAIL_LENGTH = 300;

function shown(value: unknown): string {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
  const visible = text.replace(/[\p{C}]/gu, " ");
  return visible.length > 80 ? `${visible.slice(0, 77)}...` : visible;
}

function bounded(detail: string): string {
  const visible = detail.replace(/[\p{C}]/gu, " ");
  return visible.length > MAX_DETAIL_LENGTH
    ? `${visible.slice(0, MAX_DETAIL_LENGTH - 3)}...`
    : visible;
}

function refused(reason: TrustLintRefusalReasonV1, detail: string): TrustLintRunOutcomeV1 {
  return Object.freeze({ kind: "refused" as const, reason, detail: bounded(detail) });
}

/** Read through a call so the post-analysis check is not narrowed away. */
function aborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function cancelled(): TrustLintRunOutcomeV1 {
  return Object.freeze({
    kind: "failed" as const,
    stage: "execution" as const,
    detail: "trust lint was cancelled before it completed",
    cause: "cancelled" as const,
  });
}

/**
 * The declared selection must name files of the sealed tree: unique
 * source-relative POSIX paths, each a regular file or a symlink to a file
 * whose realpath stays inside the root. Anything else is a subject mismatch.
 */
function validateSelection(
  value: unknown,
  tree: TrustLintTreeV1,
): { selection: readonly string[] } | { refusal: string } {
  if (!Array.isArray(value)) return { refusal: "selectedClosurePaths must be an array of paths" };
  if (value.length > MAX_SELECTED_PATHS)
    return { refusal: `selectedClosurePaths exceeds the ${MAX_SELECTED_PATHS}-path bound` };
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    const at = `selectedClosurePaths[${index}]`;
    if (typeof entry !== "string" || !isSourceRelativeUriV1(entry))
      return { refusal: `${at} is not a source-relative POSIX path: ${shown(entry)}` };
    if (seen.has(entry)) return { refusal: `${at} repeats ${shown(entry)}` };
    seen.add(entry);
    const file = tree.fileEntry(entry);
    if (file === undefined)
      return { refusal: `${at} is not a file of the source tree: ${shown(entry)}` };
    if (!file.realpathContained)
      return { refusal: `${at} resolves outside the source root: ${shown(entry)}` };
  }
  return { selection: Object.freeze([...(value as string[])]) };
}

function mustRead(tree: TrustLintTreeV1, rel: string): string {
  const source = tree.readText(rel);
  if (source === undefined) throw new TypeError(`trust-lint: unreadable selected file ${rel}`);
  return source;
}

/**
 * Every native finding in Core's order (C2a §2.2): (1) per-document lint over
 * the selection — the full lint for trust documents, hidden Unicode only for
 * strict/script surfaces; (2) manifests; (3) dependency names; (4) plaintext
 * secrets over the tree, then MCP config secrets over the declared paths;
 * (5) MCP server description lint over the declared paths; (6) native
 * malicious code over the selection.
 */
export function scanTrustLintTreeV1(
  tree: TrustLintTreeV1,
  selection: readonly string[],
  options: TrustLintDetectorOptionsV1,
): TrustLintFindingV1[] {
  const findings: TrustLintFindingV1[] = [];
  for (const rel of selection) {
    if (shouldScanTrustDocV1(rel)) {
      findings.push(...scanTrustDocumentV1(rel, mustRead(tree, rel)));
    } else if (isStrictUnicodeSurfaceV1(rel) || isMaliciousCodeScanFilePathV1(rel)) {
      findings.push(...scanTrustUnicodeDocumentV1(rel, mustRead(tree, rel)));
    }
  }
  findings.push(...scanTrustManifestsV1(tree, selection));
  findings.push(...scanTrustDependencyNamesV1(tree, selection, options.internalScopes));
  findings.push(...scanPlaintextSecretsV1(tree));
  findings.push(...scanMcpConfigSecretsV1(tree, options.mcpConfigPaths));
  findings.push(...scanMcpServerDescriptionsV1(tree, options.mcpConfigPaths));
  findings.push(...scanNativeMaliciousCodeV1(tree, selection));
  return findings;
}

/**
 * The `detector.aih-trust-lint` engine function (C2a §2). Refusals come
 * before anything is analyzed: a malformed selection is
 * `subject-requirement-unmet`, malformed options `detector-options-invalid`.
 * An already-aborted signal fails with `cause: "cancelled"`; the analysis is
 * synchronous, so the signal is checked again before the result is returned.
 * An unreadable selected file fails the run (`stage: "execution"`); nothing
 * partial is returned.
 */
export function runTrustLintV1(request: TrustLintRunRequestV1): TrustLintRunOutcomeV1 {
  if (aborted(request.signal)) return cancelled();
  if (typeof request.sourceRoot !== "string" || request.sourceRoot.length === 0)
    return refused("subject-requirement-unmet", "sourceRoot must be a non-empty absolute path");
  let tree: TrustLintTreeV1;
  try {
    tree = buildTrustLintTreeV1(request.sourceRoot);
  } catch (error) {
    return refused(
      "subject-requirement-unmet",
      `source tree could not be enumerated: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
  const selection = validateSelection(request.selectedClosurePaths, tree);
  if ("refusal" in selection) return refused("subject-requirement-unmet", selection.refusal);
  const options = validateTrustLintDetectorOptionsV1(
    request.detectorOptions,
    tree,
    selection.selection,
  );
  if (!options.ok) return refused(options.reason, options.detail);
  let sarif: TrustLintSarifV1;
  try {
    sarif = trustLintSarifV1({
      findings: scanTrustLintTreeV1(tree, selection.selection, options.options),
      runFacts: trustLintRunFactsV1(tree, selection.selection),
      artifacts: trustLintTreeArtifactFactsV1(tree),
    });
  } catch (error) {
    return Object.freeze({
      kind: "failed" as const,
      stage: "execution" as const,
      detail: bounded(error instanceof Error ? error.message : "trust lint failed"),
    });
  }
  if (aborted(request.signal)) return cancelled();
  return Object.freeze({ kind: "completed" as const, sarif, sarifText: JSON.stringify(sarif) });
}

export { POPULAR_PACKAGES_V1, scanTrustDependencyNamesV1 } from "./depnames.js";
export { trustLintRunFactsV1, trustLintTreeArtifactFactsV1 } from "./facts.js";
export {
  isSourceRelativeUriV1,
  TRUST_LINT_DETECTOR_ID_V1,
  TRUST_LINT_PROPERTY_KEY_V1,
  TRUST_LINT_UNTRUSTED_URI_V1,
  type TrustLintArtifactV1,
  type TrustLintCheckCodeV1,
  type TrustLintFileFactsV1,
  type TrustLintFindingV1,
  type TrustLintMcpDescriptionV1,
  type TrustLintRunFactsV1,
  type TrustLintSarifResultV1,
  type TrustLintSarifV1,
  trustLintSarifV1,
} from "./findings.js";
export { contentFindingFingerprintV1, type TrustLintFindingIdentityV1 } from "./fingerprint.js";
export {
  buildTrustLintTreeV1,
  DEFAULT_TRUST_LINT_SKIP_DIRS_V1,
  type TrustLintPathKindV1,
  type TrustLintTreeEntryV1,
  type TrustLintTreeOptionsV1,
  type TrustLintTreeV1,
} from "./inventory.js";
export {
  classifyUnicodeRiskV1,
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  scanTrustUnicodeDocumentV1,
  shouldScanTrustDocV1,
  type UnicodeRiskV1,
} from "./lint.js";
export { scanNativeMaliciousCodeV1 } from "./malicious-code.js";
export { scanTrustManifestsV1 } from "./manifest.js";
export { safeMcpNameV1, scanMcpServerDescriptionsV1 } from "./mcp-description.js";
export {
  TRUST_LINT_OPTIONS_INVALID_REASON_V1,
  type TrustLintDetectorOptionsV1,
  type TrustLintOptionsValidationV1,
  validateTrustLintDetectorOptionsV1,
} from "./options.js";
export {
  isInstallScriptEvidenceFilePathV1,
  isMaliciousCodeScanFilePathV1,
} from "./script-files.js";
export {
  INCOMING_MCP_CONFIG_FILES_V1,
  MCP_CONFIG_FILES_V1,
  scanMcpConfigSecretsV1,
  scanPlaintextSecretsV1,
} from "./secrets.js";
