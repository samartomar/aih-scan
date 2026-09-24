import { z } from "zod";
import { scanTrustDependencyNamesV1 } from "./depnames.js";
import type { TrustLintFindingV1, TrustLintSarifV1 } from "./findings.js";
import { trustLintFindingsToSarifV1 } from "./findings.js";
import type { TrustLintTreeV1 } from "./inventory.js";
import {
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  scanTrustUnicodeDocumentV1,
} from "./lint.js";
import { scanNativeMaliciousCodeV1 } from "./malicious-code.js";
import { scanTrustManifestsV1 } from "./manifest.js";
import { isMaliciousCodeScanFilePathV1 } from "./script-files.js";
import {
  collectIncomingMcpConfigFilesV1,
  scanMcpConfigSecretsV1,
  scanPlaintextSecretsV1,
} from "./secrets.js";

/**
 * `detector.aih-trust-lint` — native trust/security findings, ported from
 * Core's `src/trust/**` detection layer. Pure analysis: no external process,
 * no network; the runtime drives it with an inventory/file-read seam
 * (`TrustLintTreeV1`, built from a real tree by `buildTrustLintTreeV1`).
 *
 * Failure behaviour (fail closed, matching Core): a file the inventory
 * listed but cannot be read throws `TypeError` naming the path; malformed
 * frontmatter YAML / package.json produces `trust.auto-exec-hook` findings
 * rather than throwing. Grading, posture, acknowledgements and MCP policy
 * (`mcp.policy-denied`, incoming-MCP classification) stay in Core — every
 * finding here is the raw pre-grading `fail` detection.
 */

const ROOT_TRUST_DOCS = new Set(["AGENTS.md", "CLAUDE.md", "GEMINI.md"]);

const MAX_INTERNAL_SCOPES = 256;
const optionsSchema = z.strictObject({
  internalScopes: z.array(z.string().min(1).max(256)).max(MAX_INTERNAL_SCOPES).optional(),
});

export interface TrustLintScanOptionsV1 {
  /** Internal npm scopes for `trust.dependency-confusion` (normalized like Core). */
  readonly internalScopes?: readonly string[];
}

function parseOptions(options: unknown): TrustLintScanOptionsV1 {
  if (options === undefined) return {};
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success)
    throw new TypeError(`trust-lint: invalid scan options (${parsed.error.issues[0]?.message})`);
  return parsed.data;
}

function extnameLower(name: string): string {
  const index = name.lastIndexOf(".");
  return index > 0 ? name.slice(index).toLowerCase() : "";
}

function shouldScanTrustDoc(rel: string): boolean {
  const parts = rel.split("/");
  const name = parts.at(-1) ?? "";
  if (name === "SKILL.md") return true;
  if (parts.length === 1 && ROOT_TRUST_DOCS.has(name)) return true;
  return extnameLower(name) === ".md";
}

function shouldScanStrictUnicodeSurface(rel: string): boolean {
  return isStrictUnicodeSurfaceV1(rel) || isMaliciousCodeScanFilePathV1(rel);
}

function mustRead(tree: TrustLintTreeV1, rel: string): string {
  const source = tree.readText(rel);
  if (source === undefined) throw new TypeError(`trust-lint: unreadable inventoried file ${rel}`);
  return source;
}

/**
 * Runs every native trust check over the tree in Core's `scanTrustTree`
 * order: per-document lint (full scan for trust docs, hidden-unicode-only for
 * strict unicode/script surfaces), then manifests, dependency names,
 * plaintext secrets, MCP config secrets, and native malicious code. Core
 * additionally runs incoming-MCP POLICY checks between the secret and
 * malicious-code batches; those are not detection and are not ported.
 */
export function scanTrustLintTreeV1(
  tree: TrustLintTreeV1,
  options?: TrustLintScanOptionsV1,
): TrustLintFindingV1[] {
  const parsed = parseOptions(options);
  const findings: TrustLintFindingV1[] = [];
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    if (shouldScanTrustDoc(rel)) {
      findings.push(...scanTrustDocumentV1(rel, mustRead(tree, rel)));
    } else if (shouldScanStrictUnicodeSurface(rel)) {
      findings.push(...scanTrustUnicodeDocumentV1(rel, mustRead(tree, rel)));
    }
  }
  findings.push(...scanTrustManifestsV1(tree));
  findings.push(...scanTrustDependencyNamesV1(tree, parsed.internalScopes ?? []));
  findings.push(...scanPlaintextSecretsV1(tree));
  findings.push(...scanMcpConfigSecretsV1(tree, collectIncomingMcpConfigFilesV1(tree)));
  findings.push(...scanNativeMaliciousCodeV1(tree));
  return findings;
}

/** Convenience: full tree scan projected straight to frozen SARIF 2.1.0. */
export function trustLintTreeToSarifV1(
  tree: TrustLintTreeV1,
  options?: TrustLintScanOptionsV1,
): TrustLintSarifV1 {
  return trustLintFindingsToSarifV1(scanTrustLintTreeV1(tree, options));
}

export {
  internalScopesFromEnvV1,
  POPULAR_PACKAGES_V1,
  scanTrustDependencyNamesV1,
} from "./depnames.js";
export type { TrustLintCheckCodeV1, TrustLintFindingV1, TrustLintSarifV1 } from "./findings.js";
export {
  TRUST_LINT_DETECTOR_ID_V1,
  trustLintFindingsToSarifV1,
} from "./findings.js";
export type { TrustLintFindingIdentityV1 } from "./fingerprint.js";
export { contentFindingFingerprintV1 } from "./fingerprint.js";
export type {
  TrustLintTreeEntryV1,
  TrustLintTreeOptionsV1,
  TrustLintTreeV1,
} from "./inventory.js";
export {
  buildTrustLintTreeV1,
  DEFAULT_TRUST_LINT_SKIP_DIRS_V1,
} from "./inventory.js";
export type { UnicodeRiskV1 } from "./lint.js";
export {
  classifyUnicodeRiskV1,
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  scanTrustUnicodeDocumentV1,
} from "./lint.js";
export { scanNativeMaliciousCodeV1 } from "./malicious-code.js";
export { scanTrustManifestsV1 } from "./manifest.js";
export {
  isInstallScriptEvidenceFilePathV1,
  isMaliciousCodeScanFilePathV1,
} from "./script-files.js";
export {
  collectIncomingMcpConfigFilesV1,
  INCOMING_MCP_CONFIG_FILES_V1,
  MCP_CONFIG_FILES_V1,
  scanMcpConfigSecretsV1,
  scanPlaintextSecretsV1,
} from "./secrets.js";
