import { createHash } from "node:crypto";
import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import type { TrustLintTreeV1 } from "../trust-lint/inventory.js";
import {
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  scanTrustUnicodeDocumentV1,
} from "../trust-lint/lint.js";
import { scanNativeMaliciousCodeV1 } from "../trust-lint/malicious-code.js";
import { isMaliciousCodeScanFilePathV1 } from "../trust-lint/script-files.js";
import {
  type BindingGateDimensionReportV1,
  type BindingGateFindingV1,
  bindingGateSeverityForCodeV1,
} from "./findings.js";
import { isBindingGateDocSurfaceV1 } from "./inspectors.js";
import { classifyFileTypographyV1, fileHasBlockingTypographyCharV1 } from "./visible-typography.js";

/**
 * The two content dimensions of Core's `src/binding/scan-gate.ts`, ported
 * verbatim over the tree seam and the ported trust-lint scanners:
 *
 * - `inspectContentRisk` (dimension `hidden-unicode`): for every inventoried
 *   file that is a doc surface (Core's `isDocSurface`, not trust-lint's
 *   trust-document predicate) the full document lint, else for a strict or
 *   script surface the hidden-Unicode-only lint; unreadable files are
 *   skipped. Each finding carries Core's acceptance pin: the comparable
 *   `path` and `contentSha256`, the sha256 of the CRLF-normalized UTF-8 text.
 *   Each also carries the typography fact Core's gate overlay reads for its
 *   code, computed over the same text: `typography` (Core's
 *   `classifyFileTypography` verdict) on `trust.hidden-unicode`, and
 *   `dottedIBlocking` (Core's `fileHasBlockingTypographyChar` for U+0130)
 *   on `trust.visible-unicode`. Whether and how the overlay applies stays in
 *   Core.
 * - `inspectSuspiciousExecution` (dimension `suspicious-execution`): the
 *   native malicious-code scan over every inventoried file. These findings
 *   carry no `path`, exactly like Core, so they can never be accepted.
 *
 * Multiplicity is Core's: one finding per lint or malicious-code check, with
 * no per-dimension cap (Core applies none to these two dimensions).
 */

const DOTTED_LATIN_CAPITAL_I = "\u0130";

function normalizedTextSha256(text: string): string {
  return createHash("sha256").update(text.replace(/\r\n/g, "\n"), "utf8").digest("hex");
}

/** Core's `toComparablePath`. */
function toComparablePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Core's `inspectContentRisk`. */
export function inspectBindingGateContentRiskV1(
  tree: TrustLintTreeV1,
  dimension = "hidden-unicode",
): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    const isDoc = isBindingGateDocSurfaceV1(rel);
    const isStrict = isStrictUnicodeSurfaceV1(rel) || isMaliciousCodeScanFilePathV1(rel);
    if (!isDoc && !isStrict) continue;
    const source = tree.readText(rel);
    if (source === undefined) continue;
    const path = toComparablePath(rel);
    const contentSha256 = normalizedTextSha256(source);
    const checks = isDoc
      ? scanTrustDocumentV1(rel, source)
      : scanTrustUnicodeDocumentV1(rel, source);
    let typography: BindingGateFindingV1["typography"];
    let dottedIBlocking: boolean | undefined;
    for (const check of checks) {
      if (check.code === "trust.hidden-unicode")
        typography ??= classifyFileTypographyV1(path, source);
      if (check.code === "trust.visible-unicode")
        dottedIBlocking ??= fileHasBlockingTypographyCharV1(path, source, DOTTED_LATIN_CAPITAL_I);
      findings.push({
        code: check.code,
        severity: bindingGateSeverityForCodeV1(check.code),
        detail: check.detail,
        coverage: "complete",
        path,
        contentSha256,
        ...(check.code === "trust.hidden-unicode" ? { typography } : {}),
        ...(check.code === "trust.visible-unicode" ? { dottedIBlocking } : {}),
        location: { uri: check.location.uri, startLine: check.location.startLine },
      });
    }
  }
  return deepFreezeStrictJsonV1(structuredClone({ dimension, status: "produced", findings }));
}

/** Core's `inspectSuspiciousExecution`. */
export function inspectBindingGateSuspiciousExecutionV1(
  tree: TrustLintTreeV1,
  dimension = "suspicious-execution",
): BindingGateDimensionReportV1 {
  const selection = tree.files.map((entry) => entry.relativePath);
  const findings: BindingGateFindingV1[] = scanNativeMaliciousCodeV1(tree, selection).map(
    (check) => ({
      code: check.code,
      severity: bindingGateSeverityForCodeV1(check.code),
      detail: check.detail,
      coverage: "complete",
      location: { uri: check.location.uri, startLine: check.location.startLine },
    }),
  );
  return deepFreezeStrictJsonV1(structuredClone({ dimension, status: "produced", findings }));
}
