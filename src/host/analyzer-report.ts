import type { FindingPart, Severity } from "../contracts/risk.js";
import type { ScanMode } from "../contracts/validate.js";
import type { AssessItem, NotRunReason, ToolFinding, ToolRun } from "./tools.js";

/** A plain JSON object, or `undefined`. */
export function objectOf(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function notRun(
  reason: NotRunReason,
  mode: ScanMode,
  version: string,
  detail?: string,
): ToolRun {
  return Object.freeze({
    status: "not-run" as const,
    version,
    mode,
    reason,
    ...(detail === undefined ? {} : { detail }),
  });
}

/** The parts an external analyzer is routed: Text, Code and Config (`aih-scan-routing/1`). */
const ANALYZED_PARTS: ReadonlySet<FindingPart> = new Set(["text", "code", "config"]);

/**
 * One external analyzer finding placed on Scan's inventory: the file must be an item file
 * (a `./` prefix is removed) whose routed part the analyzer covers, so findings on Dependencies
 * or unrouted files and paths outside the item are dropped. Lines below 1 or missing become 1;
 * a confidence outside 0..1 is ignored.
 */
export function analyzerFinding(
  item: AssessItem,
  input: Readonly<{
    ruleId: string;
    message: string;
    file: unknown;
    line: unknown;
    severity: Severity | undefined;
    confidence: unknown;
    fingerprint?: string | undefined;
    category?: string | undefined;
  }>,
): ToolFinding | undefined {
  if (typeof input.file !== "string") return undefined;
  const path = input.file.startsWith("./") ? input.file.slice(2) : input.file;
  const part = item.routed.get(path)?.part;
  if (part === undefined || part === null || !ANALYZED_PARTS.has(part)) return undefined;
  const line =
    typeof input.line === "number" && Number.isSafeInteger(input.line) && input.line >= 1
      ? input.line
      : 1;
  const confidence =
    typeof input.confidence === "number" && input.confidence >= 0 && input.confidence <= 1
      ? input.confidence
      : undefined;
  return Object.freeze({
    ruleId: input.ruleId.slice(0, 256),
    message: input.message,
    path,
    line,
    part,
    ...(input.severity === undefined ? {} : { severity: input.severity }),
    ...(confidence === undefined ? {} : { confidence }),
    ...(input.fingerprint === undefined ? {} : { fingerprint: input.fingerprint }),
    ...(input.category === undefined ? {} : { category: input.category }),
  });
}
