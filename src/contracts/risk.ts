import type { Code } from "./codes.js";
import { formats } from "./formats.js";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type SarifLevel = "error" | "warning" | "note" | "none";
export type RiskLabel = "SAFE" | "CAUTION" | "DO NOT INSTALL";
export type SummaryLabel = RiskLabel | "NOT ASSESSED";
export type Coverage = "complete" | "partial";
/** A finding's part: the file's routed part, `code` for inline commands, `none` for an unrouted file's secret check. */
export type FindingPart = "config" | "dependencies" | "code" | "text" | "none";

/** The fields `aih-risk/1` reads from one finding. */
export interface ScoredFinding {
  readonly tool: string;
  readonly ruleId: string;
  readonly code: Code;
  readonly severity?: Severity | undefined;
  readonly level?: SarifLevel | undefined;
  readonly confidence?: number | undefined;
  readonly part: FindingPart;
  readonly path: string;
  readonly line: number;
}

export interface CountedFinding extends ScoredFinding {
  readonly points: number;
  readonly value: number;
  readonly weight: number;
  readonly contribution: number;
}

const POINTS: Readonly<Record<Severity, number>> = Object.freeze({
  CRITICAL: 50,
  HIGH: 25,
  MEDIUM: 10,
  LOW: 5,
  INFO: 0,
});
const LEVEL_SEVERITY: Readonly<Record<SarifLevel, Severity>> = Object.freeze({
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "INFO",
});

/** `aih-risk/1`, published so readers can reproduce every step. */
export const scoring = Object.freeze({
  format: formats.scoring,
  points: POINTS,
  /** Step 1: SARIF `level` is used only when the tool gave no severity; an absent level is SARIF's default `warning`. */
  levelSeverity: LEVEL_SEVERITY,
  /** Step 4: weights of the 1st, 2nd, 3rd findings of one tool rule; later ones weigh nothing. */
  weights: Object.freeze([1, 0.5, 0.25]),
  codeMultiplier: 1.3,
  missingConfidence: 1,
  cap: 100,
  thresholds: Object.freeze([
    Object.freeze({ label: "SAFE" as const, min: 0, max: 20 }),
    Object.freeze({ label: "CAUTION" as const, min: 21, max: 50 }),
    Object.freeze({ label: "DO NOT INSTALL" as const, min: 51, max: 100 }),
  ]),
  order: Object.freeze(["SAFE", "CAUTION", "DO NOT INSTALL"] as const),
  /** Codes never scored (advisories are a separate call). */
  excludedCodes: Object.freeze(["trust.known-vulnerability"] as const),
});

export function severityOf(finding: Pick<ScoredFinding, "severity" | "level">): Severity {
  return finding.severity ?? LEVEL_SEVERITY[finding.level ?? "warning"];
}

const confidenceOf = (finding: ScoredFinding) => finding.confidence ?? scoring.missingConfidence;
const codeUnit = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

/**
 * Applies `aih-risk/1`:
 * 1. points from the tool's severity, else the SARIF level;
 * 2. findings sharing code, file and line count once (from one tool or several): keep the
 *    higher points, then higher confidence (missing = 1), then the tool name first in code-unit order;
 * 3. within each kept tool rule, order by points x confidence x part multiplier, highest first,
 *    equal values by path then line;
 * 4. weigh them 1, 1/2, 1/4, then 0;
 * 5. multiply by confidence and by 1.3 for part `code`;
 * 6. sum, round half up, cap at 100.
 */
export function scoreFindings(findings: readonly ScoredFinding[]): Readonly<{
  score: number;
  counted: readonly CountedFinding[];
}> {
  const kept = new Map<string, ScoredFinding>();
  for (const finding of findings) {
    if ((scoring.excludedCodes as readonly string[]).includes(finding.code)) continue;
    const key = JSON.stringify([finding.code, finding.path, finding.line]);
    const previous = kept.get(key);
    if (previous === undefined || prefer(finding, previous)) kept.set(key, finding);
  }
  const groups = new Map<string, ScoredFinding[]>();
  for (const finding of kept.values()) {
    const key = JSON.stringify([finding.tool, finding.ruleId]);
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }
  const counted: CountedFinding[] = [];
  let total = 0;
  for (const key of [...groups.keys()].sort(codeUnit)) {
    const ranked = (groups.get(key) ?? [])
      .map((finding) => ({ finding, points: POINTS[severityOf(finding)] }))
      .map((entry) => ({
        ...entry,
        value:
          entry.points *
          confidenceOf(entry.finding) *
          (entry.finding.part === "code" ? scoring.codeMultiplier : 1),
      }))
      .sort(
        (a, b) =>
          b.value - a.value ||
          codeUnit(a.finding.path, b.finding.path) ||
          a.finding.line - b.finding.line,
      );
    ranked.forEach((entry, index) => {
      const weight = scoring.weights[index] ?? 0;
      const contribution = entry.value * weight;
      total += contribution;
      counted.push(
        Object.freeze({
          ...entry.finding,
          points: entry.points,
          value: entry.value,
          weight,
          contribution,
        }),
      );
    });
  }
  return Object.freeze({ score: roundScore(total), counted: Object.freeze(counted) });
}

function prefer(candidate: ScoredFinding, current: ScoredFinding): boolean {
  const points = POINTS[severityOf(candidate)] - POINTS[severityOf(current)];
  if (points !== 0) return points > 0;
  const confidence = confidenceOf(candidate) - confidenceOf(current);
  if (confidence !== 0) return confidence > 0;
  return codeUnit(candidate.tool, current.tool) < 0;
}

/** Half up after removing binary floating-point noise below 1e-9; capped at 100. */
function roundScore(total: number): number {
  const cleaned = Math.round(total * 1e9) / 1e9;
  return Math.min(scoring.cap, Math.floor(cleaned + 0.5));
}

export function riskLabelForScore(score: number): RiskLabel {
  if (score <= 20) return "SAFE";
  if (score <= 50) return "CAUTION";
  return "DO NOT INSTALL";
}

/**
 * The summary's stored label: NOT ASSESSED when nothing is routable; otherwise the
 * score-derived label, raised from SAFE to CAUTION when coverage is partial. The score is unchanged.
 */
export function storedLabel(input: {
  readonly score: number;
  readonly coverage: Coverage;
  readonly routable: boolean;
}): SummaryLabel {
  if (!input.routable) return "NOT ASSESSED";
  const derived = riskLabelForScore(input.score);
  return input.coverage === "partial" && derived === "SAFE" ? "CAUTION" : derived;
}

/** A partial result displays as its stored label plus ` (partial)`. */
export function displayLabel(input: {
  readonly label: SummaryLabel;
  readonly coverage: Coverage;
}): string {
  return input.coverage === "partial" ? `${input.label} (partial)` : input.label;
}

/** `--fail-at` compares the stored label with SAFE < CAUTION < DO NOT INSTALL; NOT ASSESSED never meets it. */
export function failAtReached(label: SummaryLabel, threshold: RiskLabel): boolean {
  if (label === "NOT ASSESSED") return false;
  return scoring.order.indexOf(label) >= scoring.order.indexOf(threshold);
}
