import { decodeStrictUtf8V1, parseStrictJsonObjectV1 } from "../contract/strict-json-v1.js";

/**
 * Coordinator decision D30 (revised 20:58Z, U1i): a Cisco run is complete only when every
 * `analyzers_failed` entry Cisco reports is its documented fallback. Cisco 2.1.0 records a
 * skill whose manifest does not load as `{"analyzer": "skill_loader", "error":
 * "SkillLoadError:<code>"}`, still scans the package body as inert content, and says so with a
 * SKILL_LOAD_FALLBACK_USED finding. That entry is accepted for a skill only when it is the
 * skill's one `skill_loader` entry, the same skill result carries a SKILL_LOAD_FALLBACK_USED
 * finding, and the SARIF carries that finding's counterpart result located in the same skill.
 * Any other entry fails at stage `coverage`, naming each analyzer and error; a malformed
 * `analyzers_failed` fails at `output`; an absent key or an empty array is complete.
 *
 * `scan-all` reports the list per `results[i]`; the single-skill `scan` (source-tree and shard
 * jobs, the OCI capture) at its report's top level.
 */

/** The analyzer Cisco names for a manifest that did not load. */
export const CISCO_SKILL_LOADER_ANALYZER_V1 = "skill_loader";
/** The rule of the finding Cisco reports when it scanned a skill in fallback mode. */
export const CISCO_SKILL_LOAD_FALLBACK_RULE_V1 = "SKILL_LOAD_FALLBACK_USED";

/**
 * A D30 failure. `coverage`: Cisco reported a failed analyzer that is not the matched
 * fallback. `output`: the JSON report, or its `analyzers_failed`, is unreadable or malformed.
 * A `coverage` message starts with {@link CISCO_FAILED_ANALYZERS_PREFIX_V1}; an `output`
 * message names the Cisco JSON report and carries no analyzer text.
 */
export class CiscoAnalyzerFailureV1 extends TypeError {
  readonly stage: "coverage" | "output";
  constructor(stage: "coverage" | "output", message: string) {
    super(`${CISCO_REPORT_PREFIX_V1}${message}`);
    this.name = "CiscoAnalyzerFailureV1";
    this.stage = stage;
  }
}

/** How every D30 failure message starts; the runner classifies it by this prefix. */
export const CISCO_REPORT_PREFIX_V1 = "aih-scan Cisco report: ";
/** How every D30 coverage failure message starts; the runner classifies it by this prefix. */
export const CISCO_FAILED_ANALYZERS_PREFIX_V1 = `${CISCO_REPORT_PREFIX_V1}Cisco reported failed analyzers: `;

const malformed = (what: string): never => {
  throw new CiscoAnalyzerFailureV1("output", `Cisco JSON report ${what} is malformed`);
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** One failed analyzer as Cisco reports it. */
export type CiscoFailedAnalyzerV1 = Readonly<{ analyzer: string; error: string }>;

/**
 * The entries of one `analyzers_failed` value: none when absent; otherwise an array of
 * objects holding exactly a string `analyzer` and a string `error`, as Cisco 2.1.0 writes
 * them. Anything else fails at `output`.
 */
export function ciscoFailedAnalyzersV1(value: unknown, where: string): CiscoFailedAnalyzerV1[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) malformed(`analyzers_failed at ${where}`);
  return (value as unknown[]).map((entry) => {
    if (
      !isPlainObject(entry) ||
      Object.keys(entry).sort().join(",") !== "analyzer,error" ||
      typeof entry.analyzer !== "string" ||
      typeof entry.error !== "string"
    )
      return malformed(`analyzers_failed entry at ${where}`);
    return { analyzer: entry.analyzer, error: entry.error };
  });
}

/** What one skill's report and SARIF say about its failed analyzers. */
export type CiscoSkillAnalyzersV1 = Readonly<{
  /** How the skill is named in a failure: its source-relative directory, or a report part. */
  label: string;
  failed: readonly CiscoFailedAnalyzerV1[];
  /** SKILL_LOAD_FALLBACK_USED findings in the skill's own JSON result. */
  fallbackFindings: number;
  /** Their SARIF counterparts with that rule, located in the same skill. */
  fallbackCounterparts: number;
}>;

/** A source-relative skill directory as a failure names it. */
export function ciscoSkillLabelV1(skill: string): string {
  return skill === "" ? "the root skill" : skill;
}

/**
 * Throws the D30 `coverage` failure when any skill reports a failed analyzer that is not the
 * matched `skill_loader` fallback; the message names every such skill's analyzers and errors.
 */
export function assertCiscoAnalyzersCompleteV1(skills: readonly CiscoSkillAnalyzersV1[]): void {
  const parts: string[] = [];
  for (const skill of skills) {
    if (skill.failed.length === 0) continue;
    const loaders = skill.failed.filter(
      (entry) => entry.analyzer === CISCO_SKILL_LOADER_ANALYZER_V1,
    ).length;
    let reason: string | undefined;
    if (loaders !== skill.failed.length) reason = "";
    else if (loaders > 1) reason = "more than one skill_loader failure";
    else if (skill.fallbackFindings === 0)
      reason = `no ${CISCO_SKILL_LOAD_FALLBACK_RULE_V1} finding in that skill`;
    else if (skill.fallbackCounterparts === 0)
      reason = `its ${CISCO_SKILL_LOAD_FALLBACK_RULE_V1} finding has no SARIF counterpart in that skill`;
    if (reason === undefined) continue;
    const named = skill.failed.map((entry) => `${entry.analyzer} (${entry.error})`).join(", ");
    parts.push(`${named} ${skill.label}${reason === "" ? "" : `: ${reason}`}`);
  }
  if (parts.length > 0)
    throw new CiscoAnalyzerFailureV1(
      "coverage",
      `Cisco reported failed analyzers: ${parts.join("; ")}`,
    );
}

/**
 * The single-skill JSON report `skill-scanner scan` writes (`--format json --output-json`),
 * read with the one strict parser: an object with a string `skill_path` and a `findings`
 * array of objects with a string `rule_id`, and not the `scan-all` shape (`results` or
 * `summary`). Anything unreadable or malformed fails at `output`.
 */
export function ciscoSingleSkillReportV1(
  bytes: Uint8Array,
  label: string,
): Record<string, unknown> {
  let report: Record<string, unknown>;
  try {
    report = parseStrictJsonObjectV1(
      decodeStrictUtf8V1(bytes, "Cisco JSON report"),
      "Cisco JSON report",
    );
  } catch (error) {
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report of ${label} is invalid: ${error instanceof Error ? error.message : "JSON"}`,
    );
  }
  if (
    typeof report.skill_path !== "string" ||
    !Array.isArray(report.findings) ||
    Object.hasOwn(report, "results") ||
    Object.hasOwn(report, "summary")
  )
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report of ${label} is not a single-skill scan report`,
    );
  for (const finding of report.findings)
    if (!isPlainObject(finding) || typeof finding.rule_id !== "string")
      malformed(`finding of ${label}`);
  return report;
}

/**
 * D30 for a single-skill report ({@link ciscoSingleSkillReportV1}): its top-level
 * `analyzers_failed` belongs to the one skill it scanned, `skill` (source-relative). Every
 * SARIF result of that scan lies in the skill (the job and capture containment rules), so
 * `sarifRuleIds` lists the rule of each.
 */
export function assertCiscoSingleSkillAnalyzersCompleteV1(
  report: Record<string, unknown>,
  sarifRuleIds: readonly unknown[],
  skill: string,
): void {
  const label = `in ${ciscoSkillLabelV1(skill)}`;
  const failed = ciscoFailedAnalyzersV1(report.analyzers_failed, "the top level");
  const findings = Array.isArray(report.findings) ? report.findings : [];
  assertCiscoAnalyzersCompleteV1([
    {
      label,
      failed,
      fallbackFindings: findings.filter(
        (finding) =>
          isPlainObject(finding) && finding.rule_id === CISCO_SKILL_LOAD_FALLBACK_RULE_V1,
      ).length,
      fallbackCounterparts: sarifRuleIds.filter(
        (ruleId) => ruleId === CISCO_SKILL_LOAD_FALLBACK_RULE_V1,
      ).length,
    },
  ]);
}
