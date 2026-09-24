import {
  assertCiscoAnalyzersCompleteV1,
  CISCO_SKILL_COVERAGE_MISMATCH_V1,
  CiscoAnalyzerFailureV1,
  ciscoFailedAnalyzersV1,
  ciscoSkillLabelV1,
} from "./cisco-analyzer-failures-v1.js";
import { ciscoSealedPathBinderV1 } from "./cisco-sealed-case-binding-v1.js";
import {
  type CiscoSarifResultIdentityV1,
  ciscoFallbackPairingV1,
  ciscoSarifResultIdentitiesV1,
  sourceRelativeSkillDirectoryV1,
} from "./sarif-source-relative-v1.js";

/**
 * Which skills a Cisco JSON report is evidence for (U1j, review of U1i). A report's
 * `analyzers_failed` decides completion (coordinator decision D30) only for the skill it
 * names, so every report is bound to the skill Scan asked Cisco to scan before it is read.
 */

/** A skill directory's manifest: the sealed path owner decision D1 binds. */
const manifest = (skill: string): string => (skill === "" ? "SKILL.md" : `${skill}/SKILL.md`);

/** A source-relative skill directory as a failure names it. */
const shown = (skill: string): string => (skill === "" ? "." : skill);

/** Where Scan relates a report's skill paths and which skills it expects. */
export type CiscoReportSkillContextV1 = Readonly<{
  /** The absolute root(s) the analyzer scanned under, as the SARIF side relates them. */
  sourceRoots: readonly string[];
  /** The source-relative skill directories Scan expects ("" is the root). */
  expected: readonly string[];
  /** Owner decision D1 binds a normcased path on win32 only. */
  platform: NodeJS.Platform;
}>;

/**
 * The source-relative skill directory a Cisco JSON report's `skill_path` names: related to
 * `sourceRoots` exactly as the SARIF side relates Cisco's paths, then, on win32 only, bound by
 * owner decision D1 to the unique expected skill whose manifest path is equal ignoring case
 * (Cisco 2.1.0 reports `os.path.normcase` paths). A missing, relative, unsafe or outside path,
 * or a D1 ambiguity, fails at `output`; a path that binds to no expected skill is returned as
 * related, for the caller to refuse.
 */
export function ciscoReportSkillDirectoryV1(
  skillPath: unknown,
  where: string,
  context: CiscoReportSkillContextV1,
): string {
  if (typeof skillPath !== "string")
    throw new CiscoAnalyzerFailureV1("output", `Cisco JSON report ${where} names no skill_path`);
  let skill: string;
  try {
    skill = sourceRelativeSkillDirectoryV1(skillPath, context.sourceRoots);
  } catch {
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report ${where} skill path ${JSON.stringify(skillPath)} is outside the source root`,
    );
  }
  let bound: string;
  try {
    bound = ciscoSealedPathBinderV1(
      context.expected.map(manifest),
      context.platform,
    )(manifest(skill));
  } catch (error) {
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report ${where} skill path ${JSON.stringify(skillPath)}: ${error instanceof Error ? error.message : "ambiguous"}`,
    );
  }
  return bound === "SKILL.md" ? "" : bound.slice(0, -"/SKILL.md".length);
}

/**
 * U1j (review of U1i, P1): a single-skill report (a source-tree or shard job, or the OCI
 * capture of `/source`) is evidence only for the skill that scan was given. Its `skill_path`
 * must name exactly `skill` ({@link ciscoReportSkillDirectoryV1}); another skill, a parent, a
 * child, the root or a path outside the source root fails at `output`, before the report's
 * `analyzers_failed` is read, so a failure-free report of a sibling can never stand in for
 * the scanned skill's own.
 *
 * U1k (review of U1j, P2): D1 binds only a unique match among `skills`, the run's skill
 * directories (default: this job's own), so on win32 a job whose skill has a case-variant twin
 * in the run fails at `output` whatever the report spells, the job's exact directory included.
 */
export function assertCiscoSingleSkillReportSkillV1(
  report: Record<string, unknown>,
  context: Readonly<{
    label: string;
    sourceRoots: readonly string[];
    skill: string;
    /** The run's source-relative skill directories, D1's candidates; `skill` is always one. */
    skills?: readonly string[];
    platform: NodeJS.Platform;
  }>,
): void {
  const named = ciscoReportSkillDirectoryV1(report.skill_path, `of ${context.label}`, {
    sourceRoots: context.sourceRoots,
    expected: [...new Set([context.skill, ...(context.skills ?? [])])],
    platform: context.platform,
  });
  if (named !== context.skill)
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report of ${context.label} is for skill ${shown(named)}, not ${shown(context.skill)}`,
    );
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * U1j (review of U1i, P1): Cisco `scan-all` reports each skill's `analyzers_failed` under
 * `results[i]`, so D30 inspects only the skills the report lists. The report is complete
 * only when its unique skills ({@link ciscoReportSkillDirectoryV1}) are exactly
 * `context.expected` (one per SKILL.md Scan sealed): every expected skill once, none twice
 * and nothing else, with `summary.total_skills_scanned` equal to that count. A missing,
 * duplicated or extra skill, or a disagreeing count, fails at `coverage` (a partial report
 * whose summary still counts every skill, or a duplicate standing in for a sibling, can no
 * longer hide that sibling's failures); a malformed results list or skill path fails at
 * `output`.
 */
export function assertCiscoScanAllSkillInventoryV1(
  report: Record<string, unknown>,
  context: CiscoReportSkillContextV1,
): void {
  const results = report.results;
  if (!Array.isArray(results))
    throw new CiscoAnalyzerFailureV1("output", "Cisco JSON report holds no results list");
  const listed = results.map((entry: unknown, index) => {
    if (!isRecord(entry))
      throw new CiscoAnalyzerFailureV1(
        "output",
        `Cisco JSON report results[${index}] is malformed`,
      );
    return ciscoReportSkillDirectoryV1(entry.skill_path, `results[${index}]`, context);
  });
  const counts = new Map<string, number>();
  for (const skill of listed) counts.set(skill, (counts.get(skill) ?? 0) + 1);
  const expected = new Set(context.expected);
  const problems: string[] = [];
  const missing = [...expected].filter((skill) => !counts.has(skill));
  if (missing.length > 0) problems.push(`missing ${missing.map(shown).join(", ")}`);
  const twice = [...counts].filter(([, count]) => count > 1).map(([skill]) => shown(skill));
  if (twice.length > 0) problems.push(`listed more than once ${twice.join(", ")}`);
  const extra = [...counts.keys()].filter((skill) => !expected.has(skill));
  if (extra.length > 0) problems.push(`not expected ${extra.map(shown).join(", ")}`);
  const summary = isRecord(report.summary) ? report.summary.total_skills_scanned : undefined;
  if (problems.length === 0 && summary !== expected.size)
    problems.push("the summary count disagrees");
  if (problems.length > 0)
    throw new CiscoAnalyzerFailureV1(
      "coverage",
      `${CISCO_SKILL_COVERAGE_MISMATCH_V1}the JSON report lists ${results.length} result${results.length === 1 ? "" : "s"} for ${expected.size} expected skill${expected.size === 1 ? "" : "s"} (summary ${String(summary)}): ${problems.join("; ")}`,
    );
}

// U1k: the identity pairing moved to `sarif-source-relative-v1`, where `scan-all` uses it too.
export { type CiscoSarifResultIdentityV1, ciscoSarifResultIdentitiesV1 };

/**
 * Coordinator decision D30 for a single-skill report ({@link ciscoSingleSkillReportV1}; a
 * source-tree or shard job, or the OCI capture): its top-level `analyzers_failed` belongs to
 * the one skill it scanned, `skill` (source-relative; bound first by
 * {@link assertCiscoSingleSkillReportSkillV1}).
 *
 * U1j (review of U1i, P2): each JSON SKILL_LOAD_FALLBACK_USED finding counts only with the
 * one SARIF result paired with it by the D28 identity ({@link ciscoFallbackPairingV1}: JSON
 * `(rule_id, id)` = SARIF `(ruleId, fingerprints.primaryLocationLineHash)`, unique among all
 * JSON findings and among all SARIF results, and located in `skill`); a skill_loader failure
 * with any unpaired fallback finding fails at `coverage`. U1k: `scan-all` applies the same
 * pairing to each skill.
 */
export function assertCiscoSingleSkillAnalyzersCompleteV1(
  report: Record<string, unknown>,
  sarifResults: readonly CiscoSarifResultIdentityV1[],
  skill: string,
): void {
  assertCiscoAnalyzersCompleteV1([
    {
      label: `in ${ciscoSkillLabelV1(skill)}`,
      failed: ciscoFailedAnalyzersV1(report.analyzers_failed, "the top level"),
      ...ciscoFallbackPairingV1(
        Array.isArray(report.findings) ? report.findings : [],
        sarifResults,
        skill,
      ),
    },
  ]);
}
