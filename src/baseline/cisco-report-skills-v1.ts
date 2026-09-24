import { CiscoAnalyzerFailureV1 } from "./cisco-analyzer-failures-v1.js";
import { ciscoSealedPathBinderV1 } from "./cisco-sealed-case-binding-v1.js";
import { sourceRelativeSkillDirectoryV1 } from "./sarif-source-relative-v1.js";

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
 */
export function assertCiscoSingleSkillReportSkillV1(
  report: Record<string, unknown>,
  context: Readonly<{
    label: string;
    sourceRoots: readonly string[];
    skill: string;
    platform: NodeJS.Platform;
  }>,
): void {
  const named = ciscoReportSkillDirectoryV1(report.skill_path, `of ${context.label}`, {
    sourceRoots: context.sourceRoots,
    expected: [context.skill],
    platform: context.platform,
  });
  if (named !== context.skill)
    throw new CiscoAnalyzerFailureV1(
      "output",
      `Cisco JSON report of ${context.label} is for skill ${shown(named)}, not ${shown(context.skill)}`,
    );
}
