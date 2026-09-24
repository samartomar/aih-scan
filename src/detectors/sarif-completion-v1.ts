/**
 * The completion evidence an analyzer's own SARIF must carry before Scan reports its results,
 * zero findings included (the owner principle: a clean result only when the analyzer's output
 * proves the subject was analyzed). Every SARIF-emitting analyzer Scan runs reports it:
 * skill-scanner 2.0.14, Semgrep and SkillSpector each write `version` "2.1.0" with runs that
 * name a tool driver, hold a `results` array and report their invocations with
 * `executionSuccessful: true` (warning-level notifications included).
 *
 * - `output`: another version; no runs; a run that is not an object, names no tool driver or
 *   holds no results array; a result that is not an object or whose `locations` is not an
 *   array; a run without invocations; a notification list that is not an array.
 * - `execution` (the analyzer's own failure report): an invocation that is not
 *   `executionSuccessful: true`, or an `error`-level (or malformed) entry in its
 *   `toolExecutionNotifications` or `toolConfigurationNotifications`.
 */

export type SarifCompletionStageV1 = "execution" | "output";

export class SarifCompletionErrorV1 extends TypeError {
  readonly stage: SarifCompletionStageV1;
  constructor(stage: SarifCompletionStageV1, detail: string) {
    super(detail);
    this.name = "SarifCompletionErrorV1";
    this.stage = stage;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function problem(stage: SarifCompletionStageV1, detail: string): never {
  throw new SarifCompletionErrorV1(stage, detail);
}

function hasErrorNotification(value: unknown, where: string): boolean {
  if (value === undefined) return false;
  if (!Array.isArray(value)) problem("output", `${where} notifications are malformed`);
  return value.some((entry) => !isRecord(entry) || entry.level === "error");
}

/**
 * Throws {@link SarifCompletionErrorV1} (message: what fell short, e.g. "holds no runs")
 * unless `document` is a SARIF 2.1.0 log proving a completed analysis.
 */
export function assertSarifCompletedV1(
  document: unknown,
): asserts document is Record<string, unknown> & { runs: Record<string, unknown>[] } {
  if (!isRecord(document)) problem("output", "is not a JSON object");
  if (document.version !== "2.1.0") problem("output", "is not version 2.1.0");
  const runs = document.runs;
  if (!Array.isArray(runs) || runs.length === 0) problem("output", "holds no runs");
  runs.forEach((run: unknown, index) => {
    const where = `run ${index}`;
    if (!isRecord(run)) problem("output", `${where} is malformed`);
    const driver = isRecord(run.tool) ? run.tool.driver : undefined;
    if (!isRecord(driver) || typeof driver.name !== "string" || driver.name.length === 0)
      problem("output", `${where} names no tool driver`);
    const results = run.results;
    if (!Array.isArray(results)) problem("output", `${where} holds no results array`);
    results.forEach((result: unknown, resultIndex) => {
      if (!isRecord(result) || (result.locations !== undefined && !Array.isArray(result.locations)))
        problem("output", `${where} result ${resultIndex} is malformed`);
    });
    const invocations = run.invocations;
    if (!Array.isArray(invocations) || invocations.length === 0)
      problem("output", `${where} reports no invocation`);
    for (const invocation of invocations) {
      if (!isRecord(invocation) || invocation.executionSuccessful !== true)
        problem("execution", `${where} reports an invocation that did not complete successfully`);
      if (
        hasErrorNotification(invocation.toolExecutionNotifications, where) ||
        hasErrorNotification(invocation.toolConfigurationNotifications, where)
      )
        problem("execution", `${where} reports an error notification`);
    }
  });
}
