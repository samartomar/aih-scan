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
 *   array of location objects (S2f: a `physicalLocation` and its `artifactLocation`, when
 *   present, are objects, and the artifact `uri`, when present, a string); a run without
 *   invocations; a notification list that is not an array; a malformed
 *   notification (S2f): not an object, a `level` that is not one of SARIF 2.1.0's
 *   none/note/warning/error, or a `message` that is not a message object (`text` or `id`,
 *   each a string, optional string `markdown`, optional string-array `arguments`).
 * - `execution` (the analyzer's own failure report): an invocation that is not
 *   `executionSuccessful: true`, or an `error`-level entry in its
 *   `toolExecutionNotifications` or `toolConfigurationNotifications` whose lists are
 *   otherwise well formed.
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

/** A SARIF 2.1.0 location object, as far as Scan reads one: physical location and URI. */
function isLocation(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const physical = value.physicalLocation;
  if (physical === undefined) return true;
  if (!isRecord(physical)) return false;
  const artifact = physical.artifactLocation;
  if (artifact === undefined) return true;
  return isRecord(artifact) && (artifact.uri === undefined || typeof artifact.uri === "string");
}

function problem(stage: SarifCompletionStageV1, detail: string): never {
  throw new SarifCompletionErrorV1(stage, detail);
}

const NOTIFICATION_LEVELS: ReadonlySet<unknown> = new Set(["none", "note", "warning", "error"]);

const isOptionalString = (value: unknown): boolean =>
  value === undefined || typeof value === "string";

/** A SARIF 2.1.0 message object: `text` or `id`, every present property well typed. */
function isMessage(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value.text === undefined && value.id === undefined) return false;
  if (!isOptionalString(value.text) || !isOptionalString(value.id)) return false;
  if (!isOptionalString(value.markdown)) return false;
  const args = value.arguments;
  return (
    args === undefined || (Array.isArray(args) && args.every((arg) => typeof arg === "string"))
  );
}

/** A SARIF 2.1.0 notification object: `level` and `message` well formed when present. */
function isNotification(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  if (value.level !== undefined && !NOTIFICATION_LEVELS.has(value.level)) return false;
  return value.message === undefined || isMessage(value.message);
}

/** The notifications of one list, validated whole; none when the list is absent. */
function notifications(value: unknown, where: string): Record<string, unknown>[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) problem("output", `${where} notifications are malformed`);
  if (!value.every(isNotification)) problem("output", `${where} reports a malformed notification`);
  return value;
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
      const locations = isRecord(result) ? result.locations : undefined;
      if (
        !isRecord(result) ||
        (locations !== undefined && (!Array.isArray(locations) || !locations.every(isLocation)))
      )
        problem("output", `${where} result ${resultIndex} is malformed`);
    });
    const invocations = run.invocations;
    if (!Array.isArray(invocations) || invocations.length === 0)
      problem("output", `${where} reports no invocation`);
    for (const invocation of invocations) {
      if (!isRecord(invocation) || invocation.executionSuccessful !== true)
        problem("execution", `${where} reports an invocation that did not complete successfully`);
      const reported = [
        ...notifications(invocation.toolExecutionNotifications, where),
        ...notifications(invocation.toolConfigurationNotifications, where),
      ];
      if (reported.some((entry) => entry.level === "error"))
        problem("execution", `${where} reports an error notification`);
    }
  });
}
