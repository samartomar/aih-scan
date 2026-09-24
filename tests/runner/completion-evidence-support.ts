import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";

/**
 * An independent oracle for completion evidence v1 (C2a §1.6): it reads the fixture's files
 * from disk, as Core would, instead of reusing Scan's seal or its digest code.
 */

/** Every file under `root` by root-relative POSIX path (links followed, as a snapshot does). */
export function diskFilesV1(root: string, prefix = ""): string[] {
  const files: string[] = [];
  for (const name of readdirSync(join(root, ...prefix.split("/").filter(Boolean)))) {
    const path = prefix === "" ? name : `${prefix}/${name}`;
    const stat = statSync(join(root, ...path.split("/")));
    if (stat.isDirectory()) files.push(...diskFilesV1(root, path));
    else if (stat.isFile()) files.push(path);
  }
  return files;
}

/** subject-files-v1 over files read from disk: `path NUL sha256-hex LF`, code-unit order. */
export function diskSubjectV1(
  root: string,
  paths: readonly string[],
): { subjectTreeSha256: string; analyzedFileCount: number } {
  const ordered = [...new Set(paths)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  const framed = ordered.map((path) => {
    const digest = createHash("sha256")
      .update(readFileSync(join(root, ...path.split("/"))))
      .digest("hex");
    return `${path}\u0000${digest}\n`;
  });
  return {
    subjectTreeSha256: createHash("sha256").update(framed.join(""), "utf8").digest("hex"),
    analyzedFileCount: ordered.length,
  };
}

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * S2h (coordinator decision D16): the fields SARIF 2.1.0 requires of every log Scan returns,
 * checked independently of Scan's code: `version` "2.1.0"; a non-empty `runs` array; on each
 * run `tool.driver.name` (a non-empty string) and a `results` array; on each result a
 * `message` with a `text` or `id` string; on each invocation a boolean `executionSuccessful`.
 * Returns every shortfall; an empty list means the log has them all.
 */
export function sarif210RequiredProblemsV1(log: unknown): string[] {
  const problems: string[] = [];
  if (!record(log)) return ["the log is not an object"];
  if (log.version !== "2.1.0") problems.push("version is not 2.1.0");
  if (!Array.isArray(log.runs) || log.runs.length === 0) return [...problems, "no runs"];
  for (const [index, run] of (log.runs as unknown[]).entries()) {
    const where = `runs[${index}]`;
    if (!record(run)) {
      problems.push(`${where} is not an object`);
      continue;
    }
    const driver = record(run.tool) ? run.tool.driver : undefined;
    if (!record(driver) || typeof driver.name !== "string" || driver.name.length === 0)
      problems.push(`${where}.tool.driver.name is missing`);
    if (!Array.isArray(run.results)) problems.push(`${where}.results is not an array`);
    else
      for (const [resultIndex, result] of (run.results as unknown[]).entries()) {
        const message = record(result) ? result.message : undefined;
        if (
          !record(message) ||
          (typeof message.text !== "string" && typeof message.id !== "string")
        )
          problems.push(`${where}.results[${resultIndex}].message has no text or id`);
      }
    if (run.invocations === undefined) continue;
    if (!Array.isArray(run.invocations)) problems.push(`${where}.invocations is not an array`);
    else
      for (const [invocationIndex, invocation] of (run.invocations as unknown[]).entries())
        if (!record(invocation) || typeof invocation.executionSuccessful !== "boolean")
          problems.push(`${where}.invocations[${invocationIndex}].executionSuccessful is missing`);
  }
  return problems;
}

/** Every run of `log` carries the same, exactly shaped evidence; returns it. */
export function completionOfLogV1(log: unknown): Record<string, unknown> {
  expect(sarif210RequiredProblemsV1(log)).toEqual([]);
  const runs = (log as { runs?: unknown }).runs;
  expect(Array.isArray(runs) && runs.length > 0).toBe(true);
  const found = (runs as Record<string, unknown>[]).map((run) => {
    const first = (run.invocations as Record<string, unknown>[] | undefined)?.[0];
    expect(first?.executionSuccessful).toBe(true);
    return (first?.properties as Record<string, unknown> | undefined)?.aihScanCompletionV1 as
      | Record<string, unknown>
      | undefined;
  });
  const evidence = found[0];
  expect(evidence).toBeDefined();
  for (const other of found) expect(other).toEqual(evidence);
  expect(Object.keys(evidence ?? {}).sort()).toEqual([
    "analyzedFileCount",
    "analyzer",
    "detectorId",
    "subjectTreeSha256",
  ]);
  expect(Object.keys((evidence?.analyzer as object | undefined) ?? {}).sort()).toEqual([
    "lockSha256",
    "version",
  ]);
  return evidence as Record<string, unknown>;
}

/** The evidence a succeeded `runDetectorV1` observation carries in its SARIF bytes. */
export function completionOfObservationV1(outcome: {
  readonly outcome: string;
  readonly evidence?: unknown;
}): Record<string, unknown> {
  expect(outcome.outcome).toBe("succeeded");
  const evidence = outcome.evidence as
    | { kind: string; observation?: { mediaType: string; bytes: Uint8Array } }
    | undefined;
  expect(evidence?.kind).toBe("baseline-analyzer-observation-v1");
  expect(evidence?.observation?.mediaType).toBe("application/sarif+json");
  const text = Buffer.from(evidence?.observation?.bytes ?? new Uint8Array()).toString("utf8");
  return completionOfLogV1(JSON.parse(text));
}
