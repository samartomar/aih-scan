import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";

test("actual cleanup guards admit cancellation without a preceding failure and never admit a successful candidate upload", () => {
  const workflow = parse(
      readFileSync(".github/workflows/scan-report-candidate-upload.yml", "utf8"),
    ),
    steps = workflow.jobs.upload.steps;
  const eligible = (expression: string, failed: boolean, cancelled: boolean, phase = "run") =>
    new Function(
      "failure",
      "cancelled",
      "success",
      "inputs",
      "steps",
      `return (${expression.replace(/^\$\{\{\s*|\s*\}\}$/g, "").replaceAll("steps.failure-evidence", 'steps["failure-evidence"]')});`,
    )(
      () => failed,
      () => cancelled,
      () => !failed && !cancelled,
      { phase },
      {
        "failure-evidence": {
          outputs: {
            root: "true",
            ...Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`target_${i}`, "true"])),
          },
        },
      },
    );
  for (const step of steps.filter(
    (step: { id?: string; with?: { name?: string } }) =>
      step.id === "failure-evidence" || step.with?.name?.startsWith("scan-refresh-NONPUBLISHABLE-"),
  )) {
    expect(eligible(step.if, false, true)).toBe(true);
    expect(eligible(step.if, true, false)).toBe(true);
    expect(eligible(step.if, false, false)).toBe(false);
    expect(eligible(step.if, false, true, "freeze")).toBe(false);
  }
  const github = {
    event_name: "workflow_dispatch",
    repository: "samartomar/aih-scan",
    repository_id: "1336836161",
    repository_owner_id: "9993940",
    ref: "refs/heads/main",
    workflow_ref:
      "samartomar/aih-scan/.github/workflows/scan-report-candidate-upload.yml@refs/heads/main",
    sha: "a".repeat(40),
    actor: "samartomar",
    actor_id: "9993940",
    triggering_actor: "samartomar",
    run_attempt: "1",
  };
  const job = (always: () => boolean) =>
    new Function("always", "github", "vars", `return (${workflow.jobs.upload.if});`)(
      always,
      github,
      { SCAN_REPORT_REVIEWED_HEAD: github.sha },
    );
  expect(job(() => true)).toBe(true);
  expect(job(() => false)).toBe(false);
  const candidate = steps.find(
    (step: { with?: { name?: string } }) => step.with?.name === "scan-refresh-candidate",
  );
  expect(eligible(candidate.if, false, true)).toBe(false);
  for (const step of steps.filter(
    (step: { id?: string; with?: { name?: string } }) =>
      step.id !== "failure-evidence" &&
      !step.with?.name?.startsWith("scan-refresh-NONPUBLISHABLE-"),
  ))
    expect(eligible(step.if, false, true)).toBe(false);
});

test("failed production workflow retains exact completed sibling bytes through nonpublishable bounded artifacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-failed-evidence-"));
  try {
    const candidate = join(directory, "candidate"),
      frozen = join(directory, "frozen"),
      output = join(directory, "failure-evidence"),
      githubOutput = join(directory, "outputs");
    mkdirSync(join(candidate, "targets", "mattpocock--skills"), { recursive: true });
    mkdirSync(frozen);
    const originals = new Map<string, Buffer>();
    for (const name of ["result.json", "artifact.json", "statement.json", "candidate.json"]) {
      const bytes = Buffer.from(`original ${name} with retained annex bytes\n`);
      originals.set(name, bytes);
      writeFileSync(join(candidate, "targets", "mattpocock--skills", name), bytes);
    }
    writeFileSync(join(candidate, "manifest.json"), "original manifest");
    writeFileSync(join(frozen, "scanner.tgz"), "exact original tarball");
    writeFileSync(join(frozen, "custody.json"), "original custody");
    const workflow = parse(
      readFileSync(".github/workflows/scan-report-candidate-upload.yml", "utf8"),
    );
    const step = workflow.jobs.upload.steps.find(
      (step: { id?: string }) => step.id === "failure-evidence",
    );
    expect(step).toBeDefined();
    expect(step.run.trim()).toBe(
      'node tools/artifact/retain-failure-evidence.mjs "$RUNNER_TEMP/candidate" frozen "$RUNNER_TEMP/failure-evidence"',
    );
    const toolArguments = [candidate, frozen, output];
    // Execute the actual workflow's checked-in helper at its real FS boundary.
    const result = spawnSync(
      process.execPath,
      ["tools/artifact/retain-failure-evidence.mjs", ...toolArguments],
      {
        encoding: "utf8",
        windowsHide: true,
        env: { ...process.env, GITHUB_OUTPUT: githubOutput, GITHUB_RUN_ID: "123" },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    for (const [name, bytes] of originals)
      expect(readFileSync(join(output, "targets", "mattpocock--skills", name))).toEqual(bytes);
    expect(readFileSync(join(output, "root", "scanner.tgz"), "utf8")).toBe(
      "exact original tarball",
    );
    const index = JSON.parse(readFileSync(join(output, "root", "failure.json"), "utf8"));
    expect(index.publishable).toBe(false);
    expect(index.targets).toHaveLength(7);
    expect(
      index.targets[0].files.filter((row: { status: string }) => row.status === "retained"),
    ).toHaveLength(4);
    const uploads = workflow.jobs.upload.steps.filter((step: { with?: { name?: string } }) =>
      step.with?.name?.startsWith("scan-refresh-NONPUBLISHABLE-"),
    );
    expect(uploads).toHaveLength(8);
    for (const upload of uploads) {
      expect(upload.if).toContain("failure()");
      expect(upload.with["if-no-files-found"]).toBe("error");
    }
    expect(readFileSync(githubOutput, "utf8")).toContain("target_0=true");
    expect(readFileSync(githubOutput, "utf8")).toContain("target_1=false");
    // A sparse oversized original refuses explicitly without losing valid siblings.
    truncateSync(
      join(candidate, "targets", "mattpocock--skills", "result.json"),
      128 * 1024 * 1024 + 1,
    );
    const second = join(directory, "bounded-failure");
    const bounded = spawnSync(
      process.execPath,
      ["tools/artifact/retain-failure-evidence.mjs", candidate, frozen, second],
      { encoding: "utf8", windowsHide: true },
    );
    expect(bounded.status, bounded.stderr).toBe(0);
    const boundedIndex = JSON.parse(readFileSync(join(second, "root", "failure.json"), "utf8"));
    expect(boundedIndex.targets[0].files[0].status).toBe("refused");
    expect(readFileSync(join(second, "targets", "mattpocock--skills", "artifact.json"))).toEqual(
      originals.get("artifact.json"),
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
