import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";

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
