import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "vitest";

const root = resolve(import.meta.dirname, "../..");
function route(changes: { status: string; path: string; previousPath?: string }[], full = false) {
  const temporary = mkdtempSync(join(tmpdir(), "scan-ci-route-"));
  try {
    const input = join(temporary, "changes.json");
    writeFileSync(input, JSON.stringify(changes));
    const result = spawnSync(
      process.execPath,
      [join(root, "tools/ci-route.mjs"), "--changes", input, ...(full ? ["--full"] : [])],
      { cwd: root, encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    return JSON.parse(result.stdout);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

test("documentation edits report applicable checks without real analyzer proofs", () => {
  expect(route([{ status: "M", path: "docs/DETECTOR-DEFINITIONS.md" }])).toMatchObject({
    mode: "docs",
    python: false,
    refresh: false,
    tests: ["tests/ci"],
  });
});

test("artifact tooling runs its affected checks without Python or refresh proofs", () => {
  expect(route([{ status: "M", path: "tools/artifact/check-statement.mjs" }])).toMatchObject({
    mode: "focused",
    python: false,
    refresh: false,
    tests: ["tests/artifact", "tests/ci"],
  });
});

test("source consumers widen through the installed host graph without unrelated Python work", () => {
  expect(route([{ status: "M", path: "src/material-change/delivery.ts" }])).toMatchObject({
    mode: "focused",
    python: false,
    refresh: true,
  });
  expect(route([{ status: "M", path: "src/baseline/runtime-v1.ts" }])).toMatchObject({
    mode: "focused",
    coverage: true,
    python: true,
    refresh: true,
  });
});

test.each([
  "package.json",
  "package-lock.json",
  "src/public/contracts.ts",
  ".github/workflows/ci.yml",
  "tools/ci-route.mjs",
  "tests/support/packed-assessment-consumer.mjs",
  "new-unknown.file",
])("shared, dependency, workflow or unknown impact retains all proofs: %s", (path) => {
  expect(route([{ status: "M", path }])).toMatchObject({
    coverage: true,
    python: true,
    refresh: true,
  });
});

test.each([
  { status: "D", path: "docs/DETECTOR-DEFINITIONS.md" },
  { status: "R100", path: "README.md", previousPath: "src/baseline/runtime-v1.ts" },
  { status: "A", path: "unmapped.ts" },
  { status: "?", path: "README.md" },
])("deleted, renamed, missing and ambiguous paths fail closed: $status", (change) => {
  expect(route([change])).toMatchObject({ mode: "full", python: true, refresh: true });
});

test("empty change sets and explicit full validation retain coverage and both real proofs", () => {
  expect(route([])).toMatchObject({ mode: "full", coverage: true, python: true, refresh: true });
  expect(route([{ status: "M", path: "README.md" }], true)).toMatchObject({
    mode: "full",
    reason: "explicit-full",
    coverage: true,
    python: true,
    refresh: true,
  });
});

test("a selected failing test propagates a failure to the required verify job", () => {
  const temporary = mkdtempSync(join(tmpdir(), "scan-ci-failure-"));
  try {
    const plan = join(temporary, "plan.json");
    // Use a disposable Vitest root; no repository test is weakened or left failing.
    writeFileSync(
      join(temporary, "vitest.config.mjs"),
      `export default { test: { include: ["tests/**/*.test.ts"] } };`,
    );
    const fixtureRoot = join(temporary, "tests");
    mkdirSync(fixtureRoot);
    writeFileSync(
      join(fixtureRoot, "selected.test.ts"),
      `import { test, expect } from ${JSON.stringify(join(root, "node_modules/vitest/dist/index.js"))}; test("selected failure", () => expect(1).toBe(2));`,
    );
    writeFileSync(plan, JSON.stringify({ coverage: false, tests: ["tests/selected.test.ts"] }));
    // Vitest is located through a symlink to the actual isolated installation.
    symlinkSync(join(root, "node_modules"), join(temporary, "node_modules"), "dir");
    const result = spawnSync(
      process.execPath,
      [join(root, "tools/ci-route.mjs"), "--run-tests", plan],
      {
        cwd: temporary,
        encoding: "utf8",
      },
    );
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain("selected failure");
    expect(result.stdout + result.stderr).toContain("expected 1 to be 2");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("ordinary workflow preserves required verify, full dispatch and failure propagation", async () => {
  const { parse } = await import("yaml");
  const { readFileSync } = await import("node:fs");
  const workflow = parse(readFileSync(join(root, ".github/workflows/ci.yml"), "utf8"));
  expect(workflow.on.push.branches).toEqual(["main"]);
  expect(workflow.on.pull_request).toBeNull();
  expect(workflow.on.workflow_dispatch.inputs.full_validation.default).toBe(true);
  expect(workflow.concurrency["cancel-in-progress"]).toBe(true);
  expect(workflow.jobs.verify.if).toBeUndefined();
  const steps = workflow.jobs.verify.steps;
  const selected = steps.find((step: { name?: string }) =>
    step.name?.includes("Run selected checks"),
  );
  expect(selected.run).toBe("node tools/ci-route.mjs --run-tests ci-plan.json");
  expect(selected["continue-on-error"]).toBeUndefined();
  expect(selected.if).toBeUndefined();
  expect(steps.find((step: { name?: string }) => step.name?.includes("fixed Python")).if).toBe(
    "steps.route.outputs.python == 'true'",
  );
  expect(steps.find((step: { name?: string }) => step.name?.includes("seven-source")).if).toBe(
    "steps.route.outputs.refresh == 'true'",
  );
});
