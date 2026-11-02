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
  expect(route([{ status: "M", path: "docs/analyzers.md" }])).toMatchObject({
    mode: "docs",
    analyzers: false,
    tests: ["tests/ci"],
  });
});

test("publisher tooling runs its own checks without the analyzer proofs", () => {
  expect(route([{ status: "M", path: "tools/publisher/candidate.mjs" }])).toMatchObject({
    mode: "focused",
    analyzers: false,
    tests: ["tests/ci", "tests/publisher"],
  });
});

test("source in the analyzer adapters' graph and analyzer locks select the real analyzer proofs", () => {
  expect(route([{ status: "M", path: "src/cli/process-runner.ts" }])).toMatchObject({
    mode: "focused",
    coverage: true,
    analyzers: true,
  });
  expect(route([{ status: "M", path: "src/trust-lint/lint.ts" }])).toMatchObject({
    mode: "focused",
    coverage: true,
    analyzers: false,
  });
  expect(route([{ status: "M", path: "tools/analyzers/skillspector/uv.lock" }])).toMatchObject({
    mode: "focused",
    analyzers: true,
    tests: ["tests/ci", "tests/host-v1/analyzer-pins.test.ts"],
  });
});

test.each([
  "package.json",
  "package-lock.json",
  "src/public/contracts.ts",
  "src/host/scan.ts",
  "src/shared/json.ts",
  ".github/workflows/ci.yml",
  "tools/ci-route.mjs",
  "tests/support/portable-realm-v1.mjs",
  "new-unknown.file",
])("shared, dependency, workflow or unknown impact retains all proofs: %s", (path) => {
  expect(route([{ status: "M", path }])).toMatchObject({ coverage: true, analyzers: true });
});

test.each([
  { status: "D", path: "docs/analyzers.md" },
  { status: "R100", path: "README.md", previousPath: "src/host/scan.ts" },
  { status: "A", path: "unmapped.ts" },
  { status: "?", path: "README.md" },
])("deleted, renamed, missing and ambiguous paths fail closed: $status", (change) => {
  expect(route([change])).toMatchObject({ mode: "full", analyzers: true });
});

test("empty change sets and explicit full validation retain coverage and the real proofs", () => {
  expect(route([])).toMatchObject({ mode: "full", coverage: true, analyzers: true });
  expect(route([{ status: "M", path: "README.md" }], true)).toMatchObject({
    mode: "full",
    reason: "explicit-full",
    coverage: true,
    analyzers: true,
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
  const provision = steps.find((step: { name?: string }) =>
    step.name?.includes("Provision the locked SkillSpector and Cisco runtimes"),
  );
  expect(provision.if).toBe("steps.route.outputs.analyzers == 'true'");
  expect(provision.run).toContain("uv sync --project tools/analyzers/skillspector --locked");
  expect(provision.run).toContain("uv sync --project tools/analyzers/cisco-skill-scanner --locked");
  for (const variable of [
    "AIH_SCAN_TEST_SKILLSPECTOR",
    "AIH_SCAN_TEST_SKILL_SCANNER",
    "AIH_SCAN_REQUIRE_REAL_ANALYZERS=1",
  ])
    expect(provision.run).toContain(variable);
  const proof = steps.find((step: { name?: string }) => step.name?.includes("real analyzers"));
  expect(proof.if).toBe("steps.route.outputs.analyzers == 'true'");
  expect(proof.run).toContain("tests/host-v1/real-analyzers.test.ts");
  expect(proof.run).toContain("tests/package-install.test.ts");
  // Retired runtimes: no Semgrep, Bubblewrap or Docker step remains.
  expect(JSON.stringify(workflow)).not.toMatch(/semgrep|bubblewrap|bwrap|docker/i);
});
