import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";

const statementSha = "15844fd0e376154a85a52fc8eb7a6c1b5b1fe906deb62408c2e222afe4cb5e33";
const scanId = "scan:sha256:fd5e886dc290901110d82ec45e2f444b8fa1b2c05f1bbe7028cbbb4e880bc4dd";
const workflow = (name: string) =>
  parse(readFileSync(`.github/workflows/scan-report-${name}.yml`, "utf8"));
const context = (name: string) => ({
  github: {
    event_name: "workflow_dispatch",
    repository: "samartomar/aih-scan",
    repository_id: "1336836161",
    repository_owner_id: "9993940",
    ref: "refs/heads/main",
    sha: "a".repeat(40),
    actor: "stomar-tech",
    actor_id: "333589491",
    triggering_actor: "stomar-tech",
    run_attempt: "1",
    workflow_ref: `samartomar/aih-scan/.github/workflows/scan-report-${name}.yml@refs/heads/main`,
  },
  vars: {
    SCAN_REPORT_REVIEWED_HEAD: "a".repeat(40),
    SCAN_REPORT_CANDIDATE_RUN_ID: "123",
    SCAN_REPORT_UNSIGNED_ARTIFACT_ID: "456",
    SCAN_REPORT_UNSIGNED_ARTIFACT_DIGEST: "sha256:" + "b".repeat(64),
    SCAN_REPORT_STATEMENT_ARTIFACT_ID: "457",
    SCAN_REPORT_STATEMENT_ARTIFACT_DIGEST: "sha256:" + "c".repeat(64),
  },
  inputs: { candidate_run_id: "123", statement_sha256: statementSha, expected_scan_id: scanId },
});
// Evaluate the actual admission expression from reviewed configuration. These
// guards use only context-property comparisons and boolean operators.
const admits = (expression: string, value: ReturnType<typeof context>) => {
  expect(expression).toMatch(/^[a-zA-Z0-9_.'@/\- :&|=!]+$/);
  return Boolean(
    new Function("github", "vars", "inputs", `return (${expression});`)(
      value.github,
      value.vars,
      value.inputs,
    ),
  );
};

test("only the reviewed independent actor's first manual main run can enter each publisher job", () => {
  for (const name of ["publisher", "candidate-upload"]) {
    const config = workflow(name);
    expect(Object.keys(config.on)).toEqual(["workflow_dispatch"]);
    expect(config.permissions).toEqual({});
    for (const job of Object.values(config.jobs) as { if: string }[]) {
      const selected = context(name);
      expect(admits(job.if, selected)).toBe(true);
      for (const [key, value] of Object.entries({
        event_name: "push",
        repository: "other/aih-scan",
        repository_id: "1",
        repository_owner_id: "1",
        ref: "refs/heads/other",
        sha: "b".repeat(40),
        actor: "samartomar",
        actor_id: "9993940",
        triggering_actor: "samartomar",
        run_attempt: "2",
        workflow_ref: "samartomar/aih-scan/.github/workflows/other.yml@refs/heads/main",
      })) {
        const changed = structuredClone(selected);
        changed.github[key as keyof typeof changed.github] = value;
        expect(admits(job.if, changed), `${name}: refused ${key}`).toBe(false);
      }
      const absent = structuredClone(selected);
      absent.vars.SCAN_REPORT_REVIEWED_HEAD = "";
      expect(admits(job.if, absent)).toBe(false);
      if (name === "publisher") {
        for (const [key, value] of Object.entries({
          candidate_run_id: "124",
          statement_sha256: "0".repeat(64),
          expected_scan_id: "scan:sha256:" + "0".repeat(64),
        })) {
          const changed = structuredClone(selected);
          changed.inputs[key as keyof typeof changed.inputs] = value;
          expect(admits(job.if, changed)).toBe(false);
        }
        const noUpload = structuredClone(selected);
        noUpload.vars.SCAN_REPORT_CANDIDATE_RUN_ID = "";
        expect(admits(job.if, noUpload)).toBe(false);
        for (const key of [
          "SCAN_REPORT_UNSIGNED_ARTIFACT_ID",
          "SCAN_REPORT_UNSIGNED_ARTIFACT_DIGEST",
          "SCAN_REPORT_STATEMENT_ARTIFACT_ID",
          "SCAN_REPORT_STATEMENT_ARTIFACT_DIGEST",
        ] as const) {
          const missing = structuredClone(selected);
          missing.vars[key] = "";
          expect(admits(job.if, missing)).toBe(false);
        }
      }
    }
  }
});

test("publisher checks run custody before the signer, downloads selected immutable IDs and uses independently maintained trust", () => {
  const config = workflow("publisher");
  const candidateSteps = config.jobs["bounded-candidate"].steps as {
    run?: string;
    uses?: string;
    with?: Record<string, string>;
  }[];
  const check = candidateSteps.findIndex((step) => step.run?.includes("check-candidate-run.mjs"));
  const download = candidateSteps.findIndex((step) => step.uses?.includes("download-artifact"));
  expect(check).toBeGreaterThan(-1);
  expect(check).toBeLessThan(download);
  expect(candidateSteps[download]?.with?.["artifact-ids"]).toBe(
    "${{ vars.SCAN_REPORT_STATEMENT_ARTIFACT_ID }}",
  );
  const promotion = config.jobs["authenticate-before-promotion"].steps;
  expect(
    promotion.find((step: { with?: { "artifact-ids"?: string } }) => step.with?.["artifact-ids"])
      ?.with["artifact-ids"],
  ).toBe("${{ vars.SCAN_REPORT_UNSIGNED_ARTIFACT_ID }}");
  expect(JSON.stringify(promotion)).toContain(".github/scan-report-trust.json");
  expect(readFileSync(".github/scan-report-trust.json")).toEqual(
    readFileSync(".github/workflow-templates/scan-report-trust.candidate.json"),
  );
  const ownership = readFileSync(".github/CODEOWNERS", "utf8");
  for (const required of [
    "/.github/CODEOWNERS",
    "/.github/workflows/",
    "/.github/scan-report-trust.json",
    "/package.json",
    "/package-lock.json",
    "/src/",
    "/tools/",
    "/tsconfig*.json",
  ])
    expect(ownership).toContain(`${required} @samartomar`);
});

test("the required automatic CI check has one unique verify display name", () => {
  const names = readdirSync(".github/workflows").flatMap((file) => {
    if (!file.endsWith(".yml")) return [];
    const config = parse(readFileSync(join(".github/workflows", file), "utf8"));
    if (!(config.on?.push || config.on?.pull_request)) return [];
    return Object.entries(config.jobs).map(([id, job]) => ({
      file,
      name: (job as { name?: string }).name ?? id,
    }));
  });
  expect(names.filter(({ name }) => name === "verify")).toEqual([
    { file: "ci.yml", name: "verify" },
  ]);
});

test("unsigned upload materializes only the exact reviewed immutable data without executing Scan", () => {
  const config = workflow("candidate-upload");
  expect(config.jobs.upload.permissions).toEqual({});
  expect(
    config.jobs.upload.steps.some((step: { uses?: string }) => step.uses?.includes("checkout")),
  ).toBe(false);
  const script = config.jobs.upload.steps.find((step: { run?: string }) => step.run)?.run as string;
  const javascript = script.split("<<'NODE'\n")[1]?.split("\nNODE")[0];
  expect(javascript).toBeDefined();
  const temporary = mkdtempSync(join(tmpdir(), "scan-reviewed-upload-"));
  try {
    const result = spawnSync(process.execPath, ["--input-type=module"], {
      input: javascript,
      cwd: temporary,
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    const artifact = readFileSync(join(temporary, "candidate/artifact.json"));
    const statement = readFileSync(join(temporary, "candidate/statement.json"));
    expect(artifact.length).toBe(5585);
    expect(createHash("sha256").update(artifact).digest("hex")).toBe(
      "bac82f592646ca58eaea3eb38c9f48ddd430f4440612ba7ef76a908552d61634",
    );
    expect(statement.length).toBe(483);
    expect(createHash("sha256").update(statement).digest("hex")).toBe(statementSha);
    const report = JSON.parse(artifact.toString());
    expect(report.scanId).toBe(scanId);
    expect(report.annexes[0].byteLength).toBe(246);
    expect(
      createHash("sha256")
        .update(Buffer.from(report.annexes[0].bytesBase64, "base64"))
        .digest("hex"),
    ).toBe("6096cd35014a208ac6d62d5bb5f80efb0d863a02464d38f440cac7412c3b1ff9");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("publisher candidate admission binds successful first upload run, source/actor and both independently selected immutable artifact IDs/digests", () => {
  const temporary = mkdtempSync(join(tmpdir(), "scan-run-admission-"));
  const repository = { id: 1336836161, full_name: "samartomar/aih-scan", owner: { id: 9993940 } };
  const actor = { login: "stomar-tech", id: 333589491 };
  const run = {
    id: 123,
    run_attempt: 1,
    event: "workflow_dispatch",
    status: "completed",
    conclusion: "success",
    head_sha: "a".repeat(40),
    head_branch: "main",
    path: ".github/workflows/scan-report-candidate-upload.yml",
    repository,
    head_repository: repository,
    actor,
    triggering_actor: actor,
  };
  const artifacts = {
    total_count: 2,
    artifacts: [
      {
        id: 456,
        name: "scan-unsigned-artifact",
        digest: "sha256:" + "b".repeat(64),
        expired: false,
        size_in_bytes: 6000,
        workflow_run: { id: 123, head_sha: "a".repeat(40) },
      },
      {
        id: 457,
        name: "scan-detached-statement",
        digest: "sha256:" + "c".repeat(64),
        expired: false,
        size_in_bytes: 1000,
        workflow_run: { id: 123, head_sha: "a".repeat(40) },
      },
    ],
  };
  const invoke = (metadata: typeof run, uploads: typeof artifacts) => {
    writeFileSync(join(temporary, "run.json"), JSON.stringify(metadata));
    writeFileSync(join(temporary, "artifacts.json"), JSON.stringify(uploads));
    return spawnSync(
      process.execPath,
      [
        join(process.cwd(), "tools/artifact/check-candidate-run.mjs"),
        join(temporary, "run.json"),
        join(temporary, "artifacts.json"),
        "123",
        "a".repeat(40),
        "456",
        "sha256:" + "b".repeat(64),
        "457",
        "sha256:" + "c".repeat(64),
      ],
      { encoding: "utf8" },
    );
  };
  try {
    expect(invoke(run, artifacts).status).toBe(0);
    for (const [key, value] of Object.entries({
      id: 124,
      run_attempt: 2,
      event: "push",
      conclusion: "failure",
      status: "in_progress",
      head_sha: "b".repeat(40),
      head_branch: "other",
      path: ".github/workflows/other.yml",
    })) {
      expect(invoke({ ...run, [key]: value }, artifacts).status, key).toBe(2);
    }
    expect(invoke({ ...run, actor: { login: "samartomar", id: 9993940 } }, artifacts).status).toBe(
      2,
    );
    expect(
      invoke({ ...run, triggering_actor: { login: "samartomar", id: 9993940 } }, artifacts).status,
    ).toBe(2);
    expect(invoke({ ...run, head_repository: { ...repository, id: 1 } }, artifacts).status).toBe(2);
    for (const [key, value] of Object.entries({
      id: 999,
      name: "other",
      expired: true,
      digest: "sha256:" + "d".repeat(64),
      size_in_bytes: 96 * 1024 * 1024,
    })) {
      const changed = structuredClone(artifacts);
      Object.assign(changed.artifacts[0]!, { [key]: value });
      expect(invoke(run, changed).status, key).toBe(2);
    }
    const extra = structuredClone(artifacts);
    extra.total_count = 3;
    extra.artifacts.push(extra.artifacts[0]!);
    expect(invoke(run, extra).status).toBe(2);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
