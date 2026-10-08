import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";

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
    SCAN_REPORT_CANDIDATE_ARTIFACT_ID: "456",
    SCAN_REPORT_CANDIDATE_ARTIFACT_DIGEST: "sha256:" + "b".repeat(64),
    SCAN_REPORT_MANIFEST_SHA256: "c".repeat(64),
    SCAN_REPORT_SELECTION_SHA256: "d".repeat(64),
  },
  inputs: {
    candidate_run_id: "123",
    manifest_sha256: "c".repeat(64),
    selection_sha256: "d".repeat(64),
  },
});
// Evaluate the actual admission expression from reviewed configuration. These
// guards use only context-property comparisons and boolean operators.
const admits = (expression: string, value: ReturnType<typeof context>) => {
  expect(expression).toMatch(/^[a-zA-Z0-9_.'@/\- :&|=!()]+$/);
  return Boolean(
    new Function("github", "vars", "inputs", "always", `return (${expression});`)(
      value.github,
      value.vars,
      value.inputs,
      () => true,
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
          manifest_sha256: "0".repeat(64),
          selection_sha256: "0".repeat(64),
        })) {
          const changed = structuredClone(selected);
          changed.inputs[key as keyof typeof changed.inputs] = value;
          expect(admits(job.if, changed)).toBe(false);
        }
        const noUpload = structuredClone(selected);
        noUpload.vars.SCAN_REPORT_CANDIDATE_RUN_ID = "";
        expect(admits(job.if, noUpload)).toBe(false);
        for (const key of [
          "SCAN_REPORT_CANDIDATE_ARTIFACT_ID",
          "SCAN_REPORT_CANDIDATE_ARTIFACT_DIGEST",
          "SCAN_REPORT_MANIFEST_SHA256",
          "SCAN_REPORT_SELECTION_SHA256",
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
  const check = candidateSteps.findIndex((step) => step.run?.includes("check-refresh-run.mjs"));
  const download = candidateSteps.findIndex((step) => step.uses?.includes("download-artifact"));
  expect(check).toBeGreaterThan(-1);
  expect(check).toBeLessThan(download);
  expect(candidateSteps[download]?.with?.["artifact-ids"]).toBe(
    "${{ vars.SCAN_REPORT_CANDIDATE_ARTIFACT_ID }}",
  );
  expect(candidateSteps[download]?.with?.["digest-mismatch"]).toBe("error");
  const promotion = config.jobs["authenticate-before-promotion"].steps;
  expect(
    promotion.find((step: { with?: { "artifact-ids"?: string } }) => step.with?.["artifact-ids"])
      ?.with["artifact-ids"],
  ).toBe("${{ vars.SCAN_REPORT_CANDIDATE_ARTIFACT_ID }}");
  expect(
    promotion.find((step: { with?: { "artifact-ids"?: string } }) => step.with?.["artifact-ids"])
      ?.with["digest-mismatch"],
  ).toBe("error");
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

test("producer freezes reviewed package data separately and runs without signing authority", () => {
  const config = workflow("candidate-upload");
  expect(config.jobs.upload.permissions).toEqual({ contents: "read", actions: "read" });
  expect(config.on.workflow_dispatch.inputs.phase.options).toEqual(["freeze", "run"]);
  const steps = config.jobs.upload.steps as {
    run?: string;
    uses?: string;
    with?: Record<string, string>;
  }[];
  const body = JSON.stringify(steps);
  const execution = steps.find((step) => step.run?.includes("run-workflow.sh"));
  const wrapper = readFileSync("tools/refresh/run-workflow.sh", "utf8");
  expect(body).toContain("refresh.mjs freeze");
  expect(execution?.run).toMatch(/^exec bash tools\/refresh\/run-workflow\.sh /);
  expect(wrapper).toContain("refresh.mjs run");
  expect(body).toContain("install-retained-scanner.mjs");
  expect(body).toContain("retain");
  expect(wrapper).toContain("0|1");
  expect(body).not.toContain("id-token");
  expect(steps.some((step) => step.uses?.includes("actions/attest@"))).toBe(false);
  expect(
    steps
      .filter(
        (step) =>
          step.uses?.includes("upload-artifact@") && !step.with?.name?.includes("NONPUBLISHABLE"),
      )
      .map((step) => step.with?.name),
  ).toEqual(["scan-refresh-frozen", "scan-refresh-candidate"]);
  const custody = steps.findIndex((step) => step.run?.includes("check-refresh-run.mjs"));
  const download = steps.findIndex((step) => step.uses?.includes("download-artifact@"));
  expect(custody).toBeGreaterThan(-1);
  expect(download).toBeGreaterThan(custody);
});

function candidateBoundary() {
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
  const selectors = [
    "123",
    "a".repeat(40),
    "456",
    "sha256:" + "b".repeat(64),
    "457",
    "sha256:" + "c".repeat(64),
  ];
  const invoke = (metadata: unknown = run, uploads: unknown = artifacts, selected = selectors) => {
    const raw = (value: unknown) =>
      typeof value === "string" || Buffer.isBuffer(value) ? value : JSON.stringify(value);
    writeFileSync(join(temporary, "run.json"), raw(metadata));
    writeFileSync(join(temporary, "artifacts.json"), raw(uploads));
    return spawnSync(
      process.execPath,
      [
        join(process.cwd(), "tools/artifact/check-candidate-run.mjs"),
        join(temporary, "run.json"),
        join(temporary, "artifacts.json"),
        ...selected,
      ],
      { encoding: "utf8" },
    );
  };
  return {
    run,
    artifacts,
    selectors,
    invoke,
    dispose: () => rmSync(temporary, { recursive: true, force: true }),
  };
}

const refused = (
  result: ReturnType<ReturnType<typeof candidateBoundary>["invoke"]>,
  reason?: string,
) => {
  expect(result.status).toBe(2);
  expect(result.stdout).toBe("");
  expect(result.stderr).toMatch(
    /^Candidate custody refused: (selector|run-metadata|artifact-metadata|run-custody|actor-custody|artifact-ambiguity|artifact-custody)\.\n$/,
  );
  expect(result.stderr.length).toBeLessThanOrEqual(64);
  if (reason) expect(result.stderr).toBe(`Candidate custody refused: ${reason}.\n`);
};

test("custody refusals identify fixed stages without exposing metadata or dependency errors", () => {
  const fixture = candidateBoundary();
  const selected = [...fixture.selectors];
  selected[0] = "0";
  try {
    refused(fixture.invoke(fixture.run, fixture.artifacts, selected), "selector");
    refused(
      fixture.invoke('{"private":"PRIVATE_SENTINEL_DO_NOT_ECHO"', fixture.artifacts),
      "run-metadata",
    );
    refused(
      fixture.invoke(fixture.run, '{"private":"PRIVATE_SENTINEL_DO_NOT_ECHO"'),
      "artifact-metadata",
    );
    refused(
      fixture.invoke({ ...fixture.run, head_branch: "PRIVATE_SENTINEL_DO_NOT_ECHO" }),
      "run-custody",
    );
    refused(
      fixture.invoke({
        ...fixture.run,
        actor: { ...fixture.run.actor, login: "PRIVATE_SENTINEL_DO_NOT_ECHO" },
      }),
      "actor-custody",
    );
    refused(
      fixture.invoke(fixture.run, { ...fixture.artifacts, total_count: 3 }),
      "artifact-ambiguity",
    );
    const altered = structuredClone(fixture.artifacts);
    altered.artifacts[1]!.name = "PRIVATE_SENTINEL_DO_NOT_ECHO";
    refused(fixture.invoke(fixture.run, altered), "artifact-custody");
  } finally {
    fixture.dispose();
  }
});

test("publisher candidate admission binds successful first upload run, source/actor and both independently selected immutable artifact IDs/digests", () => {
  const { run, artifacts, invoke, dispose } = candidateBoundary();
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
    expect(
      invoke({ ...run, head_repository: { ...run.repository, id: 1 } }, artifacts).status,
    ).toBe(2);
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
    dispose();
  }
});

test.each([
  "run",
  "artifacts",
] as const)("candidate admission refuses malformed or oversized raw %s metadata safely", (field) => {
  const fixture = candidateBoundary();
  const json = JSON.stringify(fixture[field]);
  const key = field === "run" ? "id" : "total_count";
  const duplicate = `{"${key}":${field === "run" ? 123 : 2},${json.slice(1)}`;
  const invoke = (raw: string | Buffer) =>
    field === "run" ? fixture.invoke(raw, fixture.artifacts) : fixture.invoke(fixture.run, raw);
  try {
    expect(invoke(json.padEnd(256 * 1024, " ")).status).toBe(0);
    for (const raw of [
      json.slice(0, -1),
      "null",
      duplicate,
      Buffer.from([0xc3, 0x28]),
      json.padEnd(256 * 1024 + 1, " "),
    ])
      refused(invoke(raw));
  } finally {
    fixture.dispose();
  }
});

test.each([
  0, 2, 4,
])("candidate admission refuses noncanonical or unsafe numeric selector %i", (index) => {
  const fixture = candidateBoundary();
  try {
    for (const invalid of [
      "",
      "0",
      "01",
      "+123",
      "-1",
      "1.5",
      "1e3",
      " 123",
      "9007199254740992",
      "12345678901234567",
    ]) {
      const selected = [...fixture.selectors];
      selected[index] = invalid;
      refused(fixture.invoke(fixture.run, fixture.artifacts, selected));
    }
  } finally {
    fixture.dispose();
  }
});

test("candidate admission refuses duplicate selected IDs and malformed head or service digest selectors", () => {
  const fixture = candidateBoundary();
  try {
    for (const [index, invalid] of [
      [4, "456"],
      [1, "a".repeat(39)],
      [1, "A".repeat(40)],
      [1, "g".repeat(40)],
      [3, "b".repeat(64)],
      [3, "sha256:" + "B".repeat(64)],
      [5, "sha256:" + "c".repeat(63)],
    ] as const) {
      const selected = [...fixture.selectors];
      selected[index] = invalid;
      refused(fixture.invoke(fixture.run, fixture.artifacts, selected));
    }
  } finally {
    fixture.dispose();
  }
});

test.each([
  0, 1,
])("neither selected artifact %i can evade custody, ambiguity or the 128 KiB boundary", (index) => {
  const fixture = candidateBoundary();
  const changed = () => structuredClone(fixture.artifacts);
  try {
    const boundary = changed();
    boundary.artifacts[index]!.size_in_bytes = 128 * 1024;
    expect(fixture.invoke(fixture.run, boundary).status).toBe(0);
    for (const size of [0, -1, 1.5, 128 * 1024 + 1]) {
      const uploads = changed();
      uploads.artifacts[index]!.size_in_bytes = size;
      refused(fixture.invoke(fixture.run, uploads));
    }
    for (const association of [
      { id: 124, head_sha: "a".repeat(40) },
      { id: 123, head_sha: "b".repeat(40) },
    ]) {
      const uploads = changed();
      uploads.artifacts[index]!.workflow_run = association;
      refused(fixture.invoke(fixture.run, uploads));
    }
    const missing = changed();
    missing.artifacts[index]!.id = 999;
    refused(fixture.invoke(fixture.run, missing));
    const duplicate = changed();
    duplicate.artifacts[1 - index] = duplicate.artifacts[index]!;
    refused(fixture.invoke(fixture.run, duplicate));
  } finally {
    fixture.dispose();
  }
});

test("signing alone has token authority and authenticated publication stays behind unsuppressed prerequisite jobs", () => {
  const jobs = workflow("publisher").jobs;
  expect(jobs["bounded-candidate"].permissions).toEqual({ contents: "read", actions: "read" });
  expect(jobs.signer.permissions).toEqual({
    contents: "read",
    "id-token": "write",
    attestations: "write",
  });
  expect(jobs["authenticate-before-promotion"].permissions).toEqual({
    contents: "read",
    actions: "read",
  });
  expect(jobs.signer.needs).toBe("bounded-candidate");
  expect(jobs["authenticate-before-promotion"].needs).toEqual(["bounded-candidate", "signer"]);
  expect(jobs["publish-immutable"]).toBeUndefined();
  expect(Object.keys(jobs)).toHaveLength(3);
  expect(JSON.stringify(jobs)).not.toContain('"contents":"write"');
  expect(JSON.stringify(jobs)).toContain("scan-refresh-final-publication");
  for (const job of Object.values(jobs) as {
    "continue-on-error"?: boolean;
    steps: { "continue-on-error"?: boolean }[];
  }[]) {
    expect(job["continue-on-error"]).not.toBe(true);
    for (const step of job.steps) expect(step["continue-on-error"]).not.toBe(true);
  }
  const steps = jobs["authenticate-before-promotion"].steps as {
    run?: string;
    uses?: string;
    "continue-on-error"?: boolean;
  }[];
  const authentication = steps.findIndex((step) =>
    step.run?.includes("refresh-publication.mjs assemble"),
  );
  const publication = steps.findIndex((step) => step.uses?.startsWith("actions/upload-artifact@"));
  expect(authentication).toBeGreaterThan(-1);
  expect(publication).toBeGreaterThan(authentication);
  expect(steps[authentication]?.["continue-on-error"]).not.toBe(true);
  expect(steps[authentication]?.run).not.toMatch(/\|\|\s*true/);
  expect(steps[authentication]?.run?.trim().split("\n").at(-1)).toContain(
    "refresh-publication.mjs assemble",
  );
});
