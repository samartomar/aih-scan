import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkCandidateRun,
  selectSummaries,
  validatePreparedImport,
  validateSources,
} from "../../tools/publisher/candidate.mjs";

const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("reviewed local prepared import descriptor", () => {
  const descriptor = {
    format: "aih-scan-prepared-import/1",
    url: "https://artifacts.example.com/reviewed.tar",
    allowedHosts: ["artifacts.example.com"],
    archiveSha256: "a".repeat(64),
    manifestSha256: "b".repeat(64),
    receiptSha256: "c".repeat(64),
  };
  const accept = (value: unknown) => {
    const bytes = Buffer.from(JSON.stringify(value));
    return validatePreparedImport(bytes, sha256(bytes));
  };
  it("binds archive and manifest/receipt digests without changing candidate workflow custody", () => {
    expect(accept(descriptor)).toEqual(descriptor);
  });
  it("refuses another descriptor digest, implicit hosts, credentials, redirects via query and malformed hashes", () => {
    const bytes = Buffer.from(JSON.stringify(descriptor));
    expect(() => validatePreparedImport(bytes, "0".repeat(64))).toThrow("digest");
    for (const changed of [
      { ...descriptor, allowedHosts: [] },
      { ...descriptor, allowedHosts: ["elsewhere.example.com"] },
      { ...descriptor, url: "http://artifacts.example.com/reviewed.tar" },
      { ...descriptor, url: "https://user:secret@artifacts.example.com/reviewed.tar" },
      { ...descriptor, url: "https://artifacts.example.com/reviewed.tar?token=secret" },
      { ...descriptor, receiptSha256: "not-a-digest" },
    ])
      expect(() => accept(changed)).toThrow();
  });
});
const temporary = () => {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-publisher-"));
  roots.push(root);
  return root;
};

describe("reviewed sources", () => {
  const commit = "5bf4e78011075bcfc0dc295f0724994cd123ee71";
  const accept = (value: unknown) => {
    const bytes = Buffer.from(JSON.stringify(value));
    return validateSources(bytes, sha256(bytes));
  };

  it("accept pinned public repositories, items and exact npm versions as CLI targets", () => {
    expect(
      accept([
        { repo: "https://github.com/obra/superpowers", ref: commit },
        { repo: "https://github.com/obra/superpowers", ref: commit, path: "skills/brainstorming" },
        { npm: "@modelcontextprotocol/server-github@2025.4.8" },
      ]),
    ).toEqual([
      { target: "https://github.com/obra/superpowers", ref: commit },
      {
        target: `https://github.com/obra/superpowers/tree/${commit}/skills/brainstorming`,
        ref: commit,
      },
      { target: "npm:@modelcontextprotocol/server-github@2025.4.8" },
    ]);
  });

  it("refuse other digests, unpinned refs, ranges, paths that leave the repository and extra fields", () => {
    const bytes = Buffer.from("[]");
    expect(() => validateSources(bytes, "0".repeat(64))).toThrow("digest mismatch");
    expect(() => validateSources(bytes, "not-a-digest")).toThrow("Invalid reviewed sources");
    expect(() => accept([])).toThrow("non-empty");
    for (const entry of [
      { repo: "https://github.com/obra/superpowers", ref: "main" },
      { repo: "http://github.com/obra/superpowers", ref: commit },
      { repo: "https://example.com/obra/superpowers", ref: commit },
      { repo: "https://github.com/obra/superpowers", ref: commit, path: "../x" },
      { repo: "https://github.com/obra/superpowers", ref: commit, token: "x" },
      { npm: "ws@^8.0.0" },
      { npm: "ws" },
      { folder: "/tmp/x" },
      "obra/superpowers",
    ])
      expect(() => accept([entry]), JSON.stringify(entry)).toThrow();
  });
});

describe("candidate run custody", () => {
  const head = "a".repeat(40);
  const digest = `sha256:${"b".repeat(64)}`;
  const repository = { id: 1336836161, full_name: "samartomar/aih-scan", owner: { id: 9993940 } };
  const owner = { id: 9993940, login: "samartomar" };
  const run = (overrides: Record<string, unknown> = {}) => ({
    id: 42,
    run_attempt: 1,
    event: "workflow_dispatch",
    status: "completed",
    conclusion: "success",
    head_sha: head,
    head_branch: "main",
    path: ".github/workflows/scan-report-candidate-upload.yml",
    repository,
    head_repository: repository,
    actor: owner,
    triggering_actor: owner,
    ...overrides,
  });
  const archive = (overrides: Record<string, unknown> = {}) => ({
    total_count: 1,
    artifacts: [
      {
        id: 7,
        name: "scan-report-candidate",
        digest,
        expired: false,
        size_in_bytes: 1024,
        workflow_run: { id: 42, head_sha: head },
        ...overrides,
      },
    ],
  });

  it("admits only the selected archive of one successful reviewed candidate run", () => {
    expect(checkCandidateRun(run(), archive(), "42", head, "7", digest)).toEqual({
      runId: 42,
      head,
      artifactId: 7,
      artifactDigest: digest,
    });
  });

  it.each([
    ["another attempt", { run_attempt: 2 }],
    ["a failed run", { conclusion: "failure" }],
    ["another head", { head_sha: "c".repeat(40) }],
    ["another workflow", { path: ".github/workflows/ci.yml" }],
    ["another branch", { head_branch: "feature" }],
    ["another actor", { triggering_actor: { id: 1, login: "someone" } }],
    ["a fork", { head_repository: { ...repository, id: 1 } }],
  ])("refuses %s", (_label, overrides) => {
    expect(() => checkCandidateRun(run(overrides), archive(), "42", head, "7", digest)).toThrow(
      "custody refused",
    );
  });

  it.each([
    ["another archive digest", { digest: `sha256:${"c".repeat(64)}` }],
    ["an expired archive", { expired: true }],
    ["another archive name", { name: "other" }],
    ["an archive from another run", { workflow_run: { id: 43, head_sha: head } }],
    ["an oversized archive", { size_in_bytes: 2 ** 40 }],
  ])("refuses %s", (_label, overrides) => {
    expect(() => checkCandidateRun(run(), archive(overrides), "42", head, "7", digest)).toThrow(
      "archive custody refused",
    );
  });

  it("refuses malformed selectors and extra archives", () => {
    expect(() => checkCandidateRun(run(), archive(), "042", head, "7", digest)).toThrow("ID");
    expect(() => checkCandidateRun(run(), archive(), "42", "main", "7", digest)).toThrow(
      "selector",
    );
    const two = archive();
    two.artifacts.push({ ...two.artifacts[0]!, id: 8 });
    two.total_count = 2;
    expect(() => checkCandidateRun(run(), two, "42", head, "7", digest)).toThrow("archive set");
  });
});

describe("summary selection", () => {
  function candidate(): string {
    const root = temporary();
    const write = (path: string, text: string) => {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), text);
    };
    write("targets/0/git-sha1-aa/summary.json", '{"a":1}');
    write("targets/0/git-sha1-aa/sarif/1.sarif", "{}");
    write("targets/1/git-sha1-bb/summary.json", '{"b":1}');
    write("targets/0.result.json", "{}");
    write("sources.json", "[]");
    return root;
  }
  const listing = (root: string) =>
    ["targets/0/git-sha1-aa/summary.json", "targets/1/git-sha1-bb/summary.json"]
      .map((path) => `${sha256(readFileSync(join(root, path)))}  ${path}\n`)
      .join("");

  it("copies exactly the reviewed summaries and their SARIF", () => {
    const root = candidate();
    const out = join(temporary(), "selected");
    const result = selectSummaries(root, sha256(listing(root)), out);
    expect(result.count).toBe(2);
    expect(result.listing).toBe(listing(root));
    expect(existsSync(join(out, "targets/0/git-sha1-aa/sarif/1.sarif"))).toBe(true);
    expect(existsSync(join(out, "targets/0.result.json"))).toBe(false);
    expect(existsSync(join(out, "sources.json"))).toBe(false);
  });

  it("refuses a changed summary, an empty candidate and links", () => {
    const root = candidate();
    const reviewed = sha256(listing(root));
    writeFileSync(join(root, "targets/1/git-sha1-bb/summary.json"), '{"b":2}');
    expect(() => selectSummaries(root, reviewed, join(temporary(), "o"))).toThrow(
      "digest mismatch",
    );
    expect(() => selectSummaries(temporary(), reviewed, join(temporary(), "o"))).toThrow(
      "no summaries",
    );
    symlinkSync("/etc/hostname", join(root, "targets/link"));
    expect(() => selectSummaries(root, reviewed, join(temporary(), "o"))).toThrow("link");
  });
});
