import { execFileSync } from "node:child_process";
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
  validateProducerContext,
  validateSources,
} from "../../tools/publisher/candidate.mjs";

import { buildProducerContext, checkProducerContext } from "../../tools/publisher/producer.mjs";
import { readPackedPackage } from "../support/npm-pack-output.js";
import { publisherTransport } from "../support/publisher-transport.js";

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
  it("accepts only an explicit immutable public GitHub release asset identity", () => {
    const { url: _url, allowedHosts: _hosts, ...base } = descriptor;
    const release = {
      ...base,
      githubRelease: { repository: "samartomar/aih-scan", assetId: 123, name: "reviewed.tar" },
    };
    expect(accept(release)).toEqual(release);
    for (const githubRelease of [
      { ...release.githubRelease, assetId: "latest" },
      { ...release.githubRelease, repository: "../private" },
      { ...release.githubRelease, name: "../reviewed.tar" },
    ])
      expect(() => accept({ ...base, githubRelease })).toThrow();
  });
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

describe("independently reviewed producer context", () => {
  const context = {
    format: "aih-scan-producer-context/1",
    sourceCommit: "1".repeat(40),
    packageSha256: "2".repeat(64),
    lockSha256: "3".repeat(64),
    archiveSha256: "4".repeat(64),
    manifestSha256: "5".repeat(64),
    receiptSha256: "6".repeat(64),
    selectionSha256: "7".repeat(64),
  };
  it("requires a separately reviewed source, dependency, package and report selection identity", () => {
    const bytes = Buffer.from(JSON.stringify(context));
    expect(validateProducerContext(bytes, sha256(bytes))).toEqual(context);
    expect(() => validateProducerContext(bytes, "0".repeat(64))).toThrow("digest");
    for (const change of [{ sourceCommit: "main" }, { lockSha256: null }, { extra: true }]) {
      const changed = Buffer.from(JSON.stringify({ ...context, ...change }));
      expect(() => validateProducerContext(changed, sha256(changed))).toThrow();
    }
  });
});

describe("public release acquisition through the real CLI transport boundary", () => {
  it("follows only the bounded public release route without credentials or signed-query logs", async () => {
    const bytes = Buffer.from("original immutable archive fixture");
    const fixture = await publisherTransport(bytes);
    const root = temporary();
    const descriptor = {
      format: "aih-scan-prepared-import/1",
      githubRelease: { repository: "samartomar/aih-scan", assetId: 123, name: "reviewed.tar" },
      archiveSha256: sha256(bytes),
      manifestSha256: "b".repeat(64),
      receiptSha256: "c".repeat(64),
    };
    const path = join(root, "import.json");
    writeFileSync(path, JSON.stringify(descriptor));
    const run = (out: string, env = {}) =>
      fixture.run(["prepared-download", path, sha256(readFileSync(path)), join(root, out)], env);
    try {
      expect(
        (
          await run("accepted.tar", {
            GH_TOKEN: "fixture-gh-secret",
            GITHUB_TOKEN: "fixture-token-secret",
            NODE_AUTH_TOKEN: "fixture-npm-secret",
          })
        ).stderr,
      ).toBe("");
      expect(readFileSync(join(root, "accepted.tar"))).toEqual(bytes);
      expect(fixture.state.headers).toHaveLength(3);
      for (const headers of fixture.state.headers) {
        expect(headers.authorization).toBeUndefined();
        expect(headers.cookie).toBeUndefined();
      }
      const refusals = [
        () => {
          fixture.state.redirect =
            "https://evil.example/github-production-release-asset/id/file?signature=fixture-query-secret";
        },
        () => {
          fixture.state.redirect =
            "https://user:secret@release-assets.githubusercontent.com/github-production-release-asset/id/file";
        },
        () => {
          fixture.state.redirect =
            "http://release-assets.githubusercontent.com/github-production-release-asset/id/file";
        },
        () => {
          fixture.state.redirect =
            "https://release-assets.githubusercontent.com:444/github-production-release-asset/id/file";
        },
        () => {
          fixture.state.redirect =
            "https://release-assets.githubusercontent.com/github-production-release-asset/id/file#fragment";
        },
        () => {
          fixture.state.redirect =
            "https://release-assets.githubusercontent.com/elsewhere/file?signature=fixture-query-secret";
        },
      ];
      let index = 0;
      for (const change of refusals) {
        change();
        await expect(run(`refused-${index++}.tar`)).rejects.toThrow();
      }
      fixture.state.redirect =
        "https://release-assets.githubusercontent.com/github-production-release-asset/id/file?signature=fixture-query-secret";
      await expect(
        run("private.tar", {
          AIH_SCAN_TEST_PRIVATE_DNS_HOST: "release-assets.githubusercontent.com",
        }),
      ).rejects.toThrow("Import transport failed");
      fixture.state.terminalStatus = 302;
      await expect(run("loop.tar")).rejects.toThrow("redirects are not followed");
      fixture.state.terminalStatus = 200;
      fixture.state.bytes = Buffer.from("changed immutable archive fixture!");
      await expect(run("tampered.tar")).rejects.toThrow();
      fixture.state.bytes = bytes;
      for (const metadata of [
        { id: 999 },
        { name: "changed.tar" },
        { url: "https://api.github.com/repos/other/repo/releases/assets/123" },
        {
          browser_download_url:
            "https://github.com/other/repo/releases/download/fixture/reviewed.tar",
        },
        { size: 512 * 1024 * 1024 + 1 },
        { state: "new" },
      ]) {
        fixture.state.metadata = metadata;
        await expect(run(`metadata-${index++}.tar`)).rejects.toThrow();
      }
      fixture.state.metadata = {};
      fixture.state.redirect = "https://evil.example/file?signature=fixture-query-secret";
      try {
        await run("secret.tar");
        throw new Error("Expected refusal");
      } catch (error) {
        expect(String(error)).not.toContain("fixture-query-secret");
        expect(String(error)).not.toContain("fixture-gh-secret");
      }
      const legacy = {
        ...descriptor,
        githubRelease: undefined,
        url: "https://artifacts.example.com/archive.tar",
        allowedHosts: ["artifacts.example.com"],
      };
      writeFileSync(path, JSON.stringify(legacy));
      await expect(run("legacy-redirect.tar")).rejects.toThrow("redirects are not followed");
    } finally {
      await fixture.close();
    }
  }, 30000);
});

describe("reviewed source provisioning before candidate intake", () => {
  it("builds the exact package and locked runtime without ambient credentials or lifecycle hooks", () => {
    const root = temporary(),
      source = join(root, "source"),
      consumer = join(root, "consumer"),
      packed = join(root, "packed");
    mkdirSync(join(source, "dist"), { recursive: true });
    mkdirSync(packed);
    const manifest = {
      name: "@aihq/scan",
      version: "0.1.0",
      type: "module",
      files: ["dist"],
      scripts: {
        build: "node build.mjs",
        prebuild: "node -e 'process.exit(9)'",
        postbuild: "node -e 'process.exit(9)'",
        prepack: "node -e 'process.exit(9)'",
        postpack: "node -e 'process.exit(9)'",
      },
    };
    writeFileSync(join(source, "package.json"), JSON.stringify(manifest));
    writeFileSync(
      join(source, "package-lock.json"),
      JSON.stringify({
        name: manifest.name,
        version: manifest.version,
        lockfileVersion: 3,
        requires: true,
        packages: { "": { name: manifest.name, version: manifest.version } },
      }),
    );
    writeFileSync(join(source, ".gitignore"), "dist/\nnode_modules/\n");
    writeFileSync(
      join(source, "build.mjs"),
      `import { mkdirSync, writeFileSync } from "node:fs"; for (const key of Object.keys(process.env)) if (/^(GH_TOKEN|GITHUB_TOKEN|ACTIONS_|DEEPSEEK_|NODE_OPTIONS|NODE_AUTH_TOKEN|SSH_|SKILLSPECTOR_)/.test(key)) throw new Error("ambient credential or loader leaked"); mkdirSync("dist", { recursive: true }); writeFileSync("dist/proof.txt", "reviewed clean producer");`,
    );
    writeFileSync(join(source, "dist/proof.txt"), "reviewed clean producer");
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const pack = readPackedPackage(
      execFileSync(npm, ["pack", "--ignore-scripts", "--json", "--pack-destination", packed], {
        cwd: source,
        encoding: "utf8",
      }),
    );
    const git = (args: string[]) =>
      execFileSync("git", ["-C", source, ...args], { encoding: "utf8" }).trim();
    git(["init", "--quiet"]);
    git(["remote", "add", "origin", "https://github.com/samartomar/aih-scan.git"]);
    git(["add", "."]);
    git([
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "Reviewed source",
    ]);
    const context = {
      format: "aih-scan-producer-context/1",
      sourceCommit: git(["rev-parse", "HEAD"]),
      packageSha256: sha256(readFileSync(join(packed, pack.filename))),
      lockSha256: sha256(readFileSync(join(source, "package-lock.json"))),
      archiveSha256: "a".repeat(64),
      manifestSha256: "b".repeat(64),
      receiptSha256: "c".repeat(64),
      selectionSha256: "d".repeat(64),
    };
    const bytes = Buffer.from(JSON.stringify(context));
    const old = process.env.GH_TOKEN;
    process.env.GH_TOKEN = "fixture-never-inherited";
    try {
      expect(buildProducerContext(bytes, sha256(bytes), source, consumer)).toEqual(context);
    } finally {
      if (old === undefined) delete process.env.GH_TOKEN;
      else process.env.GH_TOKEN = old;
    }
    expect(readFileSync(join(consumer, "node_modules/@aihq/scan/dist/proof.txt"), "utf8")).toBe(
      "reviewed clean producer",
    );
    expect(checkProducerContext(bytes, sha256(bytes), consumer)).toEqual(context);
    writeFileSync(
      join(consumer, "node_modules/.package-lock.json"),
      "changed locked dependency tree",
    );
    expect(() => checkProducerContext(bytes, sha256(bytes), consumer)).toThrow("runtime/context");
    const mismatched = Buffer.from(JSON.stringify({ ...context, sourceCommit: "f".repeat(40) }));
    expect(() =>
      buildProducerContext(mismatched, sha256(mismatched), source, join(root, "never-built")),
    ).toThrow("source commit mismatch");
    expect(existsSync(join(root, "never-built.home"))).toBe(false);
  }, 30000);
});
