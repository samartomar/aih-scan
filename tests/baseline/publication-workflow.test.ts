import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const workflowPath = resolve(
  import.meta.dirname,
  "..",
  "..",
  ".github",
  "workflows",
  "baseline-publication.yml",
);
const readmePath = resolve(import.meta.dirname, "..", "..", "README.md");

function requestBatchVerifier(workflow: string): string {
  const marker = "Verify each authored request binds to the dispatched source";
  const markerIndex = workflow.indexOf(marker);
  expect(markerIndex).toBeGreaterThanOrEqual(0);
  const delimiterIndex = workflow.indexOf("<<'NODE'\n", markerIndex);
  expect(delimiterIndex).toBeGreaterThanOrEqual(0);
  const bodyStart = delimiterIndex + "<<'NODE'\n".length;
  const bodyEnd = workflow.indexOf("\n          NODE", bodyStart);
  expect(bodyEnd).toBeGreaterThan(bodyStart);
  return workflow.slice(bodyStart, bodyEnd).replace(/^ {10}/gmu, "");
}

function writeRequest(directory: string, batch: number, source: unknown): void {
  writeFileSync(
    join(directory, `batch-${String(batch).padStart(3, "0")}.request.json`),
    JSON.stringify({ source }),
  );
}

describe("immutable baseline publication workflow", () => {
  it("offers data-only request-set input and preserves the legacy catalog dispatch", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    expect(workflow).toContain("request_set_url:");
    expect(workflow).toContain("request_set_sha256:");
    expect(workflow).toContain("catalog:");
    expect(workflow).toContain("if: inputs.request_set_url == ''");
    expect(workflow).toContain("node tools/prepare-publication-request-set.mjs");
    expect(workflow).toContain('if [ -z "$REQUEST_SET_URL" ]; then');
    const steps = workflow.split(/\n {6}- /u);
    const step = (name: string) => {
      const found = steps.find((value) => value.startsWith(`name: ${name}\n`));
      if (found === undefined) throw new Error(`Missing workflow step: ${name}`);
      return found;
    };
    expect(step("Check out exact Core request author")).toMatch(
      /\n {8}if: inputs\.request_set_url == ''\n/u,
    );
    expect(step("Author the canonical request independently")).toMatch(
      /\n {8}if: inputs\.request_set_url == '' && inputs\.catalog == '' && inputs\.candidate != 'aih'\n/u,
    );
    expect(step("Install exact Scanner dependencies and optional Core client")).toContain(
      'if [ -z "$REQUEST_SET_URL" ]; then\n            npm --prefix .core ci --ignore-scripts\n          fi',
    );
    expect(step("Validate immutable inputs before checkout")).toContain(
      'if [ -n "$REQUEST_SET_URL" ]; then\n            test -z "$CORE_REF"\n            test -z "$LEGACY_CATALOG"',
    );
    expect(step("Author legacy active-catalog requests")).toContain("if: inputs.catalog != ''");
    const independent = step("Prepare independently reviewed data-only requests");
    expect(independent).not.toMatch(/\.core|npm|--import/u);
  });
  it("is explicit, exact-input, content-addressed, and split at the privilege boundary", () => {
    const workflow = readFileSync(workflowPath, "utf8");

    expect(workflow).toMatch(/^on:\n {2}workflow_dispatch:/m);
    expect(workflow).not.toMatch(/^ {2}(push|pull_request|schedule):/m);
    expect(workflow).toMatch(/^permissions:\n {2}contents: read\s*$/m);
    expect(workflow).toContain("CORE_REF");
    expect(workflow).toContain("SOURCE_REF");
    expect(workflow).toContain('[[ "$CORE_REF" =~ ^[0-9a-f]{40}$ ]]');
    expect(workflow).toContain('[[ "$SOURCE_REF" =~ ^[0-9a-f]{40}$ ]]');
    expect(workflow).toContain('test "$CORE_REF" = "$(git -C .core rev-parse HEAD)"');
    expect(workflow).toContain('test "$SOURCE_REF" = "$(git -C .source rev-parse HEAD)"');
    expect(workflow).toContain('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]');
    expect(workflow).toContain(".core/tools/prepare-candidate-baseline-requests.mjs");
    expect(workflow).toContain(
      "Author the canonical request independently\n        working-directory: .core",
    );
    expect(workflow).toContain(".core/.github/baseline-candidates/$CANDIDATE.inventory.json");
    expect(workflow).toContain("npm --prefix .core run baseline:request");
    expect(workflow).toContain("aih-core:samartomar/ai-harness");
    expect(workflow).toContain("anthropics-skills:anthropics/skills");
    expect(workflow).toContain("ecc:affaan-m/ECC");
    expect(workflow).toContain("mattpocock-skills:mattpocock/skills");
    expect(workflow).toContain("ponytail:DietrichGebert/ponytail");
    expect(workflow).toContain("superpowers:obra/Superpowers");
    expect(workflow).not.toContain('mkdir -p "$RUNNER_TEMP/baseline/requests"');
    expect(workflow).toContain('mkdir -p "$RUNNER_TEMP/baseline" "$RUNNER_TEMP/baseline/bundles"');
    expect(workflow).toContain("node dist/cli.js baseline-vet");
    expect(workflow).toContain("node dist/cli.js baseline-pack");
    expect(workflow).toContain("node dist/cli.js baseline-inspect");
    expect(workflow).toContain('tag="baseline-v1-$GITHUB_SHA-$request_sha256"');
    expect(workflow).not.toContain('tag="baseline-v1-$request_sha256"');
    expect(workflow).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    expect(workflow).toContain(
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    );
    expect(workflow).toContain(
      "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
    );
    expect(workflow).toMatch(
      /publish:\n[\s\S]*?environment: baseline-evidence-publish\n[\s\S]*?permissions:\n {6}contents: write\n {6}id-token: write\n {6}attestations: write/,
    );
    expect(workflow).toContain('gh release view "$tag"');
    expect(workflow).toContain('gh release create "$tag"');
    expect(workflow).not.toContain("npm publish");
  });

  it("binds every authored request to the dispatched candidate source before analyzers run", () => {
    const workflow = readFileSync(workflowPath, "utf8").replace(/\r\n/gu, "\n");
    const validator = requestBatchVerifier(workflow);
    const root = mkdtempSync(join(tmpdir(), "aih-publication-requests-"));
    const pin = "5caf398a91599029a176ca6d806409b00d1052c4";
    const run = (directory: string, candidate: string, repository: string, commit: string) =>
      spawnSync(
        process.execPath,
        ["--input-type=module", "-", directory, candidate, repository, commit],
        {
          input: validator,
          encoding: "utf8",
        },
      );
    const source = (
      overrides: Partial<{
        id: unknown;
        owner: unknown;
        repository: unknown;
        pinnedCommit: unknown;
      }> = {},
    ) => ({
      id: "ecc",
      owner: "affaan-m",
      repository: "ECC",
      pinnedCommit: pin,
      ...overrides,
    });

    try {
      const candidates = [
        ["aih-core", "samartomar", "ai-harness"],
        ["anthropics-skills", "anthropics", "skills"],
        ["ecc", "affaan-m", "ECC"],
        ["mattpocock-skills", "mattpocock", "skills"],
        ["ponytail", "DietrichGebert", "ponytail"],
        ["superpowers", "obra", "Superpowers"],
      ] as const;
      for (const [candidate, owner, repository] of candidates) {
        const directory = join(root, candidate);
        mkdirSync(directory);
        writeRequest(directory, 1, { id: candidate, owner, repository, pinnedCommit: pin });
        expect(run(directory, candidate, `${owner}/${repository}`, pin).status, candidate).toBe(0);
      }

      for (const [name, overrides] of [
        ["fork-owner", { owner: "samartomar" }],
        ["array-owner", { owner: ["affaan-m"] }],
        ["array-repository", { repository: ["ECC"] }],
        ["repository", { repository: "not-ECC" }],
        ["catalog", { id: "superpowers" }],
        ["commit", { pinnedCommit: "a".repeat(40) }],
      ] as const) {
        const directory = join(root, name);
        mkdirSync(directory);
        writeRequest(directory, 1, source());
        writeRequest(directory, 2, source(overrides));
        expect(run(directory, "ecc", "affaan-m/ECC", pin).status, name).not.toBe(0);
      }

      const nullSource = join(root, "null-source");
      mkdirSync(nullSource);
      writeRequest(nullSource, 1, source());
      writeRequest(nullSource, 2, null);
      expect(run(nullSource, "ecc", "affaan-m/ECC", pin).status, "null-source").not.toBe(0);
      for (const name of ["empty", "unexpected-file", "unexpected-directory"]) {
        const directory = join(root, name);
        mkdirSync(directory);
        if (name === "unexpected-file") writeFileSync(join(directory, "notes.txt"), "unexpected");
        if (name === "unexpected-directory") mkdirSync(join(directory, "batch-001.request.json"));
        expect(run(directory, "ecc", "affaan-m/ECC", pin).status, name).not.toBe(0);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("documents publisher-and-request-addressed immutable releases", () => {
    const readme = readFileSync(readmePath, "utf8");

    expect(readme).toContain("publisher-and-request-addressed GitHub Releases");
    expect(readme).toContain("baseline-v1-PUBLISHER_COMMIT-REQUEST_SHA");
    expect(readme).toContain("affaan-m/ECC");
    expect(readme).toContain("anthropics/skills");
    expect(readme).toContain("mattpocock/skills");
    expect(readme).toContain("DietrichGebert/ponytail");
    expect(readme).toContain("samartomar/ai-harness");
    expect(readme).toContain("same commit");
    expect(readme).not.toContain("creates request-addressed GitHub Releases");
  });
});
