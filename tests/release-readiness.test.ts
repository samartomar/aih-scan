import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8").replace(/\r\n/gu, "\n");

function inlineModuleFollowing(workflow: string, marker: string): string {
  const markerIndex = workflow.indexOf(marker);
  expect(markerIndex).toBeGreaterThanOrEqual(0);
  const delimiterIndex = workflow.indexOf("<<'NODE'\n", markerIndex);
  expect(delimiterIndex).toBeGreaterThanOrEqual(0);
  const bodyStart = delimiterIndex + "<<'NODE'\n".length;
  const bodyEnd = workflow.indexOf("\n          NODE", bodyStart);
  expect(bodyEnd).toBeGreaterThan(bodyStart);
  return workflow.slice(bodyStart, bodyEnd).replace(/^ {10}/gmu, "");
}

describe("@aihq/scan release boundary (#12)", () => {
  it("uses the same Apache-2.0 public-package boundary as Core", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.license).toBe("Apache-2.0");
    expect(manifest.publishConfig).toEqual({ access: "public" });
    expect(read("LICENSE")).toContain("Apache License\n                           Version 2.0");
    expect(read("README.md")).toContain("[Apache-2.0](LICENSE)");
  });

  it("pins a tag-only, main-bound workflow that separates candidate code from publication authority", () => {
    const workflow = read(".github/workflows/release.yml");
    expect(workflow).toContain('- "v-scan-*"');
    expect(workflow).not.toMatch(/workflow_dispatch|workflow_call|pull_request_target/);
    expect(workflow).toContain(
      "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
    );
    expect(workflow).toContain('if [ "$GITHUB_SHA" != "$main_sha" ]; then');
    expect(workflow).toContain(['tag="$', '{GITHUB_REF_NAME#v-scan-}"'].join(""));
    expect(workflow).toContain('if [ "$ver" != "$tag" ]; then');
    expect(workflow).toContain("name: npm-publish");
    expect(workflow).toContain("https://www.npmjs.com/package/@aihq/scan");
    expect(workflow).toContain("verify-and-pack:");
    expect(workflow).toContain("npm-publish:");
    expect(workflow).toContain("needs: verify-and-pack");
    expect(workflow).toContain("if: github.ref == 'refs/tags/v-scan-0.1.1'");
    expect(workflow).toContain('test "$GITHUB_REF_NAME" = "v-scan-0.1.1"');
    expect(workflow).toContain("actions: read");
    expect(workflow).toMatch(/id-token:\s*write/);
    expect(workflow).toMatch(/attestations:\s*write/);
    expect(workflow).toMatch(/contents:\s*write/);
    expect(workflow).not.toContain("packages: write");
    expect(workflow).not.toContain("NPM_TOKEN");
    expect(workflow.match(/secrets\.NPM_BOOTSTRAP_TOKEN/gu)).toHaveLength(1);
    expect(workflow.match(/npm view "@aihq\/scan" name --json/gu)).toHaveLength(2);
    expect(workflow.match(/--loglevel silent/gu)).toHaveLength(2);
    expect(workflow.match(/REGISTRY_OBSERVATION=/gu)).toHaveLength(2);
    expect(workflow).not.toContain("grep -Eq 'E404'");
    expect(workflow).toContain('npm whoami --registry "https://registry.npmjs.org/" >/dev/null');

    const candidateJob = workflow.slice(
      workflow.indexOf("  verify-and-pack:\n"),
      workflow.indexOf("  npm-publish:\n"),
    );
    expect(candidateJob).not.toContain("NODE_AUTH_TOKEN");
    expect(candidateJob).not.toContain("NPM_BOOTSTRAP_TOKEN");

    const actions = [...workflow.matchAll(/^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+).*$/gmu)];
    expect(actions.length).toBeGreaterThanOrEqual(5);
    for (const [, action, revision] of actions) {
      expect(action).toMatch(/^[\w.-]+\/[\w.-]+$/u);
      expect(revision).toMatch(/^[0-9a-f]{40}$/u);
    }
  });

  it("verifies, packs once, and keeps one exact tarball through evidence and publication", () => {
    const manifest = JSON.parse(read("package.json")) as {
      scripts: Record<string, string>;
    };
    const verifyScript = manifest.scripts.verify ?? "";
    expect(verifyScript.indexOf("npm run build")).toBeGreaterThanOrEqual(0);
    expect(verifyScript.indexOf("npm run build")).toBeLessThan(verifyScript.indexOf("npm test"));

    const workflow = read(".github/workflows/release.yml");
    expect(workflow).toContain('node-version: "24"');
    expect(workflow).toContain("package-manager-cache: false");
    expect(workflow).toContain("npm ci --ignore-scripts");
    expect(workflow).toContain("npm run verify");
    expect(workflow.match(/npm pack --ignore-scripts/gmu)).toHaveLength(1);
    expect(workflow).toContain('tarball_sha256="$(sha256sum "$tarball" | awk \'{print $1}\')"');
    expect(workflow).toContain(
      ["artifact_id: $", "{{ steps.upload.outputs.artifact-id }}"].join(""),
    );
    expect(workflow).toContain(
      ["artifact_sha256: $", "{{ steps.upload.outputs.artifact-digest }}"].join(""),
    );
    expect(workflow).toContain("actions/upload-artifact@");
    expect(workflow).toContain("actions/download-artifact@");
    expect(workflow).toContain(
      ["artifact-ids: $", "{{ needs.verify-and-pack.outputs.artifact_id }}"].join(""),
    );
    expect(workflow).toContain(
      'api_digest="$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$EXPECTED_ARTIFACT_ID" --jq .digest)"',
    );
    expect(workflow).toContain(
      ['test "$api_digest" = "sha256:$', "{EXPECTED_ARTIFACT_SHA256}"].join(""),
    );
    expect(workflow).toContain('test "$actual_sha256" = "$EXPECTED_TARBALL_SHA256"');
    expect(workflow).toContain('if [ "$TARBALL" != "aihq-scan-$tag.tgz" ]; then');
    expect(workflow).toContain('manifest.name !== "@aihq/scan" || manifest.version !== tag');
    expect(workflow).toContain(['file: "$', '{{ env.TARBALL }}"'].join(""));
    expect(workflow).toContain(['subject-path: "$', '{{ env.TARBALL }}"'].join(""));
    expect(workflow).toContain("upload-artifact: false");
    expect(workflow).toContain("upload-release-assets: false");
    expect(workflow).toContain(
      'npm install --prefix "$consumer" --ignore-scripts --no-audit --no-fund "$tarball"',
    );
    expect(workflow).toContain('"$consumer/node_modules/.bin/aih-scan" --help');
    expect(workflow).toContain(
      'npm publish "$tarball" --ignore-scripts --provenance --access public --registry "https://registry.npmjs.org/" --tag "$dist_tag"',
    );
    expect(workflow).toContain("Revalidate current main and tag before publication");
    expect(workflow).toContain('"+refs/tags/$GITHUB_REF_NAME:refs/tags/$GITHUB_REF_NAME"');
    expect(workflow.match(/Verify exact tarball before /gmu)).toHaveLength(5);
    expect(workflow).toContain("format: spdx-json");
    expect(workflow).toContain("cosign sign-blob --yes");
    expect(workflow).toContain("gh release create");

    const candidateJob = workflow.slice(
      workflow.indexOf("  verify-and-pack:\n"),
      workflow.indexOf("  npm-publish:\n"),
    );
    expect(candidateJob).not.toMatch(/environment:|id-token:\s*write|attestations:\s*write/);
    expect(candidateJob).not.toMatch(/contents:\s*write|GH_TOKEN/);

    const publicationJob = workflow.slice(workflow.indexOf("  npm-publish:\n"));
    expect(publicationJob).not.toMatch(/actions\/checkout|npm ci|npm run |npm pack|--help/);
    expect(publicationJob).not.toContain("require('./package.json')");

    const bootstrapStep = publicationJob.slice(
      publicationJob.indexOf("Publish exact first tarball through the one-use npm bootstrap"),
      publicationJob.indexOf("Verify exact tarball before GitHub release"),
    );
    const authenticatedAbsenceIndex = bootstrapStep.indexOf('npm view "@aihq/scan" name --json');
    const liveRefIndex = bootstrapStep.indexOf(
      "Revalidate live main and tag after authenticated registry observation",
    );
    const finalHashIndex = bootstrapStep.indexOf('actual_sha256="$(sha256sum "$TARBALL"');
    const effectIndex = bootstrapStep.indexOf('npm publish "$tarball"');
    expect(authenticatedAbsenceIndex).toBeGreaterThanOrEqual(0);
    expect(liveRefIndex).toBeGreaterThan(authenticatedAbsenceIndex);
    expect(finalHashIndex).toBeGreaterThan(liveRefIndex);
    expect(effectIndex).toBeGreaterThan(finalHashIndex);
    expect(bootstrapStep).toContain("env -u NODE_AUTH_TOKEN git");
  });

  it("parses npm package-absence evidence as one exact JSON E404 error", () => {
    const workflow = read(".github/workflows/release.yml");
    const validator = inlineModuleFollowing(workflow, "REGISTRY_OBSERVATION=");
    const validate = (observation: string) =>
      spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
        env: { ...process.env, REGISTRY_OBSERVATION: observation },
        encoding: "utf8",
      });

    expect(validate(JSON.stringify({ error: { code: "E404", summary: "missing" } })).status).toBe(
      0,
    );
    expect(
      validate(
        JSON.stringify({
          error: { code: "E500", summary: "upstream mentioned E404" },
        }),
      ).status,
    ).not.toBe(0);
    expect(validate('npm ERR! code E500\n{"error":{"code":"E404"}}').status).not.toBe(0);
  });

  it("rejects a packed manifest that tries to redirect npm publication", () => {
    const workflow = read(".github/workflows/release.yml");
    const validator = inlineModuleFollowing(workflow, "Validate packed manifest identity");
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-release-manifest-"));
    try {
      const packageRoot = join(fixtureRoot, "package");
      mkdirSync(packageRoot);
      const validate = (publishConfig: Record<string, unknown>) => {
        writeFileSync(
          join(packageRoot, "package.json"),
          JSON.stringify({
            name: "@aihq/scan",
            version: "0.1.1",
            publishConfig,
          }),
        );
        execFileSync("tar", ["-czf", "candidate.tgz", "package"], {
          cwd: fixtureRoot,
        });
        return spawnSync(process.execPath, ["--input-type=module", "-", "candidate.tgz", "0.1.1"], {
          cwd: fixtureRoot,
          input: validator,
          encoding: "utf8",
        });
      };

      expect(validate({ access: "public" }).status).toBe(0);
      expect(validate({ access: "public", registry: "https://attacker.invalid/" }).status).not.toBe(
        0,
      );
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("documents bootstrap, authority, verification, and immutable failure behavior", () => {
    const releasing = read("RELEASING.md");
    expect(releasing).toContain("package must already exist");
    expect(releasing).toMatch(
      /samartomar\/aih-scan, workflow `release\.yml`,\s+environment `npm-publish`/u,
    );
    expect(releasing).toContain("full-SHA publication authorization");
    expect(releasing).toContain("**Bypass 2FA** enabled");
    expect(releasing).toMatch(/delete the GitHub\s+`NPM_BOOTSTRAP_TOKEN` secret/u);
    expect(releasing).toContain("revoke the npm token");
    expect(releasing).toMatch(/restores trusted-publisher-only\s+publication/u);
    expect(releasing).toMatch(
      /as soon as npm confirms package existence, regardless of whether\s+the later GitHub Release succeeds/u,
    );
    expect(releasing).toContain("never delete, move, or reuse the tag");
    expect(releasing).toContain("npm refused the protected publish with `EOTP`");
    expect(releasing).toContain("read-only `verify-and-pack` job");
    expect(releasing).toContain("runs no Scanner package code");
    expect(releasing).toContain("npm view @aihq/scan@0.1.1");
    expect(releasing).toContain("gh attestation verify ./aihq-scan-0.1.1.tgz");
    expect(releasing).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(releasing).toContain("Scanner evidence is not organization authority");

    const readme = read("README.md");
    expect(readme).toContain("npm install --save-exact @aihq/scan@0.1.1");
    expect(readme).toContain("gh attestation verify ./aihq-scan-0.1.1.tgz");
    expect(readme).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(readme).toContain("npm provenance");
    expect(readme).toContain("GitHub build attestation");
    expect(readme).toContain("without executing Scanner package code");
    expect(readme).toContain("has not been published");
  });

  it("packs the license, README, command, and library under the exact identity", () => {
    const raw = execFileSync(
      process.execPath,
      [process.env.npm_execpath ?? "", "pack", "--ignore-scripts", "--dry-run", "--json"],
      { cwd: root, encoding: "utf8" },
    );
    const packedManifests = JSON.parse(raw) as Array<{
      name: string;
      version: string;
      filename: string;
      files: Array<{ path: string }>;
    }>;
    expect(packedManifests).toHaveLength(1);
    const packed = packedManifests[0];
    if (packed === undefined) throw new Error("npm pack produced no manifest");
    expect(packed).toMatchObject({
      name: "@aihq/scan",
      version: "0.1.1",
      filename: "aihq-scan-0.1.1.tgz",
    });
    const paths = packed.files.map(({ path }) => path);
    expect(paths).toContain("LICENSE");
    expect(paths).toContain("README.md");
    expect(paths).toContain("dist/cli.js");
    expect(paths).toContain("dist/index.js");
  });
});
