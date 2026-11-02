import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
    expect(workflow).toContain("actions: read");
    expect(workflow).toMatch(/id-token:\s*write/);
    expect(workflow).toMatch(/attestations:\s*write/);
    expect(workflow).toMatch(/contents:\s*write/);
    expect(workflow).not.toContain("packages: write");
    expect(workflow).not.toContain("v-scan-0.1.1");
    expect(workflow).not.toContain("NPM_BOOTSTRAP_TOKEN");
    expect(workflow).not.toContain("REGISTRY_OBSERVATION");
    expect(workflow).not.toContain('npm view "@aihq/scan"');
    expect(workflow).not.toContain("npm whoami");
    expect(workflow).toContain("Publish exact tarball through npm Trusted Publishing");
    expect(workflow).toContain("dist_tag=next");
    expect(workflow).not.toContain("dist_tag=latest");
    expect(workflow).toContain("--prerelease");
    expect(workflow).toContain(
      ['if [ -n "$', '{NODE_AUTH_TOKEN:-}" ] || [ -n "$', '{NPM_TOKEN:-}" ]; then'].join(""),
    );

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
      "anchore/sbom-action@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2",
    );
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

    const trustedPublishStep = publicationJob.slice(
      publicationJob.indexOf("Publish exact tarball through npm Trusted Publishing"),
      publicationJob.indexOf("Verify exact tarball before GitHub release"),
    );
    const liveRefIndex = trustedPublishStep.indexOf(
      "Revalidate live main and tag immediately before the effect",
    );
    const finalHashIndex = trustedPublishStep.indexOf('actual_sha256="$(sha256sum "$TARBALL"');
    const effectIndex = trustedPublishStep.indexOf('npm publish "$tarball"');
    expect(liveRefIndex).toBeGreaterThanOrEqual(0);
    expect(finalHashIndex).toBeGreaterThan(liveRefIndex);
    expect(effectIndex).toBeGreaterThan(finalHashIndex);
    expect(trustedPublishStep).not.toContain("NPM_BOOTSTRAP_TOKEN");
    expect(trustedPublishStep).not.toContain("secrets.");
    expect(trustedPublishStep).not.toContain('npm view "@aihq/scan"');
  });

  it("accepts only a stable unambiguous npm CLI version at the Trusted Publishing boundary", () => {
    const workflow = read(".github/workflows/release.yml");
    const validator = inlineModuleFollowing(workflow, 'npm_version="$(npm --version)"');
    const validate = (version: string) =>
      spawnSync(process.execPath, ["--input-type=module", "-", version], {
        input: validator,
        encoding: "utf8",
      });

    for (const accepted of ["11.5.1", "11.5.2", "11.6.0", "12.0.0"]) {
      expect(validate(accepted).status, accepted).toBe(0);
    }
    for (const rejected of [
      "11.5.0",
      "10.99.99",
      "11.5.1-beta.0",
      "11.5.1+build.1",
      "v11.5.1",
      "11.5",
      "011.5.1",
      "999999999999999999999999.5.1",
      "",
    ]) {
      expect(validate(rejected).status, rejected).not.toBe(0);
    }
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
            version: "0.1.2",
            publishConfig,
          }),
        );
        execFileSync("tar", ["-czf", "candidate.tgz", "package"], {
          cwd: fixtureRoot,
        });
        return spawnSync(process.execPath, ["--input-type=module", "-", "candidate.tgz", "0.1.2"], {
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

  it("documents tokenless publication, authority, verification, and immutable failure behavior", () => {
    const releasing = read("RELEASING.md");
    expect(releasing).toContain(
      "npm trust github @aihq/scan --file release.yml --repo samartomar/aih-scan --env npm-publish --allow-publish",
    );
    expect(releasing).toContain("npm trust list @aihq/scan");
    expect(releasing).toContain("full-SHA publication authorization");
    expect(releasing).toContain("GitHub bootstrap secret is absent");
    expect(releasing).toContain("Historical release custody");
    expect(releasing).toContain("semver:none|patch|minor|major");
    expect(releasing).toContain("publishing under npm `next`");
    expect(releasing).toContain("separate promotion authorization");
    expect(releasing).toContain("old bootstrap token is revoked");
    expect(releasing).toContain("allows only `npm publish`");
    expect(releasing).toContain("never delete, move, or reuse the tag");
    expect(releasing).toContain("npm refused the protected publish with `EOTP`");
    expect(releasing).toContain("read-only `verify-and-pack` job");
    expect(releasing).toContain("runs no Scanner package code");
    expect(releasing).toContain('npm view "@aihq/scan@$version"');
    expect(releasing).toContain('gh attestation verify "./aihq-scan-$version.tgz"');
    expect(releasing).toContain("Recovery run `32903155702`");
    expect(releasing).toContain("is no longer present on `main`");
    expect(releasing).not.toContain("NPM_BOOTSTRAP_TOKEN");
    // The replacement package and its owner-controlled first cut.
    expect(releasing).toContain("`0.1.0` is the replacement content-assessment package");
    expect(releasing).toContain("`v-scan-0.1.0` already exists");
    expect(releasing).toContain("tests/package-install.test.ts");
    expect(releasing).not.toContain("promotion-readiness");
    expect(releasing).not.toContain("Core/\nCatalog acceptance");
    expect(read("VERSIONING.md")).toContain(
      "`0.1.0` is the replacement package and the sole unreleased target",
    );
    expect(read("CHANGELOG.md")).toContain("## 0.1.0 (unreleased)");
  });

  it("enforces package-bearing and repository-only release classes in CI", () => {
    const semver = read(".github/workflows/semver-label.yml");
    expect(semver).toContain("semver:none|semver:patch|semver:minor|semver:major");
    expect(semver).toContain("Exactly one semver:* label is required");
    expect(read("VERSIONING.md")).toContain("cannot start or bump a package cut");
  });

  it("declares the exact package identity, entry points and public file roots", () => {
    // tests/package-install.test.ts owns the real npm pack/install boundary.
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest).toMatchObject({
      name: "@aihq/scan",
      version: "0.1.0",
      files: [
        "dist",
        "schemas",
        "trust",
        "docs/scan-sources.md",
        "docs/analyzers.md",
        "docs/verification.md",
        "docs/advisories.md",
        "CONTRACTS.md",
        "CHANGELOG.md",
      ],
    });
    expect(Object.keys(manifest.exports as object)).not.toContain(".");
    expect(Object.keys(manifest.scripts as object).sort()).toEqual([
      "build",
      "generate:identity",
      "lint",
      "prepack",
      "repo:doctor",
      "repo:init",
      "test",
      "test:cov",
      "typecheck",
      "verify",
      "verify:workflow-action-pins",
    ]);
    expect(Object.keys(manifest.dependencies as object).sort()).toEqual([
      "smol-toml",
      "yaml",
    ]);
    // Runtime dependencies are pinned exactly.
    for (const version of Object.values(manifest.dependencies as Record<string, string>))
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    const lock = JSON.parse(read("package-lock.json")) as {
      version: string;
      packages: Record<string, { version?: string }>;
    };
    expect(lock.version).toBe("0.1.0");
    expect(lock.packages[""]?.version).toBe("0.1.0");
    for (const retired of [
      "node_modules/@sigstore/verify",
      "node_modules/@sigstore/bundle",
      "node_modules/zod",
    ])
      expect(lock.packages[retired], retired).toBeUndefined();
    expect(read("src/public/package-identity.ts")).toContain('version: "0.1.0"');
    expect(existsSync(resolve(root, "LICENSE"))).toBe(true);
    expect(existsSync(resolve(root, "README.md"))).toBe(true);
    expect(existsSync(resolve(root, "src/index.ts"))).toBe(false);
  });

  it("keeps only the replacement workflows", () => {
    expect(readdirSync(resolve(root, ".github/workflows")).sort()).toEqual([
      "ci.yml",
      "release.yml",
      "scan-report-candidate-upload.yml",
      "scan-report-publisher.yml",
      "semver-label.yml",
    ]);
    expect(existsSync(resolve(root, ".github/workflows/recover-v-scan-0.1.1.yml"))).toBe(false);
    expect(existsSync(resolve(root, ".github/workflow-templates"))).toBe(false);
    for (const name of readdirSync(resolve(root, ".github/workflows")))
      expect(read(`.github/workflows/${name}`), name).not.toMatch(
        /semgrep|bubblewrap|bwrap|docker|baseline-vet|project-core-evidence|actions\/attest@|tools\/artifact|tools\/refresh/i,
      );
  });

  it("signs reports in the default publisher workflow with aih-scan sign and verifies them as trusted", () => {
    const workflow = read(".github/workflows/scan-report-publisher.yml");
    expect(workflow).toContain(
      "github.workflow_ref == 'samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main'",
    );
    expect(workflow).toContain("environment: scan-report-signing-prod");
    expect(workflow).toContain("node tools/publisher/candidate.mjs check-run");
    expect(workflow).toContain("node tools/publisher/candidate.mjs select");
    expect(workflow).toContain('node dist/cli.js sign "signing/$path"');
    expect(workflow).toContain('node dist/cli.js verify "signing/$path" --bundle "$bundle" --json');
    expect(workflow).toContain("r.signer?.trusted!==true");
    expect(workflow).not.toMatch(/workflow_call|pull_request|push:/);
    const signer = workflow.slice(workflow.indexOf("  signer:\n"));
    expect(signer).toMatch(/id-token:\s*write/);
    expect(signer).not.toMatch(/contents:\s*write|attestations:\s*write|actions:\s*read/);
    const bounded = workflow.slice(
      workflow.indexOf("  bounded-candidate:\n"),
      workflow.indexOf("  signer:\n"),
    );
    expect(bounded).not.toMatch(/id-token|environment:/);
    // The workflow path is the default signer's identity.
    expect(read("src/contracts/verification.ts")).toContain(
      ".github/workflows/scan-report-publisher.yml@refs/heads/main",
    );
  });

  it("produces candidates with the packed installed CLI from reviewed pinned sources only", () => {
    const workflow = read(".github/workflows/scan-report-candidate-upload.yml");
    expect(workflow).toContain("node tools/publisher/candidate.mjs sources");
    expect(workflow).toContain("vars.SCAN_REPORT_SOURCES_SHA256");
    expect(workflow).toContain("npm pack --ignore-scripts --json");
    expect(workflow).toContain(
      'npm install --ignore-scripts --no-audit --no-fund --save-exact "$tarball"',
    );
    expect(workflow).toContain("--origin published --json --out");
    expect(workflow).toContain("uv sync --project tools/analyzers/skillspector --locked");
    expect(workflow).not.toMatch(/id-token|environment:|--mode ai/);
    expect(workflow).not.toMatch(/SOURCES_JSON\}\}|\$\{\{ inputs\.sources_json \}\}\s*>/);
  });
});
