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

  it("documents tokenless publication, authority, verification, and immutable failure behavior", () => {
    const releasing = read("RELEASING.md");
    expect(releasing).toContain(
      "npm trust github @aihq/scan --file release.yml --repo samartomar/aih-scan --env npm-publish --allow-publish",
    );
    expect(releasing).toContain("npm trust list @aihq/scan");
    expect(releasing).toContain("full-SHA publication authorization");
    expect(releasing).toContain("GitHub bootstrap secret is absent");
    expect(releasing).toContain("revoke the npm token");
    expect(releasing).toContain("Future Scanner tags remain blocked");
    expect(releasing).not.toContain("**Bypass 2FA** enabled");
    expect(releasing).not.toContain("NPM_BOOTSTRAP_TOKEN");
    expect(releasing).toContain("never delete, move, or reuse the tag");
    expect(releasing).toContain("npm refused the protected publish with `EOTP`");
    expect(releasing).toContain("read-only `verify-and-pack` job");
    expect(releasing).toContain("runs no Scanner package code");
    expect(releasing).toContain('npm view "@aihq/scan@$version"');
    expect(releasing).toContain('gh attestation verify "./aihq-scan-$version.tgz"');
    expect(releasing).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(releasing).toContain("Scanner evidence is not organization authority");

    const readme = read("README.md");
    expect(readme).toContain("npm install --save-exact @aihq/scan@0.1.1");
    expect(readme).toContain("gh attestation verify ./aihq-scan-0.1.1.tgz");
    expect(readme).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(readme).toContain("npm provenance");
    expect(readme).toContain("GitHub build attestation");
    expect(readme).toContain("without executing Scanner package code");
    expect(readme).toContain("is public on npm");
    expect(readme).toContain("GitHub Release evidence is incomplete");
    expect(readme).toContain("recover-v-scan-0.1.1.yml@refs/heads/main");
    expect(readme).toContain('--source-digest "$release_sha"');
    expect(releasing).toContain("recovery workflow source SHA");
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

  it("recovers only the exact retained 0.1.1 artifact through a protected no-execution boundary", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    expect(recovery).toContain("workflow_dispatch:");
    expect(recovery).not.toMatch(/push:|pull_request:|workflow_call:/u);
    expect(recovery).toContain("concurrency:");
    expect(recovery).toContain("v-scan-0.1.1");
    expect(recovery).toContain("a1f3541cf36af7a128d4ce4554a4b6bbc3d53fa8");
    expect(recovery).toContain("32876377673");
    expect(recovery).toContain("9574045679");
    expect(recovery).toContain(
      "sha256:16edeb32b197f2d42b40d9b2a9e96cbbf0ef85b847f0cde609d4e7dd1dbf8410",
    );
    expect(recovery).toContain("ac80c7a2254d796aa30e489f6c3b7c2b72afa1194a3e5ed9e31a128b8e7ae8ec");
    expect(recovery).toContain("cccb6bb5b1a2a2b9c434e6468c25165a83e66f94");
    expect(recovery).toContain("verify-recovery:");
    expect(recovery).toContain("recover-release:");
    expect(recovery).toContain("needs: verify-recovery");
    expect(recovery).toContain("name: npm-publish");
    expect(recovery).toContain("actions: read");
    expect(recovery).toMatch(/contents:\s*write/u);
    expect(recovery).toMatch(/id-token:\s*write/u);
    expect(recovery).toContain("artifact-ids: 9574045679");
    expect(recovery).toContain("run-id: 32876377673");
    expect(recovery).toContain("digest-mismatch: error");
    expect(recovery).toContain("gh attestation verify");
    expect(recovery).toContain("--source-ref refs/tags/v-scan-0.1.1");
    expect(recovery).toContain("--source-digest a1f3541cf36af7a128d4ce4554a4b6bbc3d53fa8");
    expect(recovery).toContain("--deny-self-hosted-runners");
    expect(recovery).toContain("gh attestation download");
    expect(recovery).toContain('PROVENANCE_BUNDLE="$bundle" node');
    expect(recovery).toContain("original provenance bundle is ambiguous");
    expect(recovery).toContain('--bundle "$bundle"');
    expect(recovery).toContain("format: spdx-json");
    expect(recovery).toContain("cosign sign-blob --yes");
    expect(recovery).toContain("cosign verify-blob");
    expect(recovery).toContain("--certificate-identity");
    expect(recovery).toContain("--certificate-oidc-issuer");
    expect(recovery).toContain("SHA256SUMS.txt.sigstore.json");
    expect(recovery).toContain("sha256sum aih-scan-sbom.spdx.json");
    expect(recovery).toContain('sha256sum "$TARBALL"');
    expect(recovery).toContain("sha256sum provenance.intoto.jsonl");
    expect(recovery).toContain("recovery checksum evidence is not exact for all release assets");
    expect(recovery).toContain('cmp --silent SHA256SUMS.txt "$release_root/SHA256SUMS.txt"');
    expect(recovery).toContain("sha256sum --strict --check --status SHA256SUMS.txt");
    expect(recovery).toContain("recovery SBOM is not exact SPDX evidence for the retained tarball");
    expect(recovery).toContain('gh release create "$RELEASE_TAG"');
    expect(recovery).toContain('--repo "$GITHUB_REPOSITORY"');
    expect(recovery).toContain("--verify-tag");
    expect(recovery).toContain("Recovery workflow source $GITHUB_SHA");
    expect(recovery.match(/typeof signature\.keyid/gu)).toHaveLength(2);
    expect(recovery).not.toContain("npm publish");
    expect(recovery).not.toContain("NPM_BOOTSTRAP_TOKEN");
    expect(recovery).not.toContain("NODE_AUTH_TOKEN");
    expect(recovery).not.toContain("NPM_TOKEN");

    const effectJob = recovery.slice(recovery.indexOf("  recover-release:\n"));
    expect(effectJob).not.toMatch(
      /actions\/checkout|npm ci|npm install|npm pack(?:\s|$)|npm run |--help/u,
    );
    const claimIndex = effectJob.indexOf("# Claim before the checksum-signing effect.");
    const signIndex = effectJob.indexOf("cosign sign-blob --yes");
    const revalidationIndex = effectJob.indexOf(
      "# Revalidate every live claim immediately before the Release effect.",
    );
    const releaseIndex = effectJob.indexOf('gh release create "$RELEASE_TAG"');
    expect(claimIndex).toBeGreaterThanOrEqual(0);
    for (const call of [
      "verify_live_tag",
      "verify_npm_package",
      "verify_release_absence",
      "verify_tarball",
    ]) {
      const callIndex = effectJob.indexOf(call, claimIndex);
      expect(callIndex, call).toBeGreaterThan(claimIndex);
      expect(callIndex, call).toBeLessThan(signIndex);
    }
    expect(signIndex).toBeGreaterThan(claimIndex);
    expect(revalidationIndex).toBeGreaterThan(signIndex);
    for (const call of [
      "verify_live_tag",
      "verify_npm_package",
      "verify_release_absence",
      "verify_tarball",
    ]) {
      const callIndex = effectJob.indexOf(call, revalidationIndex);
      expect(callIndex, call).toBeGreaterThan(revalidationIndex);
      expect(callIndex, call).toBeLessThan(releaseIndex);
    }
    expect(releaseIndex).toBeGreaterThan(revalidationIndex);

    const actions = [...recovery.matchAll(/^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+).*$/gmu)];
    expect(actions.length).toBeGreaterThanOrEqual(5);
    for (const [, action, revision] of actions) {
      expect(action).toMatch(/^[\w.-]+\/[\w.-]+$/u);
      expect(revision).toMatch(/^[0-9a-f]{40}$/u);
    }
  });

  it("rejects substituted, expired, or ambiguous retained release artifacts", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(recovery, "ARTIFACT_OBSERVATION=");
    const valid = {
      id: 9574045679,
      name: "scan-release-32876377673-1",
      expired: false,
      digest: "sha256:16edeb32b197f2d42b40d9b2a9e96cbbf0ef85b847f0cde609d4e7dd1dbf8410",
      workflow_run: {
        id: 32876377673,
        head_sha: "a1f3541cf36af7a128d4ce4554a4b6bbc3d53fa8",
        head_branch: "v-scan-0.1.1",
      },
    };
    const validate = (value: unknown) =>
      spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
        env: { ...process.env, ARTIFACT_OBSERVATION: JSON.stringify(value) },
        encoding: "utf8",
      });

    expect(validate(valid).status).toBe(0);
    for (const invalid of [
      { ...valid, id: 9574045680 },
      { ...valid, name: "scan-release-substituted" },
      { ...valid, expired: true },
      { ...valid, digest: `sha256:${"0".repeat(64)}` },
      { ...valid, workflow_run: { ...valid.workflow_run, id: 32876377674 } },
      { ...valid, workflow_run: { ...valid.workflow_run, head_sha: "0".repeat(40) } },
      { ...valid, workflow_run: { ...valid.workflow_run, head_branch: "main" } },
      [valid],
      null,
    ]) {
      expect(validate(invalid).status, JSON.stringify(invalid)).not.toBe(0);
    }
  });

  it("rejects mismatched or ambiguous npm observations during recovery", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(recovery, "NPM_OBSERVATION=");
    const sha1 = "cccb6bb5b1a2a2b9c434e6468c25165a83e66f94";
    const integrity =
      "sha512-NZchLJPGwVWY1V5U8GMei8Nts7g+wDcIPNmC4e6/bIV3p1JoktLc0TK0pLR/NTDtJ8J9DKlrv9XSON0yalmLXw==";
    const valid = {
      name: "@aihq/scan",
      version: "0.1.1",
      dist: {
        shasum: sha1,
        integrity,
        tarball: "https://registry.npmjs.org/@aihq/scan/-/scan-0.1.1.tgz",
        attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } },
        signatures: [{ keyid: "SHA256:key", sig: "signature" }],
      },
    };
    const validate = (value: unknown) =>
      spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
        env: {
          ...process.env,
          NPM_OBSERVATION: JSON.stringify(value),
          EXPECTED_SHA1: sha1,
          EXPECTED_INTEGRITY: integrity,
        },
        encoding: "utf8",
      });

    expect(validate(valid).status).toBe(0);
    for (const invalid of [
      { ...valid, extra: true },
      { ...valid, name: "@aihq/core" },
      { ...valid, version: "0.1.2" },
      { ...valid, dist: { ...valid.dist, shasum: "0".repeat(40) } },
      { ...valid, dist: { ...valid.dist, integrity: "sha512-substituted" } },
      { ...valid, dist: { ...valid.dist, tarball: "https://attacker.invalid/scan.tgz" } },
      { ...valid, dist: { ...valid.dist, attestations: undefined } },
      { ...valid, dist: { ...valid.dist, signatures: [] } },
      [valid],
      null,
    ]) {
      expect(validate(invalid).status, JSON.stringify(invalid)).not.toBe(0);
    }
  });

  it("rejects duplicate archive identities in a retained recovery tarball", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(
      recovery,
      'test "$actual_integrity" = "$TARBALL_INTEGRITY"',
    );
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-release-recovery-archive-"));
    try {
      const packageRoot = join(fixtureRoot, "package");
      mkdirSync(packageRoot);
      writeFileSync(
        join(packageRoot, "package.json"),
        JSON.stringify({
          name: "@aihq/scan",
          version: "0.1.1",
          publishConfig: { access: "public" },
        }),
      );
      execFileSync("tar", ["-czf", "valid.tgz", "package/package.json"], {
        cwd: fixtureRoot,
      });
      execFileSync(
        "tar",
        ["-czf", "duplicate.tgz", "package/package.json", "package/package.json"],
        { cwd: fixtureRoot },
      );
      const validate = (tarball: string) =>
        spawnSync(process.execPath, ["--input-type=module", "-", tarball], {
          cwd: fixtureRoot,
          input: validator,
          encoding: "utf8",
        });

      const validResult = validate("valid.tgz");
      expect(validResult.status, `${validResult.stdout}${validResult.stderr}`).toBe(0);
      expect(validate("duplicate.tgz").status).not.toBe(0);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("rejects ambiguous original provenance bundles before release recovery", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(recovery, 'PROVENANCE_BUNDLE="$bundle" node');
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-release-recovery-provenance-"));
    try {
      const validate = (contents: string) => {
        const bundle = join(fixtureRoot, "provenance.intoto.jsonl");
        writeFileSync(bundle, contents);
        return spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
          env: { ...process.env, PROVENANCE_BUNDLE: bundle },
          encoding: "utf8",
        });
      };

      expect(
        validate('{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n').status,
      ).toBe(0);
      expect(
        validate(
          '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n',
        ).status,
      ).not.toBe(0);
      expect(validate("not-json\n").status).not.toBe(0);
      expect(validate("\n").status).not.toBe(0);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("signs only exact sorted checksums for every recovered evidence asset", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(recovery, "CHECKSUMS_PATH=SHA256SUMS.txt");
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-release-recovery-checksums-"));
    const tarball = "aihq-scan-0.1.1.tgz";
    const tarballSha256 = "ac80c7a2254d796aa30e489f6c3b7c2b72afa1194a3e5ed9e31a128b8e7ae8ec";
    try {
      const validate = (contents: string) => {
        const checksums = join(fixtureRoot, "SHA256SUMS.txt");
        writeFileSync(checksums, contents);
        return spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
          env: {
            ...process.env,
            CHECKSUMS_PATH: checksums,
            EXPECTED_TARBALL: tarball,
            EXPECTED_SHA256: tarballSha256,
          },
          encoding: "utf8",
        });
      };
      const valid = [
        `${"1".repeat(64)}  aih-scan-sbom.spdx.json`,
        `${tarballSha256}  ${tarball}`,
        `${"2".repeat(64)}  provenance.intoto.jsonl`,
        "",
      ].join("\n");

      expect(validate(valid).status).toBe(0);
      expect(validate(valid.replace(tarballSha256, "0".repeat(64))).status).not.toBe(0);
      expect(validate(valid.replace("provenance.intoto.jsonl", "extra.asset")).status).not.toBe(0);
      expect(validate(`${valid}${"3".repeat(64)}  unexpected.txt\n`).status).not.toBe(0);
      expect(validate(valid.split("\n").reverse().join("\n")).status).not.toBe(0);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("rejects malformed or mismatched tarball-scoped SPDX evidence", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    const validator = inlineModuleFollowing(recovery, "SBOM_PATH=aihq-scan-sbom.spdx.json");
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-release-recovery-sbom-"));
    const tarball = "aihq-scan-0.1.1.tgz";
    const tarballSha256 = "ac80c7a2254d796aa30e489f6c3b7c2b72afa1194a3e5ed9e31a128b8e7ae8ec";
    const valid = {
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: tarball,
      documentNamespace: "https://example.test/spdx/document",
      packages: [
        {
          name: `/tmp/${tarball}`,
          versionInfo: `sha256:${tarballSha256}`,
          checksums: [{ algorithm: "SHA256", checksumValue: tarballSha256 }],
        },
      ],
    };
    try {
      const validate = (sbom: unknown) => {
        const sbomPath = join(fixtureRoot, "aih-scan-sbom.spdx.json");
        writeFileSync(sbomPath, JSON.stringify(sbom));
        return spawnSync(process.execPath, ["--input-type=module", "-e", validator], {
          env: {
            ...process.env,
            SBOM_PATH: sbomPath,
            EXPECTED_TARBALL: tarball,
            EXPECTED_SHA256: tarballSha256,
          },
          encoding: "utf8",
        });
      };

      expect(validate(valid).status).toBe(0);
      expect(
        validate({
          ...valid,
          packages: [{ ...valid.packages[0], versionInfo: `sha256:${"0".repeat(64)}` }],
        }).status,
      ).not.toBe(0);
      expect(
        validate({ ...valid, packages: [...valid.packages, valid.packages[0]] }).status,
      ).not.toBe(0);
      expect(validate({ ...valid, spdxVersion: "SPDX-2" }).status).not.toBe(0);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });
});
