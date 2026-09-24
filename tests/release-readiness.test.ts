import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

/** Core's runContractChecks ids, in the producer's order (WO-COMPAT §4). */
const PRODUCER_CHECKS = [
  "catalog-readers",
  "catalog-subject-digests",
  "scan-organization-evidence-schema-lock",
  "scan-decision-schema-lock",
  "catalog-decision-schema-lock",
  "catalog-qualification-receipt-schema-lock",
  "supported-clis-shape",
  "refusal-input-unknown-version",
  "refusal-evidence-unknown-version",
  "refusal-scan-core-contract-unknown",
  "refusal-catalog-index-unknown-version",
  "scan-custody-negative",
] as const;
/** The checks whose subject is Scan plus Core, in the order the gate reports them. */
const SCAN_REQUIRED_CHECKS = [
  "scan-organization-evidence-schema-lock",
  "scan-decision-schema-lock",
  "scan-custody-negative",
  "supported-clis-shape",
  "refusal-input-unknown-version",
  "refusal-evidence-unknown-version",
  "refusal-scan-core-contract-unknown",
] as const;
const sha256Of = (hex: string) => hex.repeat(64);
const SCAN_INTEGRITY = "sha512-c2Nhbi1uZXh0";
const CORE_INTEGRITY = "sha512-Y29yZS1sYXRlc3Q=";
const CATALOG_INTEGRITY = "sha512-Y2F0YWxvZy1sYXRlc3Q=";

const checks = (statuses: Record<string, string> = {}) =>
  PRODUCER_CHECKS.map((id) => ({ id, status: statuses[id] ?? "passed" }));

type RegistryEntry = {
  package: string;
  version: string;
  distTag: string;
  tarballSha256: string;
  tarballIntegrity: string;
};
const SCAN_NEXT: RegistryEntry = {
  package: "@aihq/scan",
  version: "0.5.0",
  distTag: "next",
  tarballSha256: sha256Of("a"),
  tarballIntegrity: SCAN_INTEGRITY,
};
const CORE_LATEST: RegistryEntry = {
  package: "@aihq/core",
  version: "0.7.0",
  distTag: "latest",
  tarballSha256: sha256Of("b"),
  tarballIntegrity: CORE_INTEGRITY,
};
const CATALOG_LATEST: RegistryEntry = {
  package: "@aihq/catalog",
  version: "0.3.0",
  distTag: "latest",
  tarballSha256: sha256Of("c"),
  tarballIntegrity: CATALOG_INTEGRITY,
};

const scanCandidate = (overrides: Record<string, unknown> = {}) => ({
  combination: "scan-candidate",
  candidate: SCAN_NEXT,
  baseline: [CORE_LATEST, CATALOG_LATEST],
  environment: { os: "ubuntu-latest", node: "22", npm: "11.6.2" },
  lockfileSha256: sha256Of("d"),
  contractChecks: checks(),
  ...overrides,
});

/** A Core `core-sibling-compatibility` version 2 artifact as WO-COMPAT §3 describes it. */
const compatibilityArtifact = (overrides: Record<string, unknown> = {}) => {
  const latest = ({ version, tarballSha256, tarballIntegrity }: RegistryEntry) => ({
    version,
    tarballSha256,
    tarballIntegrity,
  });
  return {
    format: "core-sibling-compatibility",
    version: 2,
    runId: "35733767496",
    runAttempt: "2",
    core: { repository: "samartomar/ai-harness", commit: "f".repeat(40) },
    resolvedAt: "2026-09-23T05:17:41.000Z",
    baseline: {
      "@aihq/core": { latest: latest(CORE_LATEST), next: null },
      "@aihq/scan": {
        latest: { version: "0.4.0", tarballSha256: sha256Of("9"), tarballIntegrity: "sha512-b2xk" },
        next: latest(SCAN_NEXT),
      },
      "@aihq/catalog": { latest: latest(CATALOG_LATEST), next: null },
    },
    candidates: [scanCandidate()],
    observations: [
      {
        leg: "registry-all-next",
        combination: "all-next",
        status: "tested",
        os: "ubuntu-latest",
        node: "22",
        packages: [
          { name: "@aihq/core", role: "all-next", version: "0.7.0" },
          { name: "@aihq/scan", role: "all-next", version: "0.5.0" },
          { name: "@aihq/catalog", role: "all-next", version: "0.3.0" },
        ],
        lockfileSha256: sha256Of("8"),
        contractChecks: checks(),
      },
    ],
    limitation:
      "Evidence of what was tested, not authorization and not a dependency pin. A candidate is promotable only for the exact bytes it names, against the exact baseline it names.",
    ...overrides,
  };
};

/** The version 1 shape: one promotable leg per next package, with no tested baseline. */
const compatibilityArtifactV1 = () => ({
  format: "core-sibling-compatibility",
  version: 1,
  runId: "35733767496",
  runAttempt: "2",
  legs: [
    {
      package: "@aihq/scan",
      version: "0.5.0",
      tarballSha256: sha256Of("a"),
      tarballIntegrity: SCAN_INTEGRITY,
      contractChecks: checks(),
    },
  ],
});

type LiveRegistry = {
  integrity: unknown;
  sha256: string;
  distTags: unknown;
  coreDistTags: unknown;
  coreIntegrity: unknown;
  catalogDistTags: unknown;
  catalogIntegrity: unknown;
};
const liveRegistry = (): LiveRegistry => ({
  integrity: SCAN_INTEGRITY,
  sha256: sha256Of("a"),
  distTags: { latest: "0.4.0", next: "0.5.0" },
  coreDistTags: { latest: "0.7.0", next: "0.8.0" },
  coreIntegrity: CORE_INTEGRITY,
  catalogDistTags: { latest: "0.3.0" },
  catalogIntegrity: CATALOG_INTEGRITY,
});

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
    expect(releasing).toContain("public installed Scanner/Core/\nCatalog acceptance");
    expect(releasing).toContain("old bootstrap token is revoked");
    expect(releasing).toContain("allows only `npm publish`");
    expect(releasing).not.toContain("Future Scanner tags remain blocked");
    expect(releasing).not.toContain("must still bind the steady-state trusted publisher");
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
    expect(readme).toContain("promoted `@aihq/scan` stable train");
    expect(readme).toContain("Candidate versions are first published under npm `next`");
    expect(readme).toContain("`@aihq/scan@0.3.0` adds immutable request-addressed publication");
    expect(readme).toContain(
      "`@aihq/scan@0.4.0` advances the bundled Cisco analyzer to `2.0.14+uvlock.aaba1f326049`",
    );
    expect(readme).toContain("version=X.Y.Z");
    expect(readme).toContain('npm install --save-exact "@aihq/scan@$version"');
    expect(readme).toContain('gh attestation verify "$release_root/aihq-scan-$version.tgz"');
    expect(readme).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(readme).toContain("npm provenance");
    expect(readme).toContain("GitHub build attestation");
    expect(readme).toContain("without executing Scanner package code");
    expect(readme).toContain("allows only `npm publish`");
    expect(readme).toContain("old bootstrap token is revoked");
    expect(readme).not.toContain(
      "custody baseline independently observed while preparing this source",
    );
    expect(readme).not.toContain("trusted-publisher binding still requires");
    expect(readme).not.toContain("short-lived npm token must still be revoked");
    expect(readme).not.toContain("Future Scanner tags remain blocked");
    expect(readme).not.toContain("Source `0.1.2` is not published");
    expect(readme).not.toContain("GitHub Release evidence is incomplete");
    expect(readme).toContain("recover-v-scan-0.1.1.yml@refs/heads/main");
    expect(readme).toContain('--source-digest "$release_sha"');
    expect(releasing).toContain("Recovery run `32903155702`");
    expect(releasing).toContain("is no longer present on `main`");

    const project = read("ai-coding/project.md");
    expect(project).toContain("promoted stable train");
    expect(project).not.toContain("Source `0.2.1` is an unpublished patch candidate");
    expect(project).toMatch(/old bootstrap token is\s+revoked/u);
    expect(project).not.toContain("custody baseline observed while preparing source `0.1.2`");
    expect(project).not.toContain("establish whether `0.1.2` is public");
    expect(project).not.toContain("before future release custody is treated as unblocked");

    const router = read("ai-coding/RULE_ROUTER.md");
    expect(router).toContain("builds the `@aihq/scan` V2 API");
  });

  it("gates promotion on Core's compatibility evidence without moving a dist tag", () => {
    const workflow = read(".github/workflows/promotion-readiness.yml");
    // The required check to protect with is the workflow name plus the job id.
    expect(workflow).toContain("name: promotion-readiness");
    expect(workflow).toContain("promotion-readiness / authorize");
    expect(workflow).toContain("  authorize:");
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).not.toMatch(
      /^\s*(push|pull_request|workflow_call|schedule|pull_request_target):/mu,
    );
    expect(workflow).toMatch(/permissions:\n\s+contents: read\n\s+actions: read/u);
    expect(workflow).not.toMatch(/contents:\s*write|id-token:\s*write|packages:\s*write/u);
    for (const input of [
      "candidate_version:",
      "compatibility_run_id:",
      "compatibility_run_attempt:",
      "promotion_authorization_comment:",
    ])
      expect(workflow, input).toContain(input);
    expect(workflow).toContain("core-sibling-compatibility");
    expect(workflow).toContain("--repo samartomar/ai-harness");
    expect(workflow).toContain('npm view "@aihq/scan@$CANDIDATE_VERSION" dist.integrity');
    expect(workflow).toContain('npm view "@aihq/scan" dist-tags --json');
    expect(workflow).toContain("--ignore-scripts");
    // npm pack writes into --pack-destination without creating it, so the directory must
    // be created before the pack runs, inside the same step.
    const packIndex = workflow.indexOf(
      'npm pack "@aihq/scan@$CANDIDATE_VERSION" --ignore-scripts --pack-destination candidate',
    );
    expect(packIndex).toBeGreaterThan(0);
    const packStepStart = workflow.lastIndexOf("      - name:", packIndex);
    const mkdirIndex = workflow.indexOf("mkdir -p candidate\n", packStepStart);
    expect(mkdirIndex).toBeGreaterThan(packStepStart);
    expect(mkdirIndex).toBeLessThan(packIndex);
    expect(workflow).toContain(
      "the published tarball bytes differ from the bytes the compatibility run tested",
    );
    // The supported Core and Catalog the candidate was tested with are re-observed live,
    // after the artifact is downloaded and before the validator reads them.
    const downloadStep = workflow.indexOf(
      "      - name: Download Core's sibling-compatibility evidence",
    );
    const baselineStep = workflow.indexOf(
      "      - name: Re-observe the supported Core and sibling",
    );
    const validatorStep = workflow.indexOf(
      "      - name: Refuse unless the tested bytes are the bytes being promoted",
    );
    expect(downloadStep).toBeGreaterThan(0);
    expect(baselineStep).toBeGreaterThan(downloadStep);
    expect(validatorStep).toBeGreaterThan(baselineStep);
    const baselineStepBody = workflow.slice(baselineStep, validatorStep);
    for (const observation of [
      'npm view "@aihq/core" dist-tags --json > live-baseline-core-dist-tags.json',
      'npm view "@aihq/core@$CORE_VERSION" dist.integrity --json > live-baseline-core-integrity.json',
      'npm view "@aihq/catalog" dist-tags --json > live-baseline-catalog-dist-tags.json',
      'npm view "@aihq/catalog@$CATALOG_VERSION" dist.integrity --json > live-baseline-catalog-integrity.json',
    ])
      expect(baselineStepBody, observation).toContain(observation);
    expect(baselineStepBody).not.toContain("${{");
    expect(workflow).not.toMatch(/evidence\.version !== 1|evidence\.legs/u);
    expect(workflow).toContain("npm dist-tag add @aihq/scan@$CANDIDATE_VERSION latest");
    // The commands exist only inside the printed heredoc, never as an executed step.
    expect(workflow).toContain("Print the promotion commands without running them");
    const heredocStart = workflow.indexOf("cat <<EOF");
    const heredocEnd = workflow.indexOf("EOF", heredocStart + "cat <<EOF".length);
    expect(heredocStart).toBeGreaterThan(0);
    expect(heredocEnd).toBeGreaterThan(heredocStart);
    const outsideHeredoc =
      workflow.slice(0, heredocStart) + workflow.slice(heredocEnd + "EOF".length);
    expect(outsideHeredoc).not.toMatch(/npm dist-tag (add|rm)/u);
    expect(outsideHeredoc).not.toContain("gh release edit");
    expect(workflow).toContain("it is not the owner's promotion authorization");

    const releasing = read("RELEASING.md");
    expect(releasing).toContain("promotion-readiness / authorize");
    expect(releasing).toContain("A green run is evidence, not authorization.");
    expect(releasing).toContain("Authorize promoting @aihq/scan@X.Y.Z from next to latest");
    const releasingProse = releasing.replace(/\s+/gu, " ");
    expect(releasingProse).toContain("version 2 compatibility evidence");
    expect(releasingProse).toContain("exactly one `scan-candidate` combination");
    expect(releasingProse).toContain("the supported `@aihq/core` and `@aihq/catalog` at `latest`");
    expect(releasingProse).toContain(
      "Evidence from an `all-next`, `baseline` or `branch` combination never qualifies",
    );
    expect(releasingProse).toContain("rerun Core's `sibling-compatibility`");
    expect(releasingProse).toContain("The first cutover goes Core first");
    expect(releasingProse).not.toContain("every contract check in its leg passed");

    const contractsProse = read("CONTRACTS.md").replace(/\s+/gu, " ");
    expect(contractsProse).toContain("`core-sibling-compatibility` version 2");
    expect(contractsProse).toContain("refuses version 1 by name");
  });

  it("refuses compatibility evidence unless it comes from Core's own main compatibility run", () => {
    const workflow = read(".github/workflows/promotion-readiness.yml");
    // The run is described before its artifact is downloaded, through env-only inputs.
    const describeIndex = workflow.indexOf(
      'gh api "repos/samartomar/ai-harness/actions/runs/$COMPATIBILITY_RUN_ID" > compatibility-run.json',
    );
    const downloadIndex = workflow.indexOf('gh run download "$COMPATIBILITY_RUN_ID"');
    expect(describeIndex).toBeGreaterThan(0);
    expect(downloadIndex).toBeGreaterThan(describeIndex);
    const inputUses = workflow.split("\n").filter((line) => line.includes("${{ inputs."));
    expect(inputUses.length).toBeGreaterThan(0);
    for (const line of inputUses)
      expect(line, line).toMatch(
        /^(\s+[A-Z_]+: \$\{\{ inputs\.[a-z_]+ \}\}|\s+group: promotion-readiness-\$\{\{ inputs\.candidate_version \}\})$/u,
      );
    // Each refusal is pinned by its condition and its named message.
    for (const refusal of [
      "refused: Core compatibility run $COMPATIBILITY_RUN_ID is unreadable",
      'refuse("the compatibility run description is not readable JSON")',
      'refuse("the compatibility run description is not an object")',
      "if (String(run.id) !== process.env.COMPATIBILITY_RUN_ID)",
      'if (run.head_repository?.full_name !== "samartomar/ai-harness")',
      ", not samartomar/ai-harness`",
      'if (run.path !== ".github/workflows/sibling-compatibility.yml")',
      ", not .github/workflows/sibling-compatibility.yml`",
      'if (run.event !== "schedule" && run.event !== "workflow_dispatch")',
      ", not schedule or workflow_dispatch`",
      'if (run.head_branch !== "main")',
      ", not main`",
      'if (run.conclusion !== "success")',
      ", not success`",
      "if (String(run.run_attempt) !== process.env.COMPATIBILITY_RUN_ATTEMPT)",
      "the compatibility run's latest attempt is",
    ])
      expect(workflow, refusal).toContain(refusal);

    const validator = inlineModuleFollowing(
      workflow,
      "Refuse evidence from any run but Core's own main compatibility run",
    );
    const genuine = {
      id: 35733767496,
      path: ".github/workflows/sibling-compatibility.yml",
      event: "schedule",
      head_branch: "main",
      conclusion: "success",
      run_attempt: 2,
      head_repository: { full_name: "samartomar/ai-harness" },
    };
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-promotion-run-"));
    try {
      const validate = (run: unknown, raw?: string) => {
        writeFileSync(join(fixtureRoot, "compatibility-run.json"), raw ?? JSON.stringify(run));
        return spawnSync(process.execPath, ["--input-type=module", "-"], {
          cwd: fixtureRoot,
          input: validator,
          encoding: "utf8",
          env: {
            ...process.env,
            COMPATIBILITY_RUN_ID: "35733767496",
            COMPATIBILITY_RUN_ATTEMPT: "2",
          },
        });
      };

      expect(validate(genuine).status).toBe(0);
      expect(validate({ ...genuine, event: "workflow_dispatch" }).status).toBe(0);
      for (const [label, forged, reason] of [
        ["other run", { ...genuine, id: 35733767497 }, "the compatibility run is 35733767497"],
        [
          "fork",
          { ...genuine, head_repository: { full_name: "someone/ai-harness" } },
          "ran from someone/ai-harness",
        ],
        [
          "other workflow",
          { ...genuine, path: ".github/workflows/ci.yml" },
          "is .github/workflows/ci.yml",
        ],
        ["pull request", { ...genuine, event: "pull_request" }, "triggered by pull_request"],
        [
          "pull request target",
          { ...genuine, event: "pull_request_target" },
          "triggered by pull_request_target",
        ],
        ["push", { ...genuine, event: "push" }, "triggered by push"],
        ["branch", { ...genuine, head_branch: "feature" }, "ran on feature, not main"],
        ["failure", { ...genuine, conclusion: "failure" }, "concluded failure, not success"],
        ["in progress", { ...genuine, conclusion: null }, "concluded null, not success"],
        ["attempt", { ...genuine, run_attempt: 3 }, "latest attempt is 3, not 2"],
        ["array", [genuine], "description is not an object"],
        ["null", null, "description is not an object"],
      ] as const) {
        const result = validate(forged);
        expect(result.status, label).toBe(1);
        expect(result.stderr, label).toMatch(/^refused: the compatibility run('s)? /u);
        expect(result.stderr, label).toContain(reason);
      }
      const unreadable = validate(undefined, "{not json");
      expect(unreadable.status).toBe(1);
      expect(unreadable.stderr).toContain(
        "refused: the compatibility run description is not readable JSON",
      );
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("reads the supported Core and Catalog versions to re-observe only from the scan-candidate combination", () => {
    const workflow = read(".github/workflows/promotion-readiness.yml");
    const extractor = inlineModuleFollowing(workflow, "Re-observe the supported Core and sibling");
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-promotion-baseline-"));
    try {
      mkdirSync(join(fixtureRoot, "compatibility"));
      const extract = (artifact: unknown) => {
        writeFileSync(
          join(fixtureRoot, "compatibility", "core-sibling-compatibility.json"),
          JSON.stringify(artifact),
        );
        return spawnSync(process.execPath, ["--input-type=module", "-"], {
          cwd: fixtureRoot,
          input: extractor,
          encoding: "utf8",
        });
      };

      const genuine = extract(compatibilityArtifact());
      expect(genuine.stderr).toBe("");
      expect(genuine.status).toBe(0);
      expect(genuine.stdout).toBe("0.7.0\n0.3.0\n");

      const [core, catalog] = [CORE_LATEST, CATALOG_LATEST];
      for (const [label, artifact, reason] of [
        [
          "version 1",
          compatibilityArtifactV1(),
          "the compatibility artifact declares an unknown format or version",
        ],
        [
          "all-next only",
          compatibilityArtifact({ candidates: [] }),
          "the compatibility artifact names no single @aihq/scan candidate tested against the supported Core",
        ],
        [
          "Core at next",
          compatibilityArtifact({
            candidates: [scanCandidate({ baseline: [{ ...core, distTag: "next" }, catalog] })],
          }),
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "shell text in a version",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ baseline: [{ ...core, version: "0.7.0$(id)" }, catalog] }),
            ],
          }),
          "the candidate combination does not name the supported Core and sibling",
        ],
      ] as const) {
        const result = extract(artifact);
        expect(result.status, label).toBe(1);
        expect(result.stdout, label).toBe("");
        expect(result.stderr, label).toBe(`refused: ${reason}\n`);
      }
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("promotes only a scan-candidate tested against the still-supported Core and Catalog", () => {
    const workflow = read(".github/workflows/promotion-readiness.yml");
    const validator = inlineModuleFollowing(
      workflow,
      "Refuse unless the tested bytes are the bytes being promoted",
    );
    const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-promotion-bytes-"));
    try {
      mkdirSync(join(fixtureRoot, "compatibility"));
      const validate = (artifact: unknown, observed: Partial<LiveRegistry> = {}) => {
        const live = { ...liveRegistry(), ...observed };
        const files: Record<string, unknown> = {
          "compatibility/core-sibling-compatibility.json": artifact,
          "live-integrity.json": live.integrity,
          "live-dist-tags.json": live.distTags,
          "live-baseline-core-dist-tags.json": live.coreDistTags,
          "live-baseline-core-integrity.json": live.coreIntegrity,
          "live-baseline-catalog-dist-tags.json": live.catalogDistTags,
          "live-baseline-catalog-integrity.json": live.catalogIntegrity,
        };
        for (const [path, value] of Object.entries(files)) {
          rmSync(join(fixtureRoot, path), { force: true });
          if (value !== undefined) writeFileSync(join(fixtureRoot, path), JSON.stringify(value));
        }
        writeFileSync(join(fixtureRoot, "live-tarball-sha256.txt"), `${live.sha256}\n`);
        return spawnSync(process.execPath, ["--input-type=module", "-"], {
          cwd: fixtureRoot,
          input: validator,
          encoding: "utf8",
          env: {
            ...process.env,
            CANDIDATE_VERSION: "0.5.0",
            COMPATIBILITY_RUN_ID: "35733767496",
            COMPATIBILITY_RUN_ATTEMPT: "2",
          },
        });
      };

      // (l) READY names the tested combination, its baseline and its environment.
      const ready = validate(compatibilityArtifact());
      expect(ready.stderr).toBe("");
      expect(ready.status).toBe(0);
      const printed = JSON.parse(ready.stdout);
      expect(printed).toMatchObject({
        status: "READY",
        candidateVersion: "0.5.0",
        combination: "scan-candidate",
        testedBy: { runId: "35733767496", runAttempt: "2" },
        tarballSha256: sha256Of("a"),
        tarballIntegrity: SCAN_INTEGRITY,
        baseline: [
          { package: "@aihq/core", version: "0.7.0", tarballSha256: sha256Of("b") },
          { package: "@aihq/catalog", version: "0.3.0", tarballSha256: sha256Of("c") },
        ],
        environment: { os: "ubuntu-latest", node: "22", npm: "11.6.2" },
        requiredChecks: SCAN_REQUIRED_CHECKS.length,
        otherChecksNotPassed: [],
        authority: "none",
      });

      // A failed check outside Scan's required list is shown to the owner, not refused.
      const otherFailed = validate(
        compatibilityArtifact({
          candidates: [scanCandidate({ contractChecks: checks({ "catalog-readers": "failed" }) })],
        }),
      );
      expect(otherFailed.stderr).toBe("");
      expect(otherFailed.status).toBe(0);
      expect(JSON.parse(otherFailed.stdout).otherChecksNotPassed).toEqual(["catalog-readers"]);

      const candidate = scanCandidate();
      const [core, catalog] = [CORE_LATEST, CATALOG_LATEST];
      const withoutCheck = checks().filter(
        (check) => check.id !== "refusal-scan-core-contract-unknown",
      );
      for (const [label, artifact, observed, reason] of [
        [
          "(a) version 1",
          compatibilityArtifactV1(),
          {},
          "the compatibility artifact declares an unknown format or version",
        ],
        [
          "no candidates array",
          compatibilityArtifact({ candidates: undefined }),
          {},
          "the compatibility artifact declares an unknown format or version",
        ],
        [
          "other run",
          compatibilityArtifact({ runAttempt: "1" }),
          {},
          "the compatibility artifact was produced by a different run or attempt",
        ],
        [
          "(b) all-next observation only",
          compatibilityArtifact({ candidates: [] }),
          {},
          "the compatibility artifact names no single @aihq/scan candidate tested against the supported Core",
        ],
        [
          "all-next posing as a candidate",
          compatibilityArtifact({ candidates: [{ ...candidate, combination: "all-next" }] }),
          {},
          "the compatibility artifact names no single @aihq/scan candidate tested against the supported Core",
        ],
        [
          "two candidates",
          compatibilityArtifact({ candidates: [candidate, candidate] }),
          {},
          "the compatibility artifact names no single @aihq/scan candidate tested against the supported Core",
        ],
        [
          "other version",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ candidate: { ...candidate.candidate, version: "0.4.9" } }),
            ],
          }),
          {},
          "the tested candidate is 0.4.9, not 0.5.0",
        ],
        [
          "candidate not from next",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ candidate: { ...candidate.candidate, distTag: "latest" } }),
            ],
          }),
          {},
          "the tested candidate was resolved from latest, not next",
        ],
        [
          "(f) baseline Core at next",
          compatibilityArtifact({
            candidates: [scanCandidate({ baseline: [{ ...core, distTag: "next" }, catalog] })],
          }),
          {},
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "(g) baseline missing the other sibling",
          compatibilityArtifact({ candidates: [scanCandidate({ baseline: [core] })] }),
          {},
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "baseline names Core twice",
          compatibilityArtifact({ candidates: [scanCandidate({ baseline: [core, core] })] }),
          {},
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "baseline names Scan",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ baseline: [core, { ...catalog, package: "@aihq/scan" }] }),
            ],
          }),
          {},
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "baseline without bytes",
          compatibilityArtifact({
            candidates: [scanCandidate({ baseline: [{ ...core, tarballSha256: "b" }, catalog] })],
          }),
          {},
          "the candidate combination does not name the supported Core and sibling",
        ],
        [
          "(c) required check failed",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ contractChecks: checks({ "scan-decision-schema-lock": "failed" }) }),
            ],
          }),
          {},
          "1 required contract check(s) missing or not passed: scan-decision-schema-lock",
        ],
        [
          "(d) required check unavailable",
          compatibilityArtifact({
            candidates: [
              scanCandidate({ contractChecks: checks({ "scan-custody-negative": "unavailable" }) }),
            ],
          }),
          {},
          "1 required contract check(s) missing or not passed: scan-custody-negative",
        ],
        [
          "(e) required check missing",
          compatibilityArtifact({ candidates: [scanCandidate({ contractChecks: withoutCheck })] }),
          {},
          "1 required contract check(s) missing or not passed: refusal-scan-core-contract-unknown",
        ],
        [
          "required check recorded twice",
          compatibilityArtifact({
            candidates: [
              scanCandidate({
                contractChecks: [...checks(), { id: "supported-clis-shape", status: "passed" }],
              }),
            ],
          }),
          {},
          "1 required contract check(s) missing or not passed: supported-clis-shape",
        ],
        [
          "no checks recorded",
          compatibilityArtifact({ candidates: [scanCandidate({ contractChecks: undefined })] }),
          {},
          `${SCAN_REQUIRED_CHECKS.length} required contract check(s) missing or not passed: ${SCAN_REQUIRED_CHECKS.join(", ")}`,
        ],
        [
          "(k) environment missing",
          compatibilityArtifact({ candidates: [scanCandidate({ environment: undefined })] }),
          {},
          "the candidate combination records no execution environment (os and node)",
        ],
        [
          "environment without node",
          compatibilityArtifact({
            candidates: [scanCandidate({ environment: { os: "ubuntu-latest", node: "" } })],
          }),
          {},
          "the candidate combination records no execution environment (os and node)",
        ],
        [
          "other integrity",
          compatibilityArtifact(),
          { integrity: "sha512-b3RoZXI=" },
          "the registry integrity differs from the integrity the compatibility run tested",
        ],
        [
          "other bytes",
          compatibilityArtifact(),
          { sha256: sha256Of("e") },
          "the published tarball bytes differ from the bytes the compatibility run tested",
        ],
        [
          "next moved",
          compatibilityArtifact(),
          { distTags: { latest: "0.4.0", next: "0.5.1" } },
          "npm dist-tags.next is 0.5.1, not 0.5.0",
        ],
        [
          "(h) live Core latest moved",
          compatibilityArtifact(),
          { coreDistTags: { latest: "0.7.1", next: "0.8.0" } },
          "the supported @aihq/core moved since the compatibility run (latest is 0.7.1, tested 0.7.0); rerun Core's sibling-compatibility",
        ],
        [
          "(i) live Core integrity differs",
          compatibilityArtifact(),
          { coreIntegrity: "sha512-b3RoZXI=" },
          "the supported @aihq/core@0.7.0 bytes differ from the bytes the compatibility run tested",
        ],
        [
          "(j) live sibling moved",
          compatibilityArtifact(),
          { catalogDistTags: { latest: "0.3.1" } },
          "the supported @aihq/catalog moved since the compatibility run (latest is 0.3.1, tested 0.3.0); rerun Core's sibling-compatibility",
        ],
        [
          "live sibling integrity differs",
          compatibilityArtifact(),
          { catalogIntegrity: "sha512-b3RoZXI=" },
          "the supported @aihq/catalog@0.3.0 bytes differ from the bytes the compatibility run tested",
        ],
        [
          "live Core never observed",
          compatibilityArtifact(),
          { coreDistTags: undefined },
          "live-baseline-core-dist-tags.json is not readable JSON",
        ],
        [
          "live sibling integrity never observed",
          compatibilityArtifact(),
          { catalogIntegrity: undefined },
          "live-baseline-catalog-integrity.json is not readable JSON",
        ],
      ] as const) {
        const result = validate(artifact, observed as Partial<LiveRegistry>);
        expect(result.status, label).toBe(1);
        expect(result.stdout, label).toBe("");
        expect(result.stderr, label).toBe(`refused: ${reason}\n`);
      }
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("enforces package-bearing and repository-only release classes in CI", () => {
    const semver = read(".github/workflows/semver-label.yml");
    expect(semver).toContain("semver:none|semver:patch|semver:minor|semver:major");
    expect(semver).toContain("Exactly one semver:* label is required");
    expect(read("VERSIONING.md")).toContain("cannot start or bump a package cut");
  });

  it("declares the exact package identity and public file roots", () => {
    // package-install-v2 owns the one real npm-pack/install boundary. A second
    // concurrent pack here races its prepack build and can read a partial dist file.
    const manifest = JSON.parse(read("package.json")) as {
      name?: unknown;
      version?: unknown;
      files?: unknown;
    };
    expect(manifest).toMatchObject({
      name: "@aihq/scan",
      version: "0.5.0",
      files: ["dist", "tools/baseline-analyzers", "tools/verify-core-contract-lock-v2.mjs"],
    });
    expect(existsSync(resolve(root, "LICENSE"))).toBe(true);
    expect(existsSync(resolve(root, "README.md"))).toBe(true);
  });

  it("retires the one-use 0.1.1 recovery workflow after verified success", () => {
    expect(existsSync(resolve(root, ".github/workflows/recover-v-scan-0.1.1.yml"))).toBe(false);
  });

  // Preserve the exact adversarial contract as a fail-loud diagnostic if the
  // spent one-use workflow is ever restored; it is not part of steady-state CI.
  if (!existsSync(resolve(root, ".github/workflows/recover-v-scan-0.1.1.yml"))) {
    return;
  }

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
    expect(recovery).toContain("output-file: aih-scan-sbom.spdx.json");
    expect(recovery).toContain("SBOM_PATH=aih-scan-sbom.spdx.json");
    expect(recovery).toContain('SBOM_PATH="$release_root/aih-scan-sbom.spdx.json"');
    expect(recovery).not.toContain("aihq-scan-sbom.spdx.json");
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

  it("normalizes the upload-artifact digest before comparing live API custody", () => {
    const recovery = read(".github/workflows/recover-v-scan-0.1.1.yml");
    expect(recovery).toContain('if ! [[ "$RECOVERY_ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]; then');
    expect(recovery).toContain('expected_api_digest="sha256:$RECOVERY_ARTIFACT_DIGEST"');
    expect(recovery).toContain('test "$api_digest" = "$expected_api_digest"');
    expect(recovery).not.toContain('[[ "$RECOVERY_ARTIFACT_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]');
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
    const validator = inlineModuleFollowing(recovery, "SBOM_PATH=aih-scan-sbom.spdx.json");
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
