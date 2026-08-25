import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8").replace(/\r\n/gu, "\n");

describe("@aihq/scan release boundary (#12)", () => {
  it("uses the same Apache-2.0 public-package boundary as Core", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.license).toBe("Apache-2.0");
    expect(manifest.publishConfig).toEqual({ access: "public" });
    expect(read("LICENSE")).toContain("Apache License\n                           Version 2.0");
    expect(read("README.md")).toContain("[Apache-2.0](LICENSE)");
  });

  it("pins one tag-only, main-bound trusted-publishing workflow", () => {
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
    expect(workflow).toMatch(/id-token:\s*write/);
    expect(workflow).toMatch(/attestations:\s*write/);
    expect(workflow).toMatch(/contents:\s*write/);
    expect(workflow).not.toContain("packages: write");
    expect(workflow).not.toContain("NPM_TOKEN");
    expect(workflow).not.toContain("NODE_AUTH_TOKEN");

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
    expect(workflow).toContain('sha256sum "$tarball"');
    expect(workflow.match(/sha256sum -c SHA256SUMS\.txt/gmu)).toHaveLength(3);
    expect(workflow).toContain(['file: "$', '{{ steps.pack.outputs.tarball }}"'].join(""));
    expect(workflow).toContain(['subject-path: "$', '{{ steps.pack.outputs.tarball }}"'].join(""));
    expect(workflow).toContain(
      'npm install --prefix "$consumer" --ignore-scripts --no-audit --no-fund "$tarball"',
    );
    expect(workflow).toContain('"$consumer/node_modules/.bin/aih-scan" --help');
    expect(workflow).toContain(
      'npm publish "$tarball" --provenance --access public --tag "$dist_tag"',
    );
    expect(workflow).toContain("format: spdx-json");
    expect(workflow).toContain("cosign sign-blob --yes");
    expect(workflow).toContain("gh release create");
  });

  it("documents bootstrap, authority, verification, and immutable failure behavior", () => {
    const releasing = read("RELEASING.md");
    expect(releasing).toContain("package must already exist");
    expect(releasing).toContain(
      "samartomar/aih-scan, workflow `release.yml`, environment `npm-publish`",
    );
    expect(releasing).toContain("full-SHA publication authorization");
    expect(releasing).toContain("one-use GitHub bootstrap path");
    expect(releasing).toContain("never delete, move, or reuse the tag");
    expect(releasing).toContain("npm view @aihq/scan@0.1.0");
    expect(releasing).toContain("gh attestation verify ./aihq-scan-0.1.0.tgz");
    expect(releasing).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(releasing).toContain("Scanner evidence is not organization authority");

    const readme = read("README.md");
    expect(readme).toContain("npm install --save-exact @aihq/scan@0.1.0");
    expect(readme).toContain("gh attestation verify ./aihq-scan-0.1.0.tgz");
    expect(readme).not.toContain("gh attestation verify ./node_modules/@aihq/scan");
    expect(readme).toContain("npm provenance");
    expect(readme).toContain("GitHub build attestation");
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
      version: "0.1.0",
      filename: "aihq-scan-0.1.0.tgz",
    });
    const paths = packed.files.map(({ path }) => path);
    expect(paths).toContain("LICENSE");
    expect(paths).toContain("README.md");
    expect(paths).toContain("dist/cli.js");
    expect(paths).toContain("dist/index.js");
  });
});
