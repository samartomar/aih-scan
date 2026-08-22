import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const bridge = resolve(root, "tools", "create-cisco-oci-capture-request.mjs");
const workflowPath = resolve(root, ".github", "workflows", "cisco-oci-equivalence.yml");
const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const roots: string[] = [];
afterEach(() => {
  for (const path of roots.splice(0)) rmSync(path, { force: true, recursive: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "aih-scan-oci-bridge-"));
  roots.push(directory);
  const sourceRoot = join(directory, "source");
  const dockerfile = join(directory, "Dockerfile");
  const pyproject = join(directory, "pyproject.toml");
  const lock = join(directory, "uv.lock");
  const layout = join(directory, "candidate-layout-v1.json");
  const imageId = join(directory, "docker-config-id.txt");
  writeFileSync(join(directory, "source-SKILL.md"), "fixture source\n");
  writeFileSync(dockerfile, "FROM scratch\n");
  writeFileSync(pyproject, "[project]\nname = 'fixture'\n");
  writeFileSync(lock, "version = 1\n");
  const manifest = "a".repeat(64);
  const config = "b".repeat(64);
  writeFileSync(
    layout,
    JSON.stringify({
      protocol: "CiscoOciLayoutV1",
      manifestDigestSha256: `sha256:${manifest}`,
      configDigestSha256: `sha256:${config}`,
      logicalReference: `local.invalid/aih-scan/cisco@sha256:${manifest}`,
      manifestPlatform: { architecture: "amd64", os: "linux" },
      manifestDescriptor: {
        annotations: { "org.opencontainers.image.ref.name": "cisco" },
        digest: `sha256:${manifest}`,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "amd64", os: "linux" },
        size: 1,
      },
    }),
  );
  writeFileSync(imageId, `sha256:${config}\n`);
  return { directory, sourceRoot, dockerfile, pyproject, lock, layout, imageId };
}

describe("Cisco OCI capture evidence bridge", () => {
  it("creates deterministic digest-bound-unverified annexes and an exact capture request from observed inputs", () => {
    const value = fixture();
    const run = (output: string) =>
      spawnSync(
        process.execPath,
        [
          bridge,
          "--layout",
          value.layout,
          "--source-root",
          value.directory,
          "--selected-path",
          "source-SKILL.md",
          "--dockerfile",
          value.dockerfile,
          "--pyproject",
          value.pyproject,
          "--lock",
          value.lock,
          "--image-id",
          value.imageId,
          "--repository",
          "owner/scanner",
          "--workflow",
          ".github/workflows/cisco-oci-equivalence.yml",
          "--source-ref",
          "refs/heads/main",
          "--commit",
          "c".repeat(40),
          "--run-id",
          "123",
          "--run-attempt",
          "2",
          "--environment",
          "github-actions",
          "--output",
          output,
        ],
        { encoding: "utf8" },
      );
    const first = join(value.directory, "first");
    const second = join(value.directory, "second");
    const firstRun = run(first);
    const secondRun = run(second);
    expect(firstRun.status, firstRun.stderr).toBe(0);
    expect(secondRun.status, secondRun.stderr).toBe(0);
    for (const file of ["annex.sbom.json", "annex.provenance.json", "ci-context.json"])
      expect(readFileSync(join(first, file))).toEqual(readFileSync(join(second, file)));
    const request = JSON.parse(readFileSync(join(first, "capture-request.json"), "utf8"));
    const sbom = JSON.parse(readFileSync(join(first, "annex.sbom.json"), "utf8"));
    const provenance = JSON.parse(readFileSync(join(first, "annex.provenance.json"), "utf8"));
    expect(request.sourceRoot).toBe(value.directory);
    expect(request.selectedClosurePaths).toEqual(["source-SKILL.md"]);
    expect(request.runtime.ociImage).toEqual({
      reference: `local.invalid/aih-scan/cisco@sha256:${"a".repeat(64)}`,
      sha256: "a".repeat(64),
    });
    expect(request.runtime.sbom.sha256).toBe(sha256(readFileSync(join(first, "annex.sbom.json"))));
    expect(request.runtime.provenance.sha256).toBe(
      sha256(readFileSync(join(first, "annex.provenance.json"))),
    );
    expect(sbom.evidenceState).toBe("digest-bound-unverified");
    expect(sbom.packages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "Dockerfile",
          sha256: sha256(readFileSync(value.dockerfile)),
        }),
        expect.objectContaining({ name: "uv.lock", sha256: sha256(readFileSync(value.lock)) }),
      ]),
    );
    expect(provenance.predicate.evidenceState).toBe("digest-bound-unverified");
    expect(provenance.predicate.buildDefinition.resolvedDependencies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "Dockerfile",
          digest: { sha256: sha256(readFileSync(value.dockerfile)) },
        }),
        expect.objectContaining({
          name: "oci-layout-v1",
          digest: { sha256: sha256(readFileSync(value.layout)) },
        }),
      ]),
    );
    expect(provenance.predicate.runDetails.metadata.ci).toEqual({
      commit: "c".repeat(40),
      environment: "github-actions",
      repository: "owner/scanner",
      runAttempt: 2,
      runId: "123",
      sourceRef: "refs/heads/main",
      workflow: ".github/workflows/cisco-oci-equivalence.yml",
    });
  });

  it("rejects a Docker image config identity that was not verified against the layout", () => {
    const value = fixture();
    writeFileSync(value.imageId, `sha256:${"d".repeat(64)}\n`);
    const result = spawnSync(
      process.execPath,
      [
        bridge,
        "--layout",
        value.layout,
        "--source-root",
        value.directory,
        "--selected-path",
        "source-SKILL.md",
        "--dockerfile",
        value.dockerfile,
        "--pyproject",
        value.pyproject,
        "--lock",
        value.lock,
        "--image-id",
        value.imageId,
        "--repository",
        "owner/scanner",
        "--workflow",
        ".github/workflows/cisco-oci-equivalence.yml",
        "--source-ref",
        "refs/heads/main",
        "--commit",
        "c".repeat(40),
        "--run-id",
        "123",
        "--run-attempt",
        "2",
        "--environment",
        "github-actions",
        "--output",
        join(value.directory, "output"),
      ],
      { encoding: "utf8" },
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Docker image config identity/i);
  });

  it("passes the existing OCI observation through independent capture, test-ephemeral sign, and verify jobs", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const job = (name: string) =>
      new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z]+:|(?![\\s\\S]))`, "m").exec(
        workflow,
      )?.[0] ?? "";
    const capture = job("capture");
    const sign = job("sign");
    const verify = job("verify");
    expect(workflow.match(/docker buildx build/g)).toHaveLength(2);
    expect(capture).toContain(
      "candidate_digest: $" + "{{ steps.capture.outputs.candidate_digest }}",
    );
    expect(capture).toContain("create-cisco-oci-capture-request.mjs");
    expect(capture).toContain("node dist/cli.js capture");
    expect(capture).toContain("digest-bound-unverified");
    expect(capture).toContain("GITHUB_HEAD_REF");
    expect(capture).toContain("event.pull_request.head.sha");
    expect(sign).toContain("needs: capture");
    expect(sign).toContain(
      'test "$candidate_digest" = "$' + '{{ needs.capture.outputs.candidate_digest }}"',
    );
    expect(sign).toContain("openssl genpkey -algorithm ED25519");
    expect(sign).toContain('class: "test-ephemeral"');
    expect(sign).toContain("node dist/cli.js sign");
    expect(sign).toContain('rm -f "$private_key"');
    expect(sign).not.toMatch(/docker|capture --request/i);
    expect(verify).toContain("needs: sign");
    expect(verify).toContain("node dist/cli.js verify");
    expect(verify).not.toMatch(/docker|capture --request|sign --bundle/i);
    expect(workflow).toMatch(/^permissions:\n {2}contents: read\s*$/m);
    expect(workflow.match(/timeout-minutes:/g)).toHaveLength(3);
  });
});
