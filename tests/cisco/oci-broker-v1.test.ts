import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { executeCiscoOciBrokerV1 } from "../../src/cisco/oci-broker-v1.js";
import { loadCiscoOciLayoutV1 } from "../../src/cisco/oci-layout-v1.js";

const roots: string[] = [];
const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
const ociIndexMediaType = "application/vnd.oci.image.index.v1+json";
const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const ociConfigMediaType = "application/vnd.oci.image.config.v1+json";
const ociLayerMediaType = "application/vnd.oci.image.layer.v1.tar";

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function writeBlob(
  root: string,
  bytes: Buffer,
): { digest: string; mediaType?: string; size: number } {
  const digest = `sha256:${sha256(bytes)}`;
  const path = join(root, "blobs", "sha256", digest.slice(7));
  mkdirSync(join(root, "blobs", "sha256"), { recursive: true });
  writeFileSync(path, bytes);
  return { digest, size: bytes.length };
}

function layoutFixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-oci-broker-layout-"));
  roots.push(root);
  writeFileSync(join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  const layerBytes = Buffer.from("candidate layer\n");
  const layer = { ...writeBlob(root, layerBytes), mediaType: ociLayerMediaType };
  const configBytes = Buffer.from(
    JSON.stringify({
      architecture: "amd64",
      os: "linux",
      rootfs: { type: "layers", diff_ids: [layer.digest] },
    }),
  );
  const config = { ...writeBlob(root, configBytes), mediaType: ociConfigMediaType };
  const manifestBytes = Buffer.from(
    JSON.stringify({ schemaVersion: 2, mediaType: ociManifestMediaType, config, layers: [layer] }),
  );
  const manifest = { ...writeBlob(root, manifestBytes), mediaType: ociManifestMediaType };
  writeFileSync(
    join(root, "index.json"),
    JSON.stringify({
      schemaVersion: 2,
      mediaType: ociIndexMediaType,
      manifests: [
        {
          ...manifest,
          platform: { architecture: "amd64", os: "linux" },
          annotations: { "org.opencontainers.image.ref.name": "candidate" },
        },
      ],
    }),
  );
  return loadCiscoOciLayoutV1({ layoutRoot: root });
}

function sourceFixture(name = "aih-scan-oci-broker-source-") {
  const root = mkdtempSync(join(tmpdir(), name));
  roots.push(root);
  writeFileSync(
    join(root, "SKILL.md"),
    "---\nname: candidate\ndescription: neutral\nlicense: MIT\n---\n",
  );
  return root;
}

const validSarif = JSON.stringify({
  $schema:
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "skill-scanner",
          version: "1.0.0",
          informationUri: "https://github.com/cisco-ai-defense/skill-scanner",
          rules: [],
        },
      },
      invocations: [{ executionSuccessful: true }],
      results: [],
    },
  ],
});

function outputDirectory(argv: readonly string[]): string {
  const mount = argv.find(
    (item) => item.startsWith("type=bind,src=") && item.includes(",dst=/output,"),
  );
  if (mount === undefined) throw new Error("broker did not provide a bounded output mount");
  const source = mount.slice("type=bind,src=".length, mount.indexOf(",dst=/output,"));
  if (!source) throw new Error("broker output mount has no source");
  return source;
}

function sourceDirectory(argv: readonly string[]): string {
  const mount = argv.find(
    (item) => item.startsWith("type=bind,src=") && item.includes(",dst=/source,"),
  );
  if (mount === undefined) throw new Error("broker did not provide a read-only source mount");
  const source = mount.slice("type=bind,src=".length, mount.indexOf(",dst=/source,"));
  if (!source) throw new Error("broker source mount has no source");
  return source;
}

function runner(options: { readonly mutateSource?: boolean; readonly response?: unknown } = {}) {
  const calls: Array<{ argv: readonly string[]; options: Record<string, unknown> | undefined }> =
    [];
  return {
    calls,
    run: async (argv: readonly string[], runOptions?: Record<string, unknown>) => {
      calls.push({ argv, options: runOptions });
      if (argv[1] === "image" && argv[2] === "inspect")
        return { code: 0, stdout: argv.at(-1), stderr: "" };
      const output = outputDirectory(argv);
      if (options.mutateSource) writeFileSync(join(sourceDirectory(argv), "SKILL.md"), "drift\n");
      writeFileSync(join(output, "result.sarif"), validSarif);
      return options.response ?? { code: 0, stdout: "", stderr: "" };
    },
  };
}

function input(
  layout = layoutFixture(),
  sourceRoot = sourceFixture(),
  overrides: Record<string, unknown> = {},
) {
  const fake = runner();
  return {
    value: {
      protocol: "CiscoOciBrokerV1",
      layout,
      sourceRoot,
      selectedClosurePaths: ["SKILL.md"],
      host: { os: "linux", architecture: "amd64" },
      runner: fake.run,
      ...overrides,
    },
    fake,
  };
}

function recursivelyFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) recursivelyFrozen(child, seen);
}

describe("Cisco OCI broker V1", () => {
  it("executes only the loaded config image ID through an injected, restricted Docker client", async () => {
    const { value, fake } = input();
    const result = await executeCiscoOciBrokerV1(value);
    const inspect = fake.calls.find(
      (call) => call.argv[1] === "image" && call.argv[2] === "inspect",
    );
    const run = fake.calls.find((call) => call.argv[1] === "run");

    expect(inspect?.argv).toEqual([
      "docker",
      "image",
      "inspect",
      "--format",
      "{{.Id}}",
      value.layout.configDigestSha256,
    ]);
    expect(run?.argv).toEqual(
      expect.arrayContaining([
        "docker",
        "run",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        value.layout.configDigestSha256,
        "skill-scanner",
        "scan",
        "/source",
        "--format",
        "sarif",
        "--output-sarif",
        "/output/result.sarif",
      ]),
    );
    expect(run?.argv).not.toContain(value.layout.manifestDigestSha256);
    expect(run?.options).toMatchObject({
      env: { PATH: "/usr/bin:/bin" },
      maxStderrBytes: 64 * 1024,
      maxStdoutBytes: 64 * 1024,
      timeoutMs: 120_000,
    });
    expect(Object.keys((run?.options?.env ?? {}) as object)).toEqual(["PATH"]);
    expect(result).toMatchObject({
      protocol: "CiscoOciBrokerV1",
      observationScope: "candidate",
      validationState: "cryptographically-unverified",
      logicalReference: value.layout.logicalReference,
    });
    recursivelyFrozen(result);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(
      /"(?:qualified|trusted|signer|signature|policy|verdict|acceptance|acknowledgement|public)"\s*:/i,
    );
  });

  it("rejects unbranded layout values, host/image mismatch, unsafe mount input, failed execution, and source drift", async () => {
    const layout = layoutFixture();
    const sourceRoot = sourceFixture();
    const stale = input(layout, sourceRoot, { layout: { ...layout } });
    const wrongHost = input(layout, sourceRoot, { host: { os: "darwin", architecture: "amd64" } });
    const injectedPath = input(layout, `${sourceRoot},dst=/host\n--privileged`);
    const failed = input(layout, sourceRoot, {
      runner: async () => ({ code: 1, stdout: "", stderr: "failed" }),
    });
    const driftRunner = runner({ mutateSource: true });
    const drift = input(layout, sourceRoot, { runner: driftRunner.run });

    for (const item of [
      stale.value,
      wrongHost.value,
      injectedPath.value,
      failed.value,
      drift.value,
    ])
      await expect(executeCiscoOciBrokerV1(item)).rejects.toThrow();
  });

  it("rejects NUL and comma/newline mount injection before the runner and cleans bounded outputs on every path", async () => {
    const { value, fake } = input();
    const hostile = { ...value, sourceRoot: `${String(value.sourceRoot)}\0,ro=false` };
    await expect(executeCiscoOciBrokerV1(hostile)).rejects.toThrow();
    expect(fake.calls).toHaveLength(0);

    const failing = input();
    let outputRoot = "";
    failing.fake.run = async (argv) => {
      if (argv[1] === "image")
        return { code: 0, stdout: failing.value.layout.configDigestSha256, stderr: "" };
      outputRoot = outputDirectory(argv);
      writeFileSync(join(outputRoot, "result.sarif"), validSarif);
      return { code: 0, stdout: "", stderr: "", truncated: true };
    };
    await expect(executeCiscoOciBrokerV1(failing.value)).rejects.toThrow();
    expect(outputRoot).not.toBe("");
    expect(existsSync(outputRoot)).toBe(false);
  });
});
