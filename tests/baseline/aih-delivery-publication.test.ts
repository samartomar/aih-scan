import { spawnSync } from "node:child_process";
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
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import { createBaselineVetRequestV1 } from "../../src/baseline/batch-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const tool = resolve("tools/prepare-aih-delivery-publication.mjs");
const pin = "a".repeat(40);
it("accepts only exact generated delivery roots and matching canonical requests", () => {
  const root = mkdtempSync(join(tmpdir(), "aih-delivery-publication-"));
  try {
    const material = join(root, "material");
    const sourceRoot = join(material, "aih-scan-material-fixture");
    mkdirSync(sourceRoot, { recursive: true });
    writeFileSync(join(sourceRoot, "delivery.md"), "# Delivered fixture\n");
    const request = createBaselineVetRequestV1({
      protocol: "BaselineVetRequestV1",
      profile: "aih-baseline-v1",
      source: {
        id: "aih",
        owner: "samartomar",
        repository: "ai-harness",
        pinnedCommit: pin,
        treeSha256: hashSourceTreeV1(sourceRoot).treeSha256,
      },
      components: [
        {
          id: "delivery",
          content: "general",
          paths: ["delivery.md"],
          treeSha256: hashComponentTreeV1(sourceRoot, ["delivery.md"]).treeSha256,
          analyzers: ["aih-native", "skillspector", "semgrep"],
        },
      ],
    });
    const manifest = {
      version: "aih-delivery-materialization/v1",
      authority: "none",
      sourceRoot,
      coreCommit: pin,
      sourceTreeSha256: request.source.treeSha256,
      requestSha256s: [request.requestSha256],
    };
    const { requestSha256: _requestDigest, ...requestInput } = request;
    const manifestPath = join(material, "materialization.json");
    const requestPath = join(material, "batch-001.request.json");
    writeFileSync(join(material, "coverage.json"), "{}");
    const reset = () => {
      writeFileSync(manifestPath, canonicalStrictJsonBytesV1(manifest));
      writeFileSync(requestPath, canonicalStrictJsonBytesV1(request));
    };
    const writeChangedRequest = (value: ReturnType<typeof createBaselineVetRequestV1>) => {
      writeFileSync(requestPath, canonicalStrictJsonBytesV1(value));
      writeFileSync(
        manifestPath,
        canonicalStrictJsonBytesV1({ ...manifest, requestSha256s: [value.requestSha256] }),
      );
    };
    const run = (output: string, commit = pin) =>
      spawnSync(process.execPath, [tool, material, commit, output], { encoding: "utf8" });
    reset();
    const accepted = run(join(root, "accepted"));
    expect(accepted.status, accepted.stderr).toBe(0);
    expect(accepted.stdout.trim()).toBe(sourceRoot);
    expect(
      JSON.parse(readFileSync(join(root, "accepted", "batch-001.request.json"), "utf8")),
    ).toEqual(request);
    const mutations = [
      () =>
        writeFileSync(
          manifestPath,
          canonicalStrictJsonBytesV1({ ...manifest, coreCommit: "b".repeat(40) }),
        ),
      () =>
        writeFileSync(manifestPath, canonicalStrictJsonBytesV1({ ...manifest, sourceRoot: root })),
      () =>
        writeFileSync(
          manifestPath,
          canonicalStrictJsonBytesV1({ ...manifest, authority: "install" }),
        ),
      () =>
        writeFileSync(
          manifestPath,
          canonicalStrictJsonBytesV1({ ...manifest, sourceTreeSha256: "b".repeat(64) }),
        ),
      () =>
        writeFileSync(
          manifestPath,
          canonicalStrictJsonBytesV1({ ...manifest, requestSha256s: ["b".repeat(64)] }),
        ),
      () => writeFileSync(manifestPath, canonicalStrictJsonBytesV1({ ...manifest, extra: true })),
      () =>
        writeFileSync(
          requestPath,
          canonicalStrictJsonBytesV1({ ...request, requestSha256: "b".repeat(64) }),
        ),
      () =>
        writeChangedRequest(
          createBaselineVetRequestV1({
            ...requestInput,
            source: { ...request.source, id: "aih-core" },
          }),
        ),
      () =>
        writeChangedRequest(
          createBaselineVetRequestV1({
            ...requestInput,
            components: [{ ...request.components[0], treeSha256: "b".repeat(64) }],
          }),
        ),
    ];
    for (const [index, mutate] of mutations.entries()) {
      reset();
      mutate();
      const output = join(root, `rejected-${index}`);
      expect(run(output).status, String(index)).not.toBe(0);
      expect(existsSync(output), String(index)).toBe(false);
    }
    reset();
    expect(run(join(root, "wrong-pin"), "b".repeat(40)).status).not.toBe(0);
    writeFileSync(join(sourceRoot, "delivery.md"), "mutated");
    expect(run(join(root, "mutated-tree")).status).not.toBe(0);
    writeFileSync(join(sourceRoot, "delivery.md"), "# Delivered fixture\n");
    const alias = join(material, "aih-scan-material-alias");
    symlinkSync(sourceRoot, alias, process.platform === "win32" ? "junction" : "dir");
    writeFileSync(manifestPath, canonicalStrictJsonBytesV1({ ...manifest, sourceRoot: alias }));
    expect(run(join(root, "linked-root")).status).not.toBe(0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

it("routes generated AIH delivery separately with equal Core/source pins and no raw request override", () => {
  const workflow = readFileSync(resolve(".github/workflows/baseline-publication.yml"), "utf8");
  expect(workflow).toContain('test "$CANDIDATE" != "aih"');
  expect(workflow).toContain('aih:samartomar/ai-harness) test "$CORE_REF" = "$SOURCE_REF" ;;');
  expect(workflow).toContain("inputs.candidate != 'aih'");
  expect(workflow).toContain("prepare-aih-delivery-baseline-requests.mjs");
  expect(workflow).toContain("prepare-aih-delivery-publication.mjs");
  expect(workflow).toContain('--source "$scanner_source"');
});
