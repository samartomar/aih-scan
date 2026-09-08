import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createBaselineVetRequestV1 } from "../../src/baseline/batch-v1.js";

const tool = resolve("tools/prepare-publication-request-set.mjs");
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const source = {
  id: "independent-provider",
  owner: "example",
  repository: "independent",
  pinnedCommit: "a".repeat(40),
  treeSha256: "b".repeat(64),
};
function request(id = "demo", paths = [`skills/${id}`], identity = source) {
  return createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: identity,
    components: [
      {
        id,
        content: "skill",
        paths,
        treeSha256: "c".repeat(64),
        analyzers: ["aih-native", "skillspector", "semgrep", "cisco"],
      },
    ],
  });
}

describe("independent publication request sets", () => {
  it("validates every reviewed provider data file through the independent tool", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-reviewed-sets-"));
    try {
      const directory = resolve(".github/baseline-request-sets");
      for (const id of readdirSync(directory)) {
        for (const name of readdirSync(join(directory, id))) {
          const file = join(directory, id, name);
          const bytes = readFileSync(file, "utf8");
          const set = JSON.parse(bytes);
          const subject = set.requests[0].source;
          expect(name).toBe(`${subject.pinnedCommit}.json`);
          const result = spawnSync(
            process.execPath,
            [
              tool,
              file,
              sha(bytes),
              id,
              `${subject.owner}/${subject.repository}`,
              subject.pinnedCommit,
              join(root, id),
            ],
            { cwd: root, encoding: "utf8" },
          );
          expect(result.status, `${id}: ${result.stderr}`).toBe(0);
          expect(readdirSync(join(root, id))).toHaveLength(set.requests.length);
        }
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
  it("materializes digest-bound canonical requests without Core or provider code", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-request-set-"));
    try {
      const manifest = JSON.stringify({
        protocol: "BaselinePublicationRequestSetV1",
        requests: [request(), request("second")],
      });
      writeFileSync(join(root, "set.json"), manifest);
      const result = spawnSync(
        process.execPath,
        [
          tool,
          join(root, "set.json"),
          sha(manifest),
          source.id,
          `${source.owner}/${source.repository}`,
          source.pinnedCommit,
          join(root, "requests"),
        ],
        { cwd: root, encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(readdirSync(join(root, "requests"))).toEqual([
        "batch-001.request.json",
        "batch-002.request.json",
      ]);
      expect(
        JSON.parse(readFileSync(join(root, "requests", "batch-001.request.json"), "utf8")),
      ).toEqual(request());
      expect(existsSync(join(root, ".core"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects mismatched hashes, sources, malformed requests, duplicates, and unknown fields before output", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-request-reject-"));
    const valid = { protocol: "BaselinePublicationRequestSetV1", requests: [request()] };
    const cases = [
      { value: valid, digest: "d".repeat(64) },
      { value: valid, repository: "attacker/independent" },
      { value: valid, id: "wrong" },
      { value: valid, commit: "e".repeat(40) },
      { value: { ...valid, requests: [] } },
      { value: { ...valid, requests: [request(), request()] } },
      { value: { ...valid, requests: [request(), request("demo", ["skills/other"])] } },
      { value: { ...valid, requests: [request(), request("other", ["skills/demo"])] } },
      { value: { ...valid, requests: [request(), request("other", ["skills/demo/child"])] } },
      {
        value: {
          ...valid,
          requests: [
            request(),
            request("other", ["skills/other"], { ...source, treeSha256: "d".repeat(64) }),
          ],
        },
      },
      { value: { ...valid, requests: Array.from({ length: 1001 }, () => request()) } },
      { value: { ...valid, extra: "unexpected" } },
      { value: { ...valid, requests: [{ ...request(), requestSha256: "d".repeat(64) }] } },
    ];
    try {
      for (const [index, test] of cases.entries()) {
        const manifest = JSON.stringify(test.value);
        writeFileSync(join(root, "set.json"), manifest);
        const output = join(root, `requests-${index}`);
        const result = spawnSync(
          process.execPath,
          [
            tool,
            join(root, "set.json"),
            test.digest ?? sha(manifest),
            test.id ?? source.id,
            test.repository ?? `${source.owner}/${source.repository}`,
            test.commit ?? source.pinnedCommit,
            output,
          ],
          { cwd: root, encoding: "utf8" },
        );
        expect(result.status, String(index)).not.toBe(0);
        expect(existsSync(output), String(index)).toBe(false);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
