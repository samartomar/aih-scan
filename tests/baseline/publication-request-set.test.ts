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
          expect(name).toMatch(
            new RegExp(`^${subject.pinnedCommit}(?:-[a-z0-9][a-z0-9-]{0,63})?\\.json$`),
          );
          const output = join(root, `${id}-${name.slice(0, -5)}`);
          const result = spawnSync(
            process.execPath,
            [
              tool,
              file,
              sha(bytes),
              id,
              `${subject.owner}/${subject.repository}`,
              subject.pinnedCommit,
              output,
            ],
            { cwd: root, encoding: "utf8" },
          );
          expect(result.status, `${id}: ${result.stderr}`).toBe(0);
          expect(readdirSync(output)).toHaveLength(set.requests.length);
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

/**
 * SI1c (decision D41): the data-only route's explicit overlap mode, Core T1's vocabulary.
 * `disjoint` (the default) refuses any path shared or nested across components, as before;
 * `compiler-catalog` allows that across components (ECC modules and baselines share files) and
 * still refuses an overlap inside one component. Every other check is unchanged.
 */
describe("independent publication request set overlap modes (SI1c, D41)", () => {
  const run = (
    root: string,
    value: unknown,
    output: string,
    mode: readonly string[] = [],
    identity = source,
  ) => {
    const manifest = JSON.stringify(value);
    writeFileSync(join(root, "set.json"), manifest);
    return spawnSync(
      process.execPath,
      [
        tool,
        join(root, "set.json"),
        sha(manifest),
        identity.id,
        `${identity.owner}/${identity.repository}`,
        identity.pinnedCommit,
        join(root, output),
        ...mode,
      ],
      { cwd: root, encoding: "utf8" },
    );
  };
  const set = (...requests: unknown[]) => ({
    protocol: "BaselinePublicationRequestSetV1",
    requests,
  });
  const crossShared = set(request("a", ["AGENTS.md", "skills/a"]), request("b", ["AGENTS.md"]));
  const crossNested = set(request("a", ["skills/a"]), request("b", ["skills/a/child"]));

  it.each([
    ["the same path in two components", crossShared],
    ["a path nested in another component's", crossNested],
  ])("disjoint refuses %s, by default and when named", (_label, value) => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-disjoint-"));
    try {
      for (const [index, mode] of [[], ["--overlap", "disjoint"]].entries()) {
        const result = run(root, value, `out-${index}`, mode);
        expect(result.status).not.toBe(0);
        expect(result.stderr).toMatch(
          /publication request set rejected: overlapping component paths/,
        );
        expect(existsSync(join(root, `out-${index}`))).toBe(false);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    ["the same path in two components", crossShared],
    ["a path nested in another component's", crossNested],
  ])("compiler-catalog accepts %s", (_label, value) => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-catalog-"));
    try {
      const result = run(root, value, "out", ["--overlap", "compiler-catalog"]);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("Verified independent publication request set: 2 requests");
      expect(readdirSync(join(root, "out"))).toEqual([
        "batch-001.request.json",
        "batch-002.request.json",
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("compiler-catalog refuses an overlap inside one component", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-within-"));
    try {
      const result = run(root, set(request("a", ["skills/a", "skills/a/child"])), "out", [
        "--overlap",
        "compiler-catalog",
      ]);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/overlapping paths within component a/);
      expect(existsSync(join(root, "out"))).toBe(false);
      // The same path twice in one component never gets this far: the request parser refuses it.
      const single = request("a", ["skills/a"]);
      const doubled = {
        ...single,
        components: [{ ...single.components[0], paths: ["skills/a", "skills/a"] }],
      };
      const twice = run(root, set(doubled), "out2", ["--overlap", "compiler-catalog"]);
      expect(twice.status).not.toBe(0);
      expect(twice.stderr).toMatch(/duplicate component path: skills\/a/);
      expect(existsSync(join(root, "out2"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    [["--overlap", "Compiler-Catalog"]],
    [["--overlap", ""]],
    [["--overlap"]],
    [["--mode", "compiler-catalog"]],
    [["compiler-catalog"]],
    [["--overlap", "compiler-catalog", "extra"]],
  ])("refuses the overlap argument %j as arguments", (mode) => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-args-"));
    try {
      const result = run(root, set(request()), "out", mode);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/publication request set rejected: arguments/);
      expect(existsSync(join(root, "out"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps the six-argument call, and its output, unchanged", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-six-"));
    try {
      const plain = run(root, set(request(), request("second")), "plain");
      const named = run(root, set(request(), request("second")), "named", [
        "--overlap",
        "disjoint",
      ]);
      expect(plain.status, plain.stderr).toBe(0);
      expect(named.status, named.stderr).toBe(0);
      expect(plain.stdout).toBe("Verified independent publication request set: 2 requests\n");
      for (const name of ["batch-001.request.json", "batch-002.request.json"])
        expect(readFileSync(join(root, "named", name))).toEqual(
          readFileSync(join(root, "plain", name)),
        );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps every other rejection before output under compiler-catalog", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-reject-"));
    const valid = { protocol: "BaselinePublicationRequestSetV1", requests: [request()] };
    const cases = [
      { value: valid, digest: "d".repeat(64) },
      { value: valid, repository: "attacker/independent" },
      { value: valid, id: "wrong" },
      { value: valid, commit: "e".repeat(40) },
      { value: { ...valid, requests: [] } },
      { value: { ...valid, requests: [request(), request()] } },
      { value: { ...valid, requests: [request(), request("demo", ["skills/other"])] } },
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
            "--overlap",
            "compiler-catalog",
          ],
          { cwd: root, encoding: "utf8" },
        );
        expect(result.status, String(index)).not.toBe(0);
        expect(result.stderr, String(index)).not.toMatch(/rejected: arguments/);
        expect(existsSync(output), String(index)).toBe(false);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  // RQ1: Core T1's ECC "core-delivery" set (411 components from the Catalog BaselineCatalog
  // definition, authored with --definition-overlap compiler-catalog), byte for byte.
  it("refuses the real ECC core-delivery set as disjoint and verifies it as compiler-catalog", () => {
    const file = resolve("tests/fixtures/publication-request-sets/ecc-5064474d-core-delivery.json");
    const bytes = readFileSync(file);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "15e69443dce8d919d7cdfd874982557b3be2d72b1d065d46093c97342bd8c292",
    );
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-ecc-"));
    const call = (output: string, mode: readonly string[]) =>
      spawnSync(
        process.execPath,
        [
          tool,
          file,
          createHash("sha256").update(bytes).digest("hex"),
          "ecc",
          "affaan-m/ECC",
          "5064474d4d762dc9640234a41617cccb79185cec",
          join(root, output),
          ...mode,
        ],
        { cwd: root, encoding: "utf8" },
      );
    try {
      const disjoint = call("disjoint", []);
      expect(disjoint.status).not.toBe(0);
      expect(disjoint.stderr).toMatch(/overlapping component paths/);
      expect(existsSync(join(root, "disjoint"))).toBe(false);
      const catalog = call("catalog", ["--overlap", "compiler-catalog"]);
      expect(catalog.status, catalog.stderr).toBe(0);
      expect(catalog.stdout).toBe("Verified independent publication request set: 5 requests\n");
      expect(readdirSync(join(root, "catalog"))).toHaveLength(5);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
