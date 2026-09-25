import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createBaselineVetRequestV1 } from "../../src/baseline/batch-v1.js";
import { parseStrictJsonObjectV1 } from "../../src/contract/strict-json-v1.js";

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

/**
 * SI1d: which reviewed set verifies as compiler-catalog is an explicit, reviewed record,
 * `overlap-modes.json` beside the sets: a closed object from a canonical set path
 * (`<candidate>/<commit>[-<name>].json`, relative to the directory) to "compiler-catalog".
 * Every set it does not list is verified as disjoint. A mode is never found by trying modes.
 */
const OVERLAP_MODES = "overlap-modes.json";
const SET_PATH = /^[a-z0-9][a-z0-9:._-]{0,127}\/[0-9a-f]{40}(?:-[a-z0-9][a-z0-9-]{0,63})?\.json$/u;

function readOverlapModes(directory: string): ReadonlySet<string> {
  const manifest = parseStrictJsonObjectV1(
    readFileSync(join(directory, OVERLAP_MODES), "utf8"),
    OVERLAP_MODES,
  );
  const listed = new Set<string>();
  for (const [key, mode] of Object.entries(manifest)) {
    if (key === OVERLAP_MODES) throw new Error(`${OVERLAP_MODES} lists itself`);
    if (!SET_PATH.test(key))
      throw new Error(`${OVERLAP_MODES}: not a canonical set path: ${JSON.stringify(key)}`);
    if (mode !== "compiler-catalog")
      throw new Error(`${OVERLAP_MODES}: the mode of ${key} is not "compiler-catalog"`);
    if (!lstatSync(join(directory, ...key.split("/")), { throwIfNoEntry: false })?.isFile())
      throw new Error(`${OVERLAP_MODES}: stale entry: ${key}`);
    listed.add(key);
  }
  return listed;
}

/** Verifies every set under `directory` with the tool, each in its recorded mode. */
function verifyRequestSets(directory: string, outputRoot: string) {
  const listed = readOverlapModes(directory);
  const verified: { key: string; mode: "disjoint" | "compiler-catalog" }[] = [];
  for (const id of readdirSync(directory).sort()) {
    if (id === OVERLAP_MODES) continue;
    if (!lstatSync(join(directory, id)).isDirectory())
      throw new Error(`not a candidate directory: ${id}`);
    for (const name of readdirSync(join(directory, id)).sort()) {
      const key = `${id}/${name}`;
      const mode = listed.has(key) ? "compiler-catalog" : "disjoint";
      const file = join(directory, id, name);
      const bytes = readFileSync(file, "utf8");
      const set = JSON.parse(bytes);
      const subject = set.requests[0].source;
      expect(name).toMatch(
        new RegExp(`^${subject.pinnedCommit}(?:-[a-z0-9][a-z0-9-]{0,63})?\\.json$`),
      );
      const output = join(outputRoot, `${id}-${name.slice(0, -5)}`);
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
          ...(mode === "compiler-catalog" ? ["--overlap", "compiler-catalog"] : []),
        ],
        { cwd: outputRoot, encoding: "utf8" },
      );
      if (result.status !== 0) throw new Error(`${key} (${mode}): ${result.stderr}`);
      expect(readdirSync(output)).toHaveLength(set.requests.length);
      verified.push({ key, mode });
    }
  }
  return verified;
}

describe("independent publication request sets", () => {
  it("validates every reviewed provider data file through the independent tool, in its recorded mode", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-reviewed-sets-"));
    try {
      const directory = resolve(".github/baseline-request-sets");
      const listed = readOverlapModes(directory);
      const verified = verifyRequestSets(directory, root);
      expect(verified.length).toBeGreaterThan(0);
      for (const key of listed) expect(verified).toContainEqual({ key, mode: "compiler-catalog" });
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

describe("reviewed overlap-mode record (SI1d)", () => {
  const commit = source.pinnedCommit;
  const listedKey = `independent-provider/${commit}.json`;
  const plainKey = `independent-provider/${commit}-plain.json`;
  const overlapping = {
    protocol: "BaselinePublicationRequestSetV1",
    requests: [request("a", ["AGENTS.md", "skills/a"]), request("b", ["AGENTS.md"])],
  };
  const plain = {
    protocol: "BaselinePublicationRequestSetV1",
    requests: [request("c", ["skills/c"])],
  };
  const withSets = (manifest: string, check: (directory: string, output: string) => void) => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-record-"));
    try {
      const directory = join(root, "sets");
      for (const [key, value] of [
        [listedKey, overlapping],
        [plainKey, plain],
      ] as const) {
        mkdirSync(dirname(join(directory, key)), { recursive: true });
        writeFileSync(join(directory, key), JSON.stringify(value));
      }
      writeFileSync(join(directory, OVERLAP_MODES), manifest);
      const output = join(root, "out");
      mkdirSync(output);
      check(directory, output);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
  const listing = (key: string, mode: unknown = "compiler-catalog") =>
    JSON.stringify({ [key]: mode });

  it("verifies a listed overlapping set as compiler-catalog and every other set as disjoint", () =>
    withSets(listing(listedKey), (directory, output) =>
      expect(verifyRequestSets(directory, output)).toEqual([
        { key: plainKey, mode: "disjoint" },
        { key: listedKey, mode: "compiler-catalog" },
      ]),
    ));

  it("refuses the same overlapping set when it is not listed", () =>
    withSets("{}", (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(
        /\(disjoint\):[\s\S]*publication request set rejected: overlapping component paths/u,
      ),
    ));

  it("refuses a stale entry", () =>
    withSets(listing(`independent-provider/${commit}-gone.json`), (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(/stale entry/),
    ));

  it.each([
    ["disjoint"],
    ["Compiler-Catalog"],
    [""],
    [true],
    [null],
    [["compiler-catalog"]],
    [{ mode: "compiler-catalog" }],
  ])("refuses the mode %j", (mode) =>
    withSets(listing(listedKey, mode), (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(/is not "compiler-catalog"/),
    ));

  it.each([
    [`./independent-provider/${commit}.json`],
    [`/independent-provider/${commit}.json`],
    [`independent-provider//${commit}.json`],
    [`independent-provider\\${commit}.json`],
    [`independent-provider/../independent-provider/${commit}.json`],
    [`independent-provider/sub/${commit}.json`],
    [`${commit}.json`],
    [`independent-provider/${commit}.JSON`],
    [`independent-provider/${commit}`],
    [`independent-provider/${commit}.json/`],
    [`Independent-provider/${commit}.json`],
    [`independent-provider/${commit.toUpperCase()}.json`],
    [` independent-provider/${commit}.json`],
  ])("refuses the non-canonical key %j", (key) =>
    withSets(listing(key), (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(/not a canonical set path/),
    ));

  it("refuses a manifest that lists itself", () =>
    withSets(listing(OVERLAP_MODES), (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(/lists itself/),
    ));

  it.each([
    ["[]"],
    ['"compiler-catalog"'],
    ["null"],
    [""],
    [`{"${listedKey}":"compiler-catalog","${listedKey}":"compiler-catalog"}`],
  ])("refuses the manifest %j through the strict reader", (manifest) =>
    withSets(manifest, (directory, output) =>
      expect(() => verifyRequestSets(directory, output)).toThrow(TypeError),
    ));

  // Phase B of RQ1, rehearsed on copies: the real ECC core-delivery set beside the reviewed ECC
  // set, verified only when the record lists it.
  it("verifies the real ECC core-delivery set only when the record lists it", () => {
    const commit = "5064474d4d762dc9640234a41617cccb79185cec";
    const key = `ecc/${commit}-core-delivery.json`;
    for (const [manifest, listed] of [
      [JSON.stringify({ [key]: "compiler-catalog" }), true],
      ["{}", false],
    ] as const) {
      const root = mkdtempSync(join(tmpdir(), "scanner-overlap-record-ecc-"));
      try {
        const directory = join(root, "sets");
        mkdirSync(join(directory, "ecc"), { recursive: true });
        writeFileSync(
          join(directory, "ecc", `${commit}.json`),
          readFileSync(resolve(`.github/baseline-request-sets/ecc/${commit}.json`)),
        );
        writeFileSync(
          join(directory, key),
          readFileSync(
            resolve("tests/fixtures/publication-request-sets/ecc-5064474d-core-delivery.json"),
          ),
        );
        writeFileSync(join(directory, OVERLAP_MODES), manifest);
        const output = join(root, "out");
        mkdirSync(output);
        if (listed)
          expect(verifyRequestSets(directory, output)).toEqual([
            { key, mode: "compiler-catalog" },
            { key: `ecc/${commit}.json`, mode: "disjoint" },
          ]);
        else
          expect(() => verifyRequestSets(directory, output)).toThrow(
            /core-delivery\.json \(disjoint\):[\s\S]*overlapping component paths/u,
          );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
  });

  it("refuses a missing manifest, so no set is verified by default", () => {
    const root = mkdtempSync(join(tmpdir(), "scanner-overlap-record-missing-"));
    try {
      mkdirSync(join(root, "sets", "independent-provider"), { recursive: true });
      writeFileSync(join(root, "sets", plainKey), JSON.stringify(plain));
      expect(() => verifyRequestSets(join(root, "sets"), root)).toThrow(/ENOENT/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
