import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type BaselineAnalyzerExecutionV1,
  type BaselineAnalyzerV1,
  type BaselineVetRequestV1,
  createBaselineVetRequestV1,
  executeBaselineVetBatchSetV1,
  executeBaselineVetBatchV1,
  verifyBaselineVetReceiptV1,
} from "../../src/baseline/batch-v1.js";
import { BASELINE_BATCH_EXECUTION_PROFILES_V1 } from "../../src/baseline/runtime-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";
import { batchAnalyzerVersion } from "./batch-version-support.js";

/**
 * D49 [Scan: SV1]: baseline-vet executes each selected analyzer once per request set, over
 * one sealed snapshot of the one source, and every request's receipt carries that single
 * execution's annex bytes. Core's consumer needs one whole-tree annex per detector across
 * all batches of a source, which per-request execution of a nondeterministic analyzer
 * (Cisco's endTimeUtc, SkillSpector's findingId) cannot give.
 */

const temporaryDirectories: string[] = [];
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

const SOURCE = {
  id: "ecc",
  owner: "affaan-m",
  repository: "everything-claude-code",
  pinnedCommit: "a".repeat(40),
} as const;

function sourceTree() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-baseline-set-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "rules"), { recursive: true });
  mkdirSync(join(root, "skills", "demo"), { recursive: true });
  mkdirSync(join(root, "skills", "other"), { recursive: true });
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  writeFileSync(join(root, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  writeFileSync(join(root, "skills", "other", "SKILL.md"), "# Other\n", "utf8");
  return root;
}

const component = (root: string, id: string, content: "general" | "skill", path: string) => ({
  id,
  content,
  paths: [path],
  treeSha256: hashComponentTreeV1(root, [path]).treeSha256,
  analyzers:
    content === "skill"
      ? ["aih-native", "skillspector", "semgrep", "cisco"]
      : ["aih-native", "skillspector", "semgrep"],
});

function requestOver(
  root: string,
  components: ReturnType<typeof component>[],
  source: Partial<typeof SOURCE> = {},
): BaselineVetRequestV1 {
  return createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: { ...SOURCE, ...source, treeSha256: hashSourceTreeV1(root).treeSha256 },
    components,
  });
}

/** Three batches of one source: general-only (no Cisco), and two single-Skill batches. */
function threeBatches() {
  const root = sourceTree();
  const requests = [
    requestOver(root, [component(root, "rules-core", "general", "rules")]),
    requestOver(root, [component(root, "skill-demo", "skill", "skills/demo")]),
    requestOver(root, [component(root, "skill-other", "skill", "skills/other")]),
  ];
  return { root, requests };
}

const sarif = (name: string, invocation: Record<string, unknown> = {}) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name } },
        results: [],
        invocations: [{ executionSuccessful: true, ...invocation }],
      },
    ],
  });

/** A deterministic executor; `nondeterministic` stamps every call as Cisco 2.1.0 does. */
function fakeExecution(
  calls: BaselineAnalyzerV1[],
  options: { nondeterministic?: boolean; failing?: BaselineAnalyzerV1 } = {},
): BaselineAnalyzerExecutionV1 {
  return async ({ analyzer }) => {
    calls.push(analyzer);
    if (analyzer === options.failing) throw new Error(`${analyzer} failed`);
    if (analyzer === "aih-native")
      return {
        mediaType: "application/vnd.aih.baseline-native+json",
        bytes: canonicalStrictJsonBytesV1({ protocol: "BaselineNativeObservationV1", files: [] }),
        analyzerVersion: "native.0123456789ab",
        executionProfileId: "in-process-native-v1",
      };
    return {
      mediaType: "application/sarif+json",
      bytes: sarif(
        analyzer,
        options.nondeterministic === true
          ? { endTimeUtc: new Date().toISOString(), properties: { run: randomUUID() } }
          : {},
      ),
      analyzerVersion: batchAnalyzerVersion(analyzer),
      executionProfileId: BASELINE_BATCH_EXECUTION_PROFILES_V1[analyzer],
    };
  };
}

/**
 * The single-request output at 349fcad, before the set entry existed: the receipt digest
 * and every annex digest for the deterministic fake over this fixture. Any change to what
 * one request produces changes these.
 */
const SINGLE_REQUEST_AT_349FCAD = {
  receiptSha256: "15f564561c6cc6b34663899d8516af0da86c946462a9a817fa188fc0bab5d892",
  annexes: {
    "annex/aih-native.json": "4fe8d3ce37161662c1408eeb44522b52df62b1834546451952f1d82485adeccb",
    "annex/skillspector.json": "938cbedf838e9afefdbde7c59314b9bfea14a102d8f3d9ba7854ccc9cd637eaf",
    "annex/semgrep.json": "1fec4d1ef2dcb0a2d1e603be5fd0f0576d03f728c3faece54f4f769bfb0b34e3",
    "annex/cisco.json": "0deeb802886fd3a7e452995f03651127e8be71459facf93480f51bb68e8a35af",
  },
} as const;

function twoComponentRequest() {
  const root = sourceTree();
  const request = requestOver(root, [
    component(root, "rules-core", "general", "rules"),
    component(root, "skill-demo", "skill", "skills/demo"),
  ]);
  return { root, request };
}

const digestsOf = (result: Awaited<ReturnType<typeof executeBaselineVetBatchV1>>) => ({
  receiptSha256: result.receipt.receiptSha256,
  annexes: Object.fromEntries(result.annexArtifacts.map((item) => [item.path, sha(item.bytes)])),
});

describe("baseline-vet request set (D49)", () => {
  it("keeps the single-request output exactly as it was at 349fcad", async () => {
    const { root, request } = twoComponentRequest();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution([]),
    });
    expect(digestsOf(result)).toEqual(SINGLE_REQUEST_AT_349FCAD);
  });

  it("gives N = 1 through the set entry exactly the single-request result", async () => {
    const { root, request } = twoComponentRequest();
    const calls: BaselineAnalyzerV1[] = [];
    const results = await executeBaselineVetBatchSetV1([request], {
      sourceRoot: root,
      execute: fakeExecution(calls),
    });
    expect(results).toHaveLength(1);
    const [only] = results;
    if (only === undefined) throw new Error("expected one result");
    expect(digestsOf(only)).toEqual(SINGLE_REQUEST_AT_349FCAD);
    expect(only.annexArtifacts.map((item) => item.path)).toEqual(
      Object.keys(SINGLE_REQUEST_AT_349FCAD.annexes),
    );
    expect(calls).toEqual(["aih-native", "skillspector", "semgrep", "cisco"]);
    const single = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution([]),
    });
    expect(canonicalStrictJsonBytesV1(only.receipt)).toEqual(
      canonicalStrictJsonBytesV1(single.receipt),
    );
  });

  it("runs each analyzer once for N = 3 and gives every request that execution's bytes", async () => {
    const { root, requests } = threeBatches();
    const calls: BaselineAnalyzerV1[] = [];
    const results = await executeBaselineVetBatchSetV1(requests, {
      sourceRoot: root,
      execute: fakeExecution(calls, { nondeterministic: true }),
    });

    // The union of the three requests' analyzers, once each, in analyzer order.
    expect(calls).toEqual(["aih-native", "skillspector", "semgrep", "cisco"]);
    expect(results).toHaveLength(3);
    results.forEach((result, index) => {
      const request = requests[index] as BaselineVetRequestV1;
      // Input order, each result bound to its own request.
      expect(result.receipt.requestSha256).toBe(request.requestSha256);
      expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
    });

    // Each request holds only its own analyzers: the general batch never selected Cisco.
    const paths = results.map((result) => result.annexArtifacts.map((item) => item.path));
    expect(paths).toEqual([
      ["annex/aih-native.json", "annex/skillspector.json", "annex/semgrep.json"],
      [
        "annex/aih-native.json",
        "annex/skillspector.json",
        "annex/semgrep.json",
        "annex/cisco.json",
      ],
      [
        "annex/aih-native.json",
        "annex/skillspector.json",
        "annex/semgrep.json",
        "annex/cisco.json",
      ],
    ]);
    expect(results[0]?.receipt.observations.map((item) => item.analyzer)).toEqual([
      "aih-native",
      "skillspector",
      "semgrep",
    ]);

    // One execution: every request that selected an analyzer carries byte-identical annexes,
    // completion evidence included, and its components point at that one digest.
    for (const analyzer of ["aih-native", "skillspector", "semgrep", "cisco"] as const) {
      const path = `annex/${analyzer}.json`;
      const holders = results.filter((result) =>
        result.annexArtifacts.some((item) => item.path === path),
      );
      expect(holders.length).toBe(analyzer === "cisco" ? 2 : 3);
      const bytes = holders.map(
        (result) => result.annexArtifacts.find((item) => item.path === path)?.bytes,
      );
      for (const other of bytes)
        expect(Buffer.from(other ?? [])).toEqual(Buffer.from(bytes[0] ?? []));
      if (analyzer !== "aih-native")
        expect(Buffer.from(bytes[0] ?? []).toString("utf8")).toContain("aihScanCompletionV1");
      for (const result of holders) {
        const digest = sha(Buffer.from(bytes[0] ?? []));
        expect(
          result.receipt.observations.find((item) => item.analyzer === analyzer)?.annex,
        ).toMatchObject({ path, sha256: digest });
        for (const item of result.receipt.components)
          expect(item.observations.find((entry) => entry.analyzer === analyzer)?.annexSha256).toBe(
            digest,
          );
      }
    }
  });

  it("returns results in input order, whatever the order", async () => {
    const { root, requests } = threeBatches();
    const reversed = [...requests].reverse();
    const results = await executeBaselineVetBatchSetV1(reversed, {
      sourceRoot: root,
      execute: fakeExecution([]),
    });
    expect(results.map((result) => result.receipt.requestSha256)).toEqual(
      reversed.map((request) => request.requestSha256),
    );
  });

  it.each<[string, (set: ReturnType<typeof threeBatches>) => BaselineVetRequestV1[], RegExp]>([
    ["an empty set", () => [], /request set is empty/],
    [
      "a duplicate request",
      ({ requests }) => [requests[0], requests[1], requests[0]] as BaselineVetRequestV1[],
      /duplicate request digest/,
    ],
    [
      "a request whose source differs",
      ({ root, requests }) => [
        requests[0] as BaselineVetRequestV1,
        requestOver(root, [component(root, "skill-demo", "skill", "skills/demo")], {
          pinnedCommit: "c".repeat(40),
        }),
      ],
      /request set source differs/,
    ],
    [
      "a request whose profile differs",
      ({ requests }) => [
        requests[0] as BaselineVetRequestV1,
        { ...(requests[1] as BaselineVetRequestV1), profile: "aih-baseline-v2" } as never,
      ],
      /validated value|profile/,
    ],
  ])("refuses %s before any analyzer runs", async (_label, build, message) => {
    const set = threeBatches();
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      executeBaselineVetBatchSetV1(build(set), {
        sourceRoot: set.root,
        execute: fakeExecution(calls),
      }),
    ).rejects.toThrow(message);
    expect(calls).toEqual([]);
  });

  it("checks every request against the snapshot before any analyzer runs", async () => {
    const { root, requests } = threeBatches();
    const stale = requestOver(root, [
      { ...component(root, "skill-other", "skill", "skills/other"), treeSha256: "e".repeat(64) },
    ]);
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      executeBaselineVetBatchSetV1([requests[0] as BaselineVetRequestV1, stale], {
        sourceRoot: root,
        execute: fakeExecution(calls),
      }),
    ).rejects.toThrow(/component digest mismatch|component/);
    expect(calls).toEqual([]);
  });

  it("fails the whole set when one analyzer fails, returning no result", async () => {
    const { root, requests } = threeBatches();
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      executeBaselineVetBatchSetV1(requests, {
        sourceRoot: root,
        execute: fakeExecution(calls, { failing: "cisco" }),
      }),
    ).rejects.toThrow(/cisco failed/);
    expect(calls).toEqual(["aih-native", "skillspector", "semgrep", "cisco"]);
  });

  it("re-observes the source for every request after the run", async () => {
    const { root, requests } = threeBatches();
    const execute: BaselineAnalyzerExecutionV1 = async (input) => {
      // Only the last request's component drifts, outside the private snapshot.
      if (input.analyzer === "cisco")
        writeFileSync(join(root, "skills", "other", "SKILL.md"), "# Changed\n", "utf8");
      return fakeExecution([])(input);
    };
    await expect(
      executeBaselineVetBatchSetV1(requests, { sourceRoot: root, execute }),
    ).rejects.toThrow(/source digest mismatch|component/);
  });
});
