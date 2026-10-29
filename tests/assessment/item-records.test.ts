import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";
import { runScan } from "../../src/public/host.js";
import * as api from "../../src/public/read.js";
import { replayItemSummaries } from "../support/item-summary-replay.mjs";

const json = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const sort = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(sort)
    : v && typeof v === "object"
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, sort((v as Record<string, unknown>)[k])]),
        )
      : v;
const bytes = (v: unknown) => Buffer.from(JSON.stringify(sort(v)));
const hash = (v: Uint8Array) => createHash("sha256").update(v).digest("hex");
const records = json("../../schemas/item-record/1.0.0.fixtures.json");
const summaries = json("../../schemas/item-summary/1.0.0.fixtures.json");
const profile = records.severityProfile;
const golden = (name: string) => records.cases.find((c: { name: string }) => c.name === name);
const read = async (report: unknown) => {
  const result = await api.readReport(bytes(report));
  expect(result.status).toBe("read");
  return result;
};
const rebind = (report: any) => {
  report.source.capture.captureSha256 = hash(
    bytes({
      domain: "aih.scan.capture.v2",
      profile: report.source.capture.profile,
      entries: report.source.capture.entries,
    }),
  );
  for (const result of report.results) {
    for (const observation of result.observations)
      observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from("aih.scan.observation.v2\0"), bytes(observation.body)]))}`;
    result.observations.sort((a: any, b: any) => (a.observationId < b.observationId ? -1 : 1));
  }
  return report;
};
/** A real scan of an MCP item's recipe file and licence only, without the behaviour file that carries its payload. */
async function recipeOnlyReport(source: { item: api.ItemDescriptor }) {
  const sourceItem = records.sourceItems.find(
    (s: { itemId: string }) => s.itemId === source.item.itemId,
  );
  const root = mkdtempSync(join(tmpdir(), "aih-recipe-only-"));
  try {
    for (const m of sourceItem.materials.filter((m: { role: string }) => m.role === "content")) {
      mkdirSync(dirname(join(root, m.capturePath)), { recursive: true });
      writeFileSync(join(root, m.capturePath), Buffer.from(m.bytesBase64, "base64"));
    }
    const run = await runScan({
      schema: "urn:aihq:scan:request:2.0.0",
      source: { kind: "local", path: root },
      selection: { paths: "all", excludedPaths: [] },
      detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
    } as never);
    if (run.status !== "assessment") throw new Error(JSON.stringify(run));
    return run.report;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const derive = async (report: unknown, item: unknown) => {
  const batch = await api.recordItems({
    artifact: await read(report),
    items: [item as api.ItemDescriptor],
    severityProfile: profile,
  });
  expect(batch.status).toBe("complete");
  return (batch as { results: api.ItemRecordResult[] }).results[0]!;
};

describe("item identity", () => {
  test("reproduces Core's independent contract vectors", async () => {
    const vectors = json("../fixtures/item-identity-1.7.0-vectors.json");
    for (const entry of vectors.cases) {
      const identity = await api.itemIdentity(entry.input);
      expect([identity.contentSha256, identity.behaviourSha256], entry.name).toEqual([
        entry.expect.contentSha256,
        entry.expect.behaviourSha256,
      ]);
    }
  });
  test("refuses an item whose hashes or behaviour file do not recompute", async () => {
    const { item, report } = golden("extensions.hook.git-guard");
    const payload = await derive(report, {
      ...item,
      payload: { ...item.payload, matcher: "Bash" },
    });
    expect(payload).toMatchObject({
      coverage: "invalid",
      diagnostics: [{ code: "behaviour-mismatch" }],
    });
    const content = await derive(report, { ...item, contentSha256: "0".repeat(64) });
    expect(content).toMatchObject({
      coverage: "invalid",
      diagnostics: [{ code: "item-identity-mismatch" }],
    });
    expect(await derive(report, { ...item, toolId: "claude" })).toMatchObject({
      coverage: "invalid",
    });
  });
});

describe("item records", () => {
  test("golden records are what recordItems derives, in the contract shape", async () => {
    for (const entry of records.cases.filter(
      (c: { expectation: string }) => c.expectation === "accept",
    )) {
      const record = await derive(entry.report, entry.item);
      expect(record).toEqual(entry.value);
      expect(Object.keys(record).sort()).toEqual([
        "authenticity",
        "completion",
        "coverage",
        "createdAt",
        "detectors",
        "evidenceKey",
        "materials",
        "scanId",
        "severityProfile",
        "subject",
      ]);
      const payload = (record as api.ItemRecord).materials.at(-1)!;
      const canonical = bytes(entry.item.payload);
      expect(payload).toEqual({
        materialId: "#payload",
        relPath: "#payload",
        sha256: hash(canonical),
        byteLength: canonical.length,
        executable: false,
        captured: true,
      });
      expect(
        await api.verifyItemRecord(entry.value, await read(entry.report), entry.item, profile),
      ).toBe("same");
    }
    for (const entry of records.cases.filter(
      (c: { expectation: string }) => c.expectation === "refuse",
    ))
      expect(api.readItemRecord(entry.value)).toMatchObject({
        status: "refused",
        diagnostics: [{ code: entry.code }],
      });
  });
  test("a relabelled record or another behaviour is not-covered", async () => {
    const docs = golden("ecc.mcp.cloudflare-docs"),
      clickhouse = golden("ecc.mcp.clickhouse");
    // Same files, other payload: the subject's behaviourSha256 differs.
    expect(
      await api.verifyItemRecord(docs.value, await read(docs.report), clickhouse.item, profile),
    ).toBe("not-covered");
    const relabelled = { ...structuredClone(docs.value), subject: clickhouse.value.subject };
    expect(
      await api.verifyItemRecord(relabelled, await read(docs.report), clickhouse.item, profile),
    ).toBe("not-covered");
    const otherBytes = {
      ...structuredClone(golden("extensions.hook.git-guard").value),
      subject: golden("extensions.matt.grill-me").value.subject,
    };
    expect(
      await api.verifyItemRecord(
        otherBytes,
        await read(golden("extensions.hook.git-guard").report),
        golden("extensions.matt.grill-me").item,
        profile,
      ),
    ).toBe("not-covered");
  });
  test("a recipe-only capture cannot cover an MCP server's payload", async () => {
    const { item } = golden("ecc.mcp.clickhouse");
    const recipeOnly = await recipeOnlyReport(golden("ecc.mcp.clickhouse"));
    const record = (await derive(recipeOnly, item)) as api.ItemRecord;
    expect(record.coverage).toBe("mismatched");
    expect(record.materials.find((m) => m.materialId === "#payload")!.captured).toBe(false);
    expect(record.detectors[0]!.exclusions).toContain("material-missing: behaviour, #payload");
  });
  test("executable bits: recorded exactly, and an unknown capture cannot be matched", async () => {
    const { item, report } = golden("extensions.matt.grill-me");
    const withModes = (mode: boolean | "unknown", behaviourOnly = false) => {
      const copy = structuredClone(report);
      const pick = (e: any) =>
        "sha256" in e && (!behaviourOnly || e.path.endsWith("aih-behaviour.json"));
      for (const e of copy.source.capture.entries) if (pick(e)) e.executable = mode;
      for (const r of copy.results)
        for (const o of r.observations)
          for (const e of o.body.input.entries) if (pick(e)) e.executable = mode;
      return rebind(copy);
    };
    // Content materials declare "unknown"; the behaviour file declares false.
    const contentTrue = structuredClone(report);
    for (const e of contentTrue.source.capture.entries)
      if ("sha256" in e && !e.path.endsWith("aih-behaviour.json")) e.executable = true;
    for (const r of contentTrue.results)
      for (const o of r.observations)
        for (const e of o.body.input.entries)
          if ("sha256" in e && !e.path.endsWith("aih-behaviour.json")) e.executable = true;
    const recorded = (await derive(rebind(contentTrue), item)) as api.ItemRecord;
    expect(recorded.coverage).toBe("matched");
    expect(recorded.materials.find((m) => m.relPath === "SKILL.md")!.executable).toBe(true);
    const differs = (await derive(withModes(true, true), item)) as api.ItemRecord;
    expect(differs.coverage).toBe("mismatched");
    expect(differs.detectors[0]!.exclusions).toEqual(["executable-differs: behaviour, #payload"]);
    const unknown = (await derive(withModes("unknown"), item)) as api.ItemRecord;
    expect(unknown.coverage).toBe("unavailable");
    expect(unknown.detectors[0]!.coverage).toBe("unavailable");
  });
  test("every stored field is compared", async () => {
    const { item, report, value } = golden("extensions.matt.grill-me");
    const assessment = await read(report);
    const mutations: [(string | number)[], unknown][] = [];
    const walk = (v: unknown, path: (string | number)[] = []) => {
      if (Array.isArray(v)) {
        mutations.push([path, []]);
        for (const [i, x] of v.entries()) walk(x, [...path, i]);
      } else if (v && typeof v === "object")
        for (const [k, x] of Object.entries(v)) walk(x, [...path, k]);
      else
        mutations.push([
          path,
          typeof v === "boolean"
            ? !v
            : typeof v === "number"
              ? v + 1
              : /^[0-9a-f]{64}$/.test(String(v))
                ? (v === "0".repeat(64) ? "1" : "0").repeat(64)
                : `${v}-changed`,
        ]);
    };
    walk(value);
    for (const [path, replacement] of mutations) {
      const changed = structuredClone(value);
      let parent = changed;
      for (const key of path.slice(0, -1)) parent = parent[key];
      if (JSON.stringify(parent[path.at(-1)!]) === JSON.stringify(replacement)) continue;
      parent[path.at(-1)!] = replacement;
      const identity =
        path[0] === "subject" ||
        (path[0] === "materials" &&
          path.length === 3 &&
          ["materialId", "sha256", "byteLength"].includes(path[2] as string));
      expect(await api.verifyItemRecord(changed, assessment, item, profile), path.join(".")).toBe(
        identity ? "not-covered" : "differs",
      );
    }
  });
  test("verification snapshots its inputs at invocation", async () => {
    const { item, report, value } = golden("extensions.matt.grill-me");
    const assessment = await read(report);
    const mutableItem = structuredClone(item),
      mutableRecord = structuredClone(value),
      mutableAssessment: any = structuredClone(assessment);
    const pending = api.verifyItemRecord(
      mutableRecord,
      mutableAssessment,
      mutableItem,
      structuredClone(profile),
    );
    mutableItem.itemId = "changed";
    mutableRecord.evidenceKey = "0".repeat(64);
    mutableAssessment.report.createdAt = "2099-01-01T00:00:00.000Z";
    expect(await pending).toBe("same");
    let reads = 0;
    const hostile = { ...value };
    Object.defineProperty(hostile, "subject", {
      enumerable: true,
      get() {
        reads++;
        return value.subject;
      },
    });
    expect(await api.verifyItemRecord(hostile, assessment, item, profile)).toBe("differs");
    expect(reads).toBe(0);
  });
});

describe("precise refusals", () => {
  test("record schema, unknown fields and report schemas", async () => {
    const { value } = golden("extensions.matt.grill-me");
    expect(api.readItemRecord({ ...value, schema: "urn:aihq:scan:item-record:1.0.0" }).status).toBe(
      "read",
    );
    expect(api.readItemRecord({ ...value, schema: "urn:aihq:scan:item-record:2.0.0" })).toEqual({
      status: "refused",
      diagnostics: [
        {
          code: "SCHEMA_UNSUPPORTED",
          path: "$.schema",
          encountered: "urn:aihq:scan:item-record:2.0.0",
          supported: ["urn:aihq:scan:item-record:1.0.0"],
          detail: "Unsupported item record schema at $.schema",
        },
      ],
    });
    const extra = structuredClone(value);
    extra.detectors[1].profileId = "x";
    expect(api.readItemRecord(extra)).toMatchObject({
      status: "refused",
      diagnostics: [{ code: "unknown-field", path: "$.detectors[1].profileId" }],
    });
    const unsupported = await api.readReport(bytes({ schema: "urn:aihq:scan:report:9.0.0" }));
    expect(unsupported).toMatchObject({
      status: "unsupported-report",
      diagnostics: [
        { code: "SCHEMA_UNSUPPORTED", path: "$.schema", encountered: "urn:aihq:scan:report:9.0.0" },
      ],
    });
  });
});

describe("item summaries", () => {
  const withArtifacts = async (entry: any) => {
    const input = structuredClone(entry.input);
    input.records = await Promise.all(
      input.records.map(async ({ report, ...c }: any) => ({
        ...c,
        artifact: await api.readReport(bytes(report)),
      })),
    );
    return input;
  };
  test("every decision-table row and ranking variant", async () => {
    const replay = await replayItemSummaries(api, summaries);
    expect(replay.rows).toEqual(Array.from({ length: 13 }, (_, i) => i + 1));
  });
  test("why is the contract's closed list and the shape is exact", async () => {
    const whys = new Set<string>();
    for (const entry of [...summaries.cases.filter((c: any) => c.input), ...summaries.variants]) {
      const result = await api.summariseItem(await withArtifacts(entry));
      if (result.status !== "summarised") throw new Error(entry.name);
      expect(Object.keys(result.summary).sort()).toEqual(
        [
          "findings",
          "scannedAt",
          "state",
          "suppressed",
          ...(result.summary.why ? ["why"] : []),
        ].sort(),
      );
      if (result.summary.why) whys.add(result.summary.why);
    }
    expect([...whys].sort()).toEqual([
      "detector-missing",
      "future-dated",
      "not-authenticated",
      "offline",
      "older-than-policy",
      "profile-not-allowed",
      "revoked",
      "unchecked",
    ]);
  });
  test("diagnostics name the precise refusal of each candidate", async () => {
    const entry = summaries.cases.find((c: any) => c.name === "record-schema-unsupported");
    const result = await api.summariseItem(await withArtifacts(entry));
    expect(result).toMatchObject({
      status: "summarised",
      diagnostics: [{ index: 0, code: "SCHEMA_UNSUPPORTED", path: "$.schema" }],
    });
  });
  test("a policy whose severity profile is not supplied is refused", async () => {
    const entry = summaries.cases.find((c: any) => c.name === "verified");
    const input = await withArtifacts(entry);
    input.severityProfiles = input.severityProfiles.slice(1);
    expect(await api.summariseItem(input)).toMatchObject({
      status: "invalid",
      diagnostics: [{ code: "severity-profile-mismatch" }],
    });
    expect(
      await api.pickRecord({
        records: [],
        item: input.item,
        policy: input.policy,
        severityProfiles: [profile],
      }),
    ).toMatchObject({ status: "none", state: "not-scanned" });
  });
  test("inputs are snapshotted at invocation", async () => {
    const entry = summaries.cases.find((c: any) => c.name === "verified");
    const input = await withArtifacts(entry);
    const pending = api.summariseItem(input);
    input.records[0].authentication.status = "revoked";
    input.records[0].artifact.report.createdAt = "2099-01-01T00:00:00.000Z";
    input.item.materials[0].sha256 = "0".repeat(64);
    expect(await pending).toMatchObject({ status: "summarised", summary: { state: "verified" } });
  });
});
