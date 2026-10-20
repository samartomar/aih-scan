import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { canonicalBytes, observationIdFor } from "../../src/assessment/json.js";
import type { ContentDescriptor, ReportBody } from "../../src/assessment/types.js";
import { runScan } from "../../src/public/host.js";
import {
  maxContentDescriptors,
  readArtifact,
  readContentCoverageBatch,
  readReport,
  readContentCoverage as singletonCoverage,
} from "../../src/public/read.js";

const examples = (
  JSON.parse(readFileSync("schemas/examples/1.0.0.json", "utf8")) as {
    examples: { format: string; valid: unknown }[];
  }
).examples;
const example = (name: string) =>
  structuredClone(examples.find((entry) => entry.format === `urn:aihq:scan:${name}:1.0.0`)!.valid);
const exampleReport = () => example("report") as ReportBody;
const skill: ContentDescriptor = {
  path: "SKILL.md",
  sha256: "f8185998ec464c5c9d5fe35c2157e0ad2593c5d5224797b24060a016df079d77",
  byteLength: 138,
};
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

// The same public contract assertions also exercise a batch row expanded through
// its public observation table; no report interpretation is duplicated here.
describe.each(["singleton", "batch"])("%s coverage contract", (reader) => {
  const readContentCoverage: typeof singletonCoverage = async (input) => {
    if (reader === "singleton") return singletonCoverage(input);
    if (input === null) {
      const invalid = await readContentCoverageBatch(input);
      if (invalid.status !== "invalid") throw new Error("Expected malformed envelope refusal");
      return invalid;
    }
    const { descriptors, ...envelope } = input;
    const batch = await readContentCoverageBatch({ ...envelope, queries: [{ descriptors }] });
    if (batch.status === "invalid") return batch;
    const row = batch.results[0]!;
    if (row.status !== "matched") return row;
    const { observationIndexes, ...rest } = row;
    return { ...rest, observations: observationIndexes.map((at) => batch.observations[at]!) };
  };

  describe("content coverage read", () => {
    test("matches exact descriptors and returns the covering observation", async () => {
      const read = await readReport(canonicalBytes(exampleReport()));
      const result = await readContentCoverage({ read, descriptors: [skill] });
      expect(result).toEqual({
        status: "matched",
        scanId: read.status === "read" ? read.scanId : "",
        authenticity: "unchecked",
        excluded: {
          "detector-not-succeeded": 0,
          "input-missing-descriptor": 0,
          "coverage-incomplete": 0,
        },
        detectorsWithoutCoverage: [],
        observations: [
          {
            observationId:
              "observation:sha256:440926cb56d7d8664fa50814170e036336511e3ca4dab82175f939454835768e",
            origin: "fresh",
            detector: {
              detectorId: "detector.aih-native",
              detectorVersion: "native.014fbd614a5a",
              adapterSha256: "6a8c0096ff8d0a7664d9e478ce352bbf1702c68908678fa06ccaf88c15135da8",
              platform: {
                os: "win32",
                architecture: "x64",
                relevantFactsSha256:
                  "7402e245a08eef12312587aa9060a08868adebfcabd08ee24e9e67405e3647be",
              },
            },
            input: {
              rulesSha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
              configurationSha256:
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
              profileId: "in-process-native-v1",
              profileSha256: "dafe959975fb633398ba013a669d118b7de692b147cc4257cb40ec13b1029b2e",
              scopeKind: "source-tree",
              targetPaths: ["SKILL.md"],
            },
            coverage: { coveredPaths: ["SKILL.md"] },
            detectorCoverage: {
              coveredPaths: ["SKILL.md"],
              excludedPaths: [],
              uncoveredPaths: [],
              complete: true,
            },
            findings: [],
            annexes: [exampleReport().annexes[0]],
          },
        ],
      });
    });

    test("reads coverage from an artifact read without an annex byte claim", async () => {
      const read = await readArtifact(canonicalBytes(example("artifact")));
      expect(read.status).toBe("read");
      expect(await readContentCoverage({ read, descriptors: [skill] })).toMatchObject({
        status: "matched",
        observations: [{ detector: { detectorId: "detector.aih-native" } }],
      });
      expect(await readContentCoverage({ read, descriptors: [skill] })).not.toHaveProperty(
        "annexBytes",
      );
    });

    test.each([
      ["digest", { ...skill, sha256: "0".repeat(64) }],
      ["byte length", { ...skill, byteLength: 139 }],
      ["path", { ...skill, path: "OTHER.md" }],
    ])("reports a %s mismatch without covering observations", async (_name, descriptor) => {
      const read = await readReport(canonicalBytes(exampleReport()));
      expect(await readContentCoverage({ read, descriptors: [descriptor] })).toEqual(
        expect.objectContaining({
          status: "mismatched",
          authenticity: "unchecked",
          unmatchedPaths: [descriptor.path],
        }),
      );
    });

    test("names an unsupported report as unavailable", async () => {
      const read = await readReport(
        new TextEncoder().encode('{"schema":"urn:aihq:scan:report:2.0.0"}'),
      );
      expect(await readContentCoverage({ read, descriptors: [skill] })).toMatchObject({
        status: "unavailable",
        reason: "unsupported-report",
        scanId: expect.stringMatching(/^scan:sha256:[0-9a-f]{64}$/),
      });
    });

    test("treats an invalid read as unavailable", async () => {
      const read = await readReport(new TextEncoder().encode("{}"));
      expect(read.status).toBe("invalid");
      expect(await readContentCoverage({ read, descriptors: [skill] })).toMatchObject({
        status: "unavailable",
        reason: "invalid-read",
      });
    });

    test.each([
      [
        "altered observation input",
        (read: Record<string, unknown>) => {
          (read.report as ReportBody).results[0]!.observations[0]!.body.input.detectorVersion = "x";
        },
      ],
      [
        "removed annex descriptor",
        (read: Record<string, unknown>) => {
          (read.report as ReportBody).annexes = [];
        },
      ],
      [
        "substituted Scan ID",
        (read: Record<string, unknown>) => {
          read.scanId = `scan:sha256:${"0".repeat(64)}`;
        },
      ],
      [
        "claimed authenticity",
        (read: Record<string, unknown>) => {
          read.authenticity = "authenticated";
        },
      ],
      [
        "extra field",
        (read: Record<string, unknown>) => {
          read.trusted = true;
        },
      ],
      [
        "accessor report",
        (read: Record<string, unknown>) => {
          const report = read.report;
          Object.defineProperty(read, "report", { enumerable: true, get: () => report });
        },
      ],
      [
        "unknown status",
        (read: Record<string, unknown>) => {
          read.status = "approved";
        },
      ],
    ])("fails closed on a read result with %s", async (_name, modify) => {
      const read = (await readReport(canonicalBytes(exampleReport()))) as unknown as Record<
        string,
        unknown
      >;
      modify(read);
      expect(
        await readContentCoverage({ read, descriptors: [skill] } as unknown as Parameters<
          typeof readContentCoverage
        >[0]),
      ).toMatchObject({ status: "unavailable", reason: "invalid-read" });
    });

    test.each([
      ["no descriptors", []],
      [
        "too many descriptors",
        Array.from({ length: maxContentDescriptors + 1 }, (_, i) => ({ ...skill, path: `f${i}` })),
      ],
      ["uppercase digest", [{ ...skill, sha256: skill.sha256.toUpperCase() }]],
      ["short digest", [{ ...skill, sha256: "abc" }]],
      ["traversal path", [{ ...skill, path: "../SKILL.md" }]],
      ["absolute path", [{ ...skill, path: "/SKILL.md" }]],
      ["oversized path", [{ ...skill, path: "a".repeat(4097) }]],
      ["negative length", [{ ...skill, byteLength: -1 }]],
      ["fractional length", [{ ...skill, byteLength: 1.5 }]],
      ["extra field", [{ ...skill, kind: "file" }]],
      ["duplicate path", [skill, { ...skill }]],
      ["non-array", skill],
    ])("refuses %s as invalid input", async (_name, descriptors) => {
      const read = await readReport(canonicalBytes(exampleReport()));
      const result = await readContentCoverage({ read, descriptors } as unknown as Parameters<
        typeof readContentCoverage
      >[0]);
      expect(result.status).toBe("invalid");
    });

    test("refuses unsupported input fields and accessor descriptors", async () => {
      const read = await readReport(canonicalBytes(exampleReport()));
      const accessor = {};
      Object.defineProperty(accessor, "path", { enumerable: true, get: () => "SKILL.md" });
      for (const input of [
        { read, descriptors: [skill], extra: true },
        { read, descriptors: [accessor] },
        null,
      ])
        expect(
          (await readContentCoverage(input as unknown as Parameters<typeof readContentCoverage>[0]))
            .status,
        ).toBe("invalid");
    });

    test("excludes and counts partial coverage from a real assessment", async () => {
      const root = mkdtempSync(join(tmpdir(), "aih-content-coverage-"));
      roots.push(root);
      writeFileSync(join(root, "A.md"), "# A\n");
      writeFileSync(join(root, "B.md"), "# B\n");
      const run = await runScan({
        schema: "urn:aihq:scan:request:1.0.0",
        source: { kind: "local", path: root },
        selection: { paths: ["A.md"], excludedPaths: [] },
        detectors: [
          { detectorId: "detector.aih-native", configuration: {} },
          { detectorId: "detector.unavailable", configuration: {} },
        ],
      });
      expect(run.status).toBe("assessment");
      if (run.status !== "assessment") return;
      const read = await readReport(canonicalBytes(run.report));
      const entries = run.report.source.capture.entries;
      const descriptor = (path: string): ContentDescriptor => {
        const entry = entries.find((item) => item.path === path)!;
        if (!("sha256" in entry)) throw new Error("fixture file missing");
        return { path, sha256: entry.sha256, byteLength: entry.byteLength };
      };
      // The whole-tree native unit binds B.md as input but covers only selected A.md.
      expect(
        await readContentCoverage({ read, descriptors: [descriptor("A.md"), descriptor("B.md")] }),
      ).toMatchObject({
        status: "matched",
        observations: [],
        excluded: { "coverage-incomplete": 1 },
        detectorsWithoutCoverage: ["detector.aih-native", "detector.unavailable"],
      });
      expect(await readContentCoverage({ read, descriptors: [descriptor("A.md")] })).toMatchObject({
        status: "matched",
        observations: [{ detector: { detectorId: "detector.aih-native" } }],
        detectorsWithoutCoverage: ["detector.unavailable"],
      });
    });
  });

  // Hand-assembled reports that the supported reader accepts, so each branch is
  // proven reachable through a valid read rather than an unvalidated object.
  async function readAssembled(report: ReportBody) {
    for (const result of report.results)
      for (const observation of result.observations)
        observation.observationId = await observationIdFor(observation.body);
    const read = await readReport(canonicalBytes(report));
    expect(read.status).toBe("read");
    return read;
  }

  describe("content coverage over valid assembled reports", () => {
    test("counts observations kept by a failed detector", async () => {
      const report = exampleReport();
      report.results[0]!.outcome = "failed";
      report.results[0]!.diagnostics = [
        { code: "detector-failed", detail: "The fixture detector failed after observing." },
      ];
      report.completion = "partial";
      const read = await readAssembled(report);
      expect(await readContentCoverage({ read, descriptors: [skill] })).toMatchObject({
        status: "matched",
        observations: [],
        excluded: { "detector-not-succeeded": 1 },
        detectorsWithoutCoverage: ["detector.aih-native"],
      });
    });

    test("returns findings with their supporting evidence annex", async () => {
      const report = exampleReport();
      const observation = report.results[0]!.observations[0]!;
      const annexId = report.annexes[0]!.id;
      observation.body.findings = [
        {
          rawOccurrenceFingerprint: `raw-occurrence-v1:${"f".repeat(64)}`,
          multiplicity: 1,
          rule: { state: "present", value: { nativeRuleId: "fixture.rule" } },
          severity: { state: "unavailable", reason: "not-declared", detail: "fixture" },
          message: { state: "present", value: "fixture finding" },
          location: {
            state: "present",
            value: { path: "SKILL.md", fileSha256: skill.sha256, startLine: 1 },
          },
          supportingEvidence: { state: "present", value: { annexId, ordinal: 0 } },
        },
      ];
      const read = await readAssembled(report);
      expect(await readContentCoverage({ read, descriptors: [skill] })).toMatchObject({
        status: "matched",
        observations: [
          {
            findings: [
              {
                rule: { value: { nativeRuleId: "fixture.rule" } },
                supportingEvidence: { value: { annexId } },
              },
            ],
            annexes: [report.annexes[0]],
          },
        ],
      });
    });

    test("counts a selected-closure observation whose input omits a descriptor", async () => {
      const root = mkdtempSync(join(tmpdir(), "aih-content-coverage-"));
      roots.push(root);
      writeFileSync(join(root, "A.md"), "# A\n");
      writeFileSync(join(root, "B.md"), "# B\n");
      const run = await runScan({
        schema: "urn:aihq:scan:request:1.0.0",
        source: { kind: "local", path: root },
        selection: { paths: ["A.md"], excludedPaths: [] },
        detectors: [{ detectorId: "detector.aih-binding-gate", configuration: {} }],
      });
      expect(run.status).toBe("assessment");
      if (run.status !== "assessment") return;
      const observation = run.report.results[0]!.observations[0]!;
      expect(observation.body.input.scopeKind).toBe("selected-closure");
      const read = await readReport(canonicalBytes(run.report));
      const descriptors = run.report.source.capture.entries.flatMap((entry) =>
        "sha256" in entry
          ? [{ path: entry.path, sha256: entry.sha256, byteLength: entry.byteLength }]
          : [],
      );
      expect(descriptors.map((descriptor) => descriptor.path)).toEqual(["A.md", "B.md"]);
      expect(await readContentCoverage({ read, descriptors })).toMatchObject({
        status: "matched",
        observations: [],
        excluded: { "input-missing-descriptor": 1 },
        detectorsWithoutCoverage: ["detector.aih-binding-gate"],
      });
    });
  });
});
