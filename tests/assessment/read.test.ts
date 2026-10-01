import { describe, expect, test } from "vitest";
import { canonicalBytes } from "../../src/assessment/json.js";
import { readReport } from "../../src/public/read.js";
import { emptyReport } from "./fixtures.js";

describe("portable report reader", () => {
  test("rejects duplicate schema keys before interpreting a report", async () => {
    const result = await readReport(
      new TextEncoder().encode('{"schema":"unknown","schema":"urn:aihq:scan:report:1.0.0"}'),
    );
    expect(result.status).toBe("invalid");
  });
  test("reads a complete account of refused work without claiming authenticity", async () => {
    const result = await readReport(canonicalBytes(emptyReport()));
    expect(result).toMatchObject({
      status: "read",
      authenticity: "unchecked",
      annexBytes: "not-supplied",
      report: { completion: "partial" },
    });
  });
  test.each([
    [
      "unknown report fields",
      (report: ReturnType<typeof emptyReport>) => Object.assign(report, { unexpected: true }),
    ],
    [
      "capture digest substitution",
      (report: ReturnType<typeof emptyReport>) => {
        report.source.capture.captureSha256 = "0".repeat(64);
      },
    ],
    [
      "omitted detector account",
      (report: ReturnType<typeof emptyReport>) => {
        report.results = [];
      },
    ],
    [
      "false complete assessment",
      (report: ReturnType<typeof emptyReport>) => {
        report.completion = "complete";
      },
    ],
    [
      "unresolved detector reported succeeded",
      (report: ReturnType<typeof emptyReport>) => {
        report.results[0]!.outcome = "succeeded";
      },
    ],
    [
      "invalid calendar time",
      (report: ReturnType<typeof emptyReport>) => {
        report.createdAt = "2026-02-30T00:00:00.000Z";
      },
    ],
    [
      "unsafe control number",
      (report: ReturnType<typeof emptyReport>) => {
        report.effectiveLimits.maxSourceBytes = Number.MAX_SAFE_INTEGER + 1;
      },
    ],
  ])("refuses %s", async (_name, modify) => {
    const report = emptyReport();
    modify(report);
    expect((await readReport(new TextEncoder().encode(JSON.stringify(report)))).status).toBe(
      "invalid",
    );
  });
  test("identifies an unsupported detailed report without pretending to read it", async () => {
    expect(
      await readReport(new TextEncoder().encode('{"schema":"urn:aihq:scan:report:2.0.0"}')),
    ).toMatchObject({ status: "unsupported-report", reportSchema: "urn:aihq:scan:report:2.0.0" });
  });
  test("rejects noncanonical supported report bytes", async () => {
    expect(
      (await readReport(new TextEncoder().encode(JSON.stringify(emptyReport(), null, 2)))).status,
    ).toBe("invalid");
  });
});
