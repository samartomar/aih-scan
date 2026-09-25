import { describe, expect, it } from "vitest";
import {
  assertSarifCompletedV1,
  SarifCompletionErrorV1,
} from "../../src/detectors/sarif-completion-v1.js";

// S2f (review of S2e): every notification on an invocation is validated as SARIF 2.1.0's
// notification object, never treated as harmless: `level`, when present, is one of
// none/note/warning/error, and `message`, when present, is a message object whose `text` or
// `id` is a string. Malformed is `output`; an error-level notification stays `execution`.
const log = (invocation: Record<string, unknown>) => ({
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "analyzer" } },
      results: [],
      invocations: [{ executionSuccessful: true, ...invocation }],
    },
  ],
});

const stageOf = (document: unknown): string | undefined => {
  try {
    assertSarifCompletedV1(document);
    return undefined;
  } catch (error) {
    if (!(error instanceof SarifCompletionErrorV1)) throw error;
    return `${error.stage}: ${error.message}`;
  }
};

// S2f sweep: a result's locations are location objects, never skipped by a later rewrite.
describe("SARIF completion: result locations", () => {
  const withLocations = (locations: unknown) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "analyzer" } },
        results: [{ ruleId: "R", message: { text: "m" }, locations }],
        invocations: [{ executionSuccessful: true }],
      },
    ],
  });

  it("fails a location that is not a location object at output", () => {
    for (const locations of [
      [null],
      [42],
      ["SKILL.md"],
      [[]],
      [{ physicalLocation: "SKILL.md" }],
      [{ physicalLocation: { artifactLocation: "SKILL.md" } }],
      [{ physicalLocation: { artifactLocation: { uri: 42 } } }],
      [{ physicalLocation: { artifactLocation: { uri: "a.md" } } }, null],
    ])
      expect(stageOf(withLocations(locations))).toBe("output: run 0 result 0 is malformed");
  });

  it("keeps physical, logical-only and URI-less locations", () => {
    expect(
      stageOf(
        withLocations([
          { physicalLocation: { artifactLocation: { uri: "a.md" }, region: { startLine: 1 } } },
          { logicalLocations: [{ name: "f" }] },
          { physicalLocation: { artifactLocation: { index: 0 } } },
          {},
        ]),
      ),
    ).toBeUndefined();
  });
});

describe.each([
  "toolExecutionNotifications",
  "toolConfigurationNotifications",
])("SARIF completion: %s", (key) => {
  const notified = (...entries: unknown[]) => stageOf(log({ [key]: entries }));

  it("fails a notification whose level is malformed at output (reviewer reproduction)", () => {
    expect(notified({ level: 42 })).toBe("output: run 0 reports a malformed notification");
    for (const level of [null, "", "fatal", "ERROR", ["error"], { level: "error" }])
      expect(notified({ level, message: { text: "m" } })).toBe(
        "output: run 0 reports a malformed notification",
      );
  });

  it("fails a notification whose message is malformed at output", () => {
    for (const message of [
      null,
      "text",
      42,
      [],
      {},
      { text: 42 },
      { id: 7 },
      { text: "m", id: 7 },
      { id: "x", text: null },
      { text: "m", markdown: 1 },
      { text: "m", arguments: "a" },
      { text: "m", arguments: [1] },
    ])
      expect(notified({ level: "warning", message })).toBe(
        "output: run 0 reports a malformed notification",
      );
  });

  it("fails a notification that is not an object at output", () => {
    for (const entry of [null, 42, "error", []])
      expect(notified(entry)).toBe("output: run 0 reports a malformed notification");
    expect(stageOf(log({ [key]: { level: "note" } }))).toBe(
      "output: run 0 notifications are malformed",
    );
  });

  it("fails a malformed notification at output even beside an error-level one", () => {
    expect(notified({ level: "error", message: { text: "boom" } }, { level: 42 })).toBe(
      "output: run 0 reports a malformed notification",
    );
  });

  it("fails an error-level notification at execution", () => {
    expect(notified({ level: "error", message: { text: "boom" } })).toBe(
      "execution: run 0 reports an error notification",
    );
    expect(notified({ level: "error", message: { id: "E1" } })).toBe(
      "execution: run 0 reports an error notification",
    );
  });

  it("keeps well-formed none, note and warning notifications, and absent fields", () => {
    expect(
      notified(
        { level: "none", message: { text: "n" } },
        { level: "note", message: { id: "N1", arguments: ["a"] } },
        { level: "warning", message: { text: "w", markdown: "**w**" } },
        { message: { text: "no level" } },
        { level: "note" },
        {},
      ),
    ).toBeUndefined();
  });
});
