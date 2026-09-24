import { describe, expect, it } from "vitest";
import {
  compareFindingKeys,
  coreRanSemgrep,
  normaliseFindingPath,
  scanRefusedForEmpty,
} from "../../tools/installed-semgrep-parity-assertions.mjs";

const completedCore = {
  parsedJson: true,
  executorsLine: "Detector executors: semgrep=core-legacy, other=scan",
  semgrepDetector: { verdict: "pass", detail: "Semgrep static scan completed" },
};

describe("installed Semgrep parity assertions", () => {
  it("accepts Core only when its Semgrep detector completed", () => {
    expect(coreRanSemgrep(completedCore)).toBe(true);
    expect(
      coreRanSemgrep({
        ...completedCore,
        semgrepDetector: { verdict: "fail", detail: "Semgrep static scan failed" },
      }),
    ).toBe(false);
    expect(
      coreRanSemgrep({
        ...completedCore,
        semgrepDetector: { verdict: "pass", detail: "Semgrep static scan started" },
      }),
    ).toBe(false);
    expect(coreRanSemgrep({ ...completedCore, executorsLine: "other=scan" })).toBe(false);
    expect(coreRanSemgrep({ ...completedCore, executorsLine: "semgrep=core-legacy-extra" })).toBe(
      false,
    );
    expect(coreRanSemgrep({ ...completedCore, semgrepDetector: null })).toBe(false);
    expect(coreRanSemgrep({ ...completedCore, parsedJson: false })).toBe(false);
    expect(
      coreRanSemgrep({
        ...completedCore,
        semgrepDetector: { verdict: "skip", detail: "Semgrep static scan completed" },
      }),
    ).toBe(false);
  });

  it("compares finding keys with duplicate multiplicity intact", () => {
    const a = "trust.prompt-injection|skills/a/SKILL.md|4";
    const b = "trust.malicious-code|skills/b/NOTES.md|3";
    expect(compareFindingKeys([a, a, b], [a, b, b])).toEqual({
      onlyCore: [a],
      onlyScan: [b],
      identical: false,
    });
    expect(compareFindingKeys([a, a, b], [b, a, a])).toEqual({
      onlyCore: [],
      onlyScan: [],
      identical: true,
    });
    expect(compareFindingKeys([a], [a], false)).toEqual({
      onlyCore: [],
      onlyScan: [],
      identical: false,
    });
  });

  it("maps only fixture-relative or explicitly rooted finding paths", () => {
    const file = "skills/injected/SKILL.md";
    const files = [file];
    expect(normaliseFindingPath(file, files, "/work/fixtures/positive")).toEqual({
      path: file,
      accepted: true,
    });
    expect(
      normaliseFindingPath(
        "/work/fixtures/positive/skills/injected/SKILL.md",
        files,
        "/work/fixtures/positive",
      ),
    ).toEqual({ path: file, accepted: true });
    expect(
      normaliseFindingPath("/aih/source/skills/injected/SKILL.md", files, "/aih/source"),
    ).toEqual({ path: file, accepted: true });
    expect(
      normaliseFindingPath("file:///aih/source/skills/injected/SKILL.md", files, "/aih/source"),
    ).toEqual({ path: file, accepted: true });
    expect(normaliseFindingPath("/other/skills/injected/SKILL.md", files, "/aih/source")).toEqual({
      path: "/other/skills/injected/SKILL.md",
      accepted: false,
    });
    expect(
      normaliseFindingPath("/aih/source-other/skills/injected/SKILL.md", files, "/aih/source"),
    ).toEqual({ path: "/aih/source-other/skills/injected/SKILL.md", accepted: false });
    expect(
      normaliseFindingPath("/aih/source/../skills/injected/SKILL.md", files, "/aih/source"),
    ).toEqual({ path: "/aih/source/../skills/injected/SKILL.md", accepted: false });
    expect(
      normaliseFindingPath("file://foreign/skills/injected/SKILL.md", files, "/aih/source"),
    ).toEqual({ path: "file://foreign/skills/injected/SKILL.md", accepted: false });
    expect(
      normaliseFindingPath(
        "file:///aih/source/../source/skills/injected/SKILL.md",
        files,
        "/aih/source",
      ),
    ).toEqual({ path: "file:///aih/source/../source/skills/injected/SKILL.md", accepted: false });
  });

  it("accepts only a successful child with the expected typed empty-tree refusal", () => {
    const scan = {
      exit: 0,
      childError: null,
      summary: {
        outcome: "refused",
        reason: "subject-requirement-unmet",
        detail: "Diagnostic wording is not a typed contract",
        executionProfileId: null,
      },
    };
    expect(scanRefusedForEmpty(scan)).toBe(true);
    expect(
      scanRefusedForEmpty({ ...scan, summary: { ...scan.summary, reason: "different" } }),
    ).toBe(false);
    expect(scanRefusedForEmpty({ ...scan, summary: { ...scan.summary, reason: "" } })).toBe(false);
    expect(
      scanRefusedForEmpty({
        ...scan,
        summary: { ...scan.summary, executionProfileId: "unexpected" },
      }),
    ).toBe(false);
    expect(scanRefusedForEmpty({ ...scan, exit: 1 })).toBe(false);
    expect(scanRefusedForEmpty({ ...scan, childError: "child failed" })).toBe(false);
  });
});
