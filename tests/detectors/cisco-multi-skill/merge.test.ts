import { describe, expect, it } from "vitest";
import {
  CISCO_SARIF_FALLBACK_URI_V1,
  prefixSafeCiscoUriV1,
} from "../../../src/detectors/cisco-multi-skill/merge-v1.js";

// C2a §3.4 with the complete §1.4 rule applied to the FINAL prefixed URI: a
// result URI Core's boundary would reject fails the whole detector, so every
// value that is not a source-relative POSIX path must become `cisco.sarif`.
describe("prefixSafeCiscoUriV1", () => {
  it.each([
    ["skills/a", "SKILL.md", "skills/a/SKILL.md"],
    ["skills/a", "scripts/run.sh", "skills/a/scripts/run.sh"],
    ["", "SKILL.md", "SKILL.md"],
    ["skills/a", "file://SKILL.md", "skills/a/SKILL.md"],
    ["skills/a", "scripts\\run.sh", "skills/a/scripts/run.sh"],
  ])("prefixes a safe URI (prefix %j, uri %j)", (prefix, uri, expected) => {
    expect(prefixSafeCiscoUriV1(prefix, uri)).toBe(expected);
  });

  it.each([
    ["skills/a", "./SKILL.md"],
    ["", "./SKILL.md"],
    ["skills/a", "a//b"],
    ["skills/a", "a/./b"],
    ["skills/a", "a/"],
    ["skills/a", "file:x"],
    ["skills/a", "https:x"],
    ["skills/a", "https://example.invalid/x"],
    ["skills/a", ".."],
    ["skills/a", "../x"],
    ["", ".."],
    ["", "."],
    ["skills/a", "."],
    ["skills/a", "/etc/passwd"],
    ["skills/a", "file:///etc/passwd"],
    ["skills/a", "C:/x"],
    ["skills/a", ""],
  ])("falls back for an unsafe final URI (prefix %j, uri %j)", (prefix, uri) => {
    expect(prefixSafeCiscoUriV1(prefix, uri)).toBe(CISCO_SARIF_FALLBACK_URI_V1);
  });

  it("falls back when the prefix itself would make the final URI unsafe", () => {
    expect(prefixSafeCiscoUriV1("skills/./a", "SKILL.md")).toBe(CISCO_SARIF_FALLBACK_URI_V1);
  });

  it("keeps a missing URI missing and replaces a non-string one", () => {
    expect(prefixSafeCiscoUriV1("skills/a", undefined)).toBeUndefined();
    expect(prefixSafeCiscoUriV1("skills/a", 42)).toBe(CISCO_SARIF_FALLBACK_URI_V1);
  });
});
