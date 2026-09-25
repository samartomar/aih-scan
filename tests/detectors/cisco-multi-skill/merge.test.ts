import { describe, expect, it } from "vitest";
import { prefixSafeCiscoUriV1 } from "../../../src/detectors/cisco-multi-skill/merge-v1.js";

// C2a §3.4 with the complete §1.4 rule applied to the FINAL prefixed URI. S2g (review of
// U1d): an unsafe URI is refused, never replaced by `cisco.sarif`, because that name can bind
// to an unrelated sealed root-level file of the same name.
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
  ])("refuses an unsafe final URI, never substituting a name (prefix %j, uri %j)", (prefix, uri) => {
    expect(() => prefixSafeCiscoUriV1(prefix, uri)).toThrow(/not a safe source-relative/);
  });

  it("refuses the reviewer's escape instead of naming cisco.sarif", () => {
    expect(() => prefixSafeCiscoUriV1("", "../outside.md")).toThrow(/not a safe source-relative/);
    expect(() => prefixSafeCiscoUriV1("skills/a", "../../cisco.sarif")).toThrow(
      /not a safe source-relative/,
    );
  });

  it("refuses when the prefix itself would make the final URI unsafe", () => {
    expect(() => prefixSafeCiscoUriV1("skills/./a", "SKILL.md")).toThrow(
      /not a safe source-relative/,
    );
  });

  it("keeps a missing URI missing and refuses a non-string one", () => {
    expect(prefixSafeCiscoUriV1("skills/a", undefined)).toBeUndefined();
    expect(() => prefixSafeCiscoUriV1("skills/a", 42)).toThrow(/not a string/);
  });

  it("accepts a contained directory only where the location may name one (S2g)", () => {
    expect(prefixSafeCiscoUriV1("skills/a", "node_modules/", true)).toBe("skills/a/node_modules/");
    expect(prefixSafeCiscoUriV1("", "node_modules/", true)).toBe("node_modules/");
    for (const uri of ["../", "a//", "/etc/", "./", "."])
      expect(() => prefixSafeCiscoUriV1("skills/a", uri, true), uri).toThrow(
        /not a safe source-relative/,
      );
    expect(() => prefixSafeCiscoUriV1("skills/a", "node_modules/")).toThrow(
      /not a safe source-relative/,
    );
  });
});
