import { describe, expect, it } from "vitest";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  parseStrictJsonObjectV1,
} from "../../src/contract/strict-json-v1.js";

describe("StrictJsonV1", () => {
  it("rejects duplicate raw keys, comments, trailing data, malformed Unicode, and non-NFC JSON", () => {
    for (const raw of [
      '{"a":1,"a":2}',
      '{"a":1}// comment',
      '{"a":1,}',
      '{"a":"\\uD800"}',
      '{"e\\u0301":1}',
    ]) {
      expect(() => parseStrictJsonObjectV1(raw, "fixture")).toThrow();
    }
  });

  it("accepts only canonical enumerable JSON data and JCS/SHA-256 is stable", () => {
    const value = { a: [true, "é"], b: 1 };
    expect(canonicalStrictJsonBytesV1(value).toString("utf8")).toBe('{"a":[true,"é"],"b":1}');
    expect(canonicalStrictJsonSha256V1(value)).toMatch(/^[a-f0-9]{64}$/);
    for (const invalid of [
      { a: undefined },
      { a: -0 },
      { a: Number.NaN },
      Object.create({ inherited: 1 }),
    ]) {
      expect(() => assertStrictJsonValueV1(invalid, "value")).toThrow();
    }
  });

  it("rejects hostile relative POSIX paths", () => {
    for (const path of [
      "",
      "/absolute",
      "C:/drive",
      "\\backslash",
      "./dot",
      "a/../b",
      "a//b",
      "a/",
      "a%2fb",
      "a?x",
      "a#x",
      "a\u0000b",
      "e\u0301.md",
    ]) {
      expect(() => assertSafeRelativePosixPathV1(path, "path")).toThrow();
    }
    expect(assertSafeRelativePosixPathV1("skills/é/SKILL.md", "path")).toBe("skills/é/SKILL.md");
  });
});
