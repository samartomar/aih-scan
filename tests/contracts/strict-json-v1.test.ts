import { describe, expect, it } from "vitest";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../../src/contract/strict-json-v1.js";

describe("StrictJsonV1", () => {
  it("rejects duplicate raw keys, comments, trailing data, malformed Unicode, and non-NFC JSON", () => {
    for (const raw of [
      '{"a":1,"a":2}',
      '{"a":1,"\\u0061":2}',
      '{"outer":{"a":1,"a":2}}',
      '{"a":1}// comment',
      '{"a":1,}',
      '{"n":-0}',
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
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    const accessor: Record<string, unknown> = {};
    Object.defineProperty(accessor, "value", { enumerable: true, get: () => 1 });
    const symbol = Symbol("not-json");
    const arrayWithHole: unknown[] = new Array(2);
    arrayWithHole[0] = "present";
    for (const invalid of [
      { a: undefined },
      { a: -0 },
      { a: Number.NaN },
      { a: Number.POSITIVE_INFINITY },
      Object.create({ inherited: 1 }),
      cycle,
      accessor,
      arrayWithHole,
      { [symbol]: "symbol" },
    ]) {
      expect(() => assertStrictJsonValueV1(invalid, "value")).toThrow();
    }
    const frozen = deepFreezeStrictJsonV1(
      assertStrictJsonValueV1({ nested: { value: "é" } }, "value"),
    );
    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen((frozen as { nested: unknown }).nested)).toBe(true);
    expect(canonicalStrictJsonBytesV1({ n: 0.000001, text: "😀" }).toString("utf8")).toBe(
      '{"n":0.000001,"text":"😀"}',
    );
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
      "a//",
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
