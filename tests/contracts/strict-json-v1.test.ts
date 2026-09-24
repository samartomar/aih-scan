import { describe, expect, it } from "vitest";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  decodeStrictUtf8V1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
  parseStrictJsonV1,
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

// S2h (review of S2g): analyzer bytes are parsed by one RFC 8259 parser that never lets a
// later key, a prototype key, a lossy number or bytes outside the JSON text change what a
// reader sees.
describe("parseStrictJsonV1 and decodeStrictUtf8V1", () => {
  const bs = "\\";
  const BOM = String.fromCharCode(0xfeff);
  const NFD = `e${String.fromCharCode(0x301)}`;
  it("rejects duplicate keys at any depth, including the reviewer's executionSuccessful and properties forms", () => {
    for (const raw of [
      '{"runs":[{"invocations":[{"executionSuccessful":false,"executionSuccessful":true}]}]}',
      '{"runs":[{"invocations":[{"executionSuccessful":true,"properties":{"aihScanCompletionV1":{}},"properties":{}}]}]}',
      '[{"a":1,"a":1}]',
      `{"a":1,"${bs}u0061":1}`,
      '{"a":{"b":[{"c":1,"c":2}]}}',
    ]) {
      expect(() => parseStrictJsonV1(raw, "fixture")).toThrow(/duplicate JSON object key/);
      if (raw.startsWith("{"))
        expect(() => parseStrictJsonObjectV1(raw, "fixture")).toThrow(/duplicate JSON object key/);
    }
  });

  it("rejects a BOM, trailing data, non-JSON whitespace, bad literals and control characters", () => {
    for (const raw of [
      `${BOM}{"a":1}`,
      `{"a":1}${BOM}`,
      '{"a":1} x',
      '{"a":1}{"b":2}',
      '{"a":1},"b":2',
      '{"a":1}\u0000',
      `{${String.fromCharCode(0xa0)}"a":1}`,
      '{\u000b"a":1}',
      '{\u000c"a":1}',
      `{${String.fromCharCode(0x2028)}"a":1}`,
      '{"a":"x\u0001y"}',
      '{"a":"x\ty"}',
      '{"a":"x\ny"}',
      `{"a":"${bs}x"}`,
      `{"a":"${bs}u12"}`,
      '{"a":01}',
      '{"a":1.}',
      '{"a":.5}',
      '{"a":+1}',
      '{"a":0x10}',
      '{"a":NaN}',
      '{"a":Infinity}',
      "{'a':1}",
      "{a:1}",
      '{"a":1,}',
      "[1,]",
      '{"a":1}// c',
      '{"a":/* c */1}',
      '{"a":True}',
      "",
      " ",
    ]) {
      expect(() => parseStrictJsonV1(raw, "fixture"), JSON.stringify(raw)).toThrow();
    }
  });

  it("rejects numbers JSON.parse would change: overflow, underflow and unsafe integers", () => {
    for (const raw of [
      '{"a":1e999}',
      '{"a":-1e999}',
      '{"a":1e-400}',
      '{"a":12345678901234567890}',
      '{"a":-9007199254740993}',
      '{"a":-0}',
    ]) {
      expect(() => parseStrictJsonV1(raw, "fixture"), raw).toThrow();
    }
    expect(parseStrictJsonV1('{"a":9007199254740991,"b":-1.5e3,"c":0.1,"d":0}', "fixture")).toEqual(
      { a: 9007199254740991, b: -1500, c: 0.1, d: 0 },
    );
  });

  it("keeps a __proto__ key as own data: it never erases a key or replaces the prototype", () => {
    for (const parse of [parseStrictJsonV1, parseStrictJsonObjectV1]) {
      const nulled = parse('{"a":1,"__proto__":null}', "fixture") as Record<string, unknown>;
      expect(Object.getPrototypeOf(nulled)).toBe(Object.prototype);
      expect(Object.keys(nulled)).toEqual(["a", "__proto__"]);
      expect(Object.getOwnPropertyDescriptor(nulled, "__proto__")?.value).toBeNull();
      const forged = parse(
        '{"properties":{"__proto__":{"aihScanCompletionV1":{}}}}',
        "fixture",
      ) as { properties: Record<string, unknown> };
      expect(Object.getPrototypeOf(forged.properties)).toBe(Object.prototype);
      expect(Object.hasOwn(forged.properties, "__proto__")).toBe(true);
      expect(Object.hasOwn(forged.properties, "aihScanCompletionV1")).toBe(false);
      expect(canonicalStrictJsonBytesV1(forged).toString("utf8")).toBe(
        '{"properties":{"__proto__":{"aihScanCompletionV1":{}}}}',
      );
    }
  });

  it("parses any JSON value strictly, bounds nesting, and keeps NFC as the caller's choice", () => {
    expect(parseStrictJsonV1(' [ {"a" : [true, false, null, "é", -1]} ] \r\n', "fixture")).toEqual([
      { a: [true, false, null, "é", -1] },
    ]);
    expect(parseStrictJsonV1(`"${bs}u00e9${bs}/${bs}n"`, "fixture")).toBe("é/\n");
    expect(() => parseStrictJsonV1(`"${bs}uD800"`, "fixture")).toThrow(/malformed Unicode/);
    expect(() => parseStrictJsonV1(`${"[".repeat(600)}${"]".repeat(600)}`, "fixture")).toThrow(
      /nesting/,
    );
    expect(() => parseStrictJsonV1(`{"${NFD}":1}`, "fixture")).toThrow(/NFC/);
    expect(parseStrictJsonV1(`{"${NFD}":1}`, "fixture", { requireNfc: false })).toEqual({
      [NFD]: 1,
    });
    expect(() => parseStrictJsonObjectV1("[]", "fixture")).toThrow(/root must be an object/);
  });

  it("decodes only well-formed UTF-8 and keeps a BOM for the parser to refuse", () => {
    expect(decodeStrictUtf8V1(Buffer.from('{"a":"é"}', "utf8"), "fixture")).toBe('{"a":"é"}');
    for (const bytes of [
      Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
      Buffer.from([0x22, 0xc3, 0x22]),
      Buffer.from([0x22, 0xed, 0xa0, 0x80, 0x22]),
      Buffer.from([0x22, 0xc0, 0xaf, 0x22]),
    ])
      expect(() => decodeStrictUtf8V1(bytes, "fixture")).toThrow(/not well-formed UTF-8/);
    const bom = decodeStrictUtf8V1(Buffer.from(`${BOM}{"a":1}`, "utf8"), "fixture");
    expect(bom.charCodeAt(0)).toBe(0xfeff);
    expect(() => parseStrictJsonV1(bom, "fixture")).toThrow();
  });
});
