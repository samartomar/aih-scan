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
  STRICT_JSON_MAX_NUMBER_CHARACTERS_V1,
  StrictJsonBoundErrorV1,
  StrictJsonNumberErrorV1,
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

  it("rejects numbers JSON.parse would change: overflow, underflow and rounded integers", () => {
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

  // S2i (review of S2h): one loss-aware policy for every spelling of a number. The decision
  // depends on the text's exact decimal value only, never on whether it has a fraction or an
  // exponent: 9007199254740993 is refused however it is written, and 9007199254740992, which a
  // double holds exactly, is accepted however it is written.
  describe("one loss-aware number policy for every spelling (S2i)", () => {
    const parsed = (lexeme: string) =>
      (parseStrictJsonV1(`{"n":${lexeme}}`, "fixture") as { n: number }).n;
    const refusal = (lexeme: string) => {
      try {
        parsed(lexeme);
      } catch (error) {
        return error;
      }
      throw new Error(`${lexeme} was accepted`);
    };

    it("accepts every spelling of a value a double holds exactly", () => {
      const exact: [string, number][] = [
        ["9007199254740992", 2 ** 53],
        ["-9007199254740992", -(2 ** 53)],
        ["9007199254740992.0", 2 ** 53],
        ["9007199254740992e0", 2 ** 53],
        ["9.007199254740992e15", 2 ** 53],
        ["90071992547409920E-1", 2 ** 53],
        ["0.9007199254740992e+16", 2 ** 53],
        ["1152921504606846976", 2 ** 60],
        ["1.152921504606846976e18", 2 ** 60],
        ["-1152921504606846976.000", -(2 ** 60)],
        ["0.1e1", 1],
        ["100e-2", 1],
        ["0", 0],
        ["0.0e7", 0],
      ];
      for (const [lexeme, value] of exact) expect(parsed(lexeme), lexeme).toBe(value);
    });

    it("accepts a fraction written as its double's shortest round-trip decimal, or exactly", () => {
      const fractions: [string, number][] = [
        ["0.1", 0.1],
        ["0.10", 0.1],
        ["1e-1", 0.1],
        ["10E-2", 0.1],
        ["-0.1", -0.1],
        ["0.30000000000000004", 0.1 + 0.2],
        ["0.1000000000000000055511151231257827021181583404541015625", 0.1],
        ["5e-324", 5e-324],
        ["2.2250738585072014e-308", 2.2250738585072014e-308],
      ];
      for (const [lexeme, value] of fractions) expect(parsed(lexeme), lexeme).toBe(value);
    });

    it("refuses every spelling of a value the double would round, with a typed failure", () => {
      for (const lexeme of [
        "9007199254740993",
        "9007199254740993e0",
        "9007199254740993.0",
        "9007199254740993.000E+0",
        "900719925474099.3e1",
        "9.007199254740993e15",
        "90071992547409930e-1",
        "-9007199254740993",
        "-9007199254740993e0",
        "-9007199254740993.0",
        "9007199254740992.5",
        "12345678901234567890",
        "12345678901234567000",
        "1e23",
        "0.3000000000000000444",
        "1.7976931348623157e-308",
        "3e-324",
      ]) {
        const error = refusal(lexeme);
        expect(error, lexeme).toBeInstanceOf(StrictJsonNumberErrorV1);
        expect(error, lexeme).toBeInstanceOf(TypeError);
        expect(error, lexeme).toMatchObject({ lexeme, loss: "rounded" });
      }
    });

    it("refuses overflow, underflow and negative zero in every spelling, typed", () => {
      const refused: [string, string][] = [
        ["1e999", "overflow"],
        ["-1e999", "overflow"],
        [`1${"0".repeat(400)}.0`, "overflow"],
        ["1e-400", "underflow"],
        ["-1e-400", "underflow"],
        [`0.${"0".repeat(400)}1`, "underflow"],
        ["-0", "negative-zero"],
        ["-0.0", "negative-zero"],
        ["-0e+1", "negative-zero"],
        ["-0.000E-5", "negative-zero"],
      ];
      for (const [lexeme, loss] of refused)
        expect(refusal(lexeme), lexeme).toMatchObject({ lexeme, loss });
    });

    // U1g (review of S2i, P2): one numeric token is bounded before any work on its value, and
    // the scan of a token is linear, so a valid but huge token cannot stall the parser.
    describe("a typed resource bound on one numeric token", () => {
      const exactSmallest = `0.${(5n ** 1074n).toString().padStart(1074, "0")}`;

      it("accepts the longest plain spelling of any double's exact value", () => {
        // 2^-1074 written out in full: the longest exact expansion a double has.
        expect(`-${exactSmallest}`.length).toBeLessThanOrEqual(
          STRICT_JSON_MAX_NUMBER_CHARACTERS_V1,
        );
        expect(parsed(exactSmallest)).toBe(5e-324);
        expect(parsed(`-${exactSmallest}`)).toBe(-5e-324);
      });

      it("refuses a token one character beyond the bound, typed, whatever its value", () => {
        for (const lexeme of [
          `1${"0".repeat(STRICT_JSON_MAX_NUMBER_CHARACTERS_V1)}`,
          `0.${"0".repeat(STRICT_JSON_MAX_NUMBER_CHARACTERS_V1 - 1)}`,
          `1e${"0".repeat(STRICT_JSON_MAX_NUMBER_CHARACTERS_V1 - 1)}`,
        ]) {
          expect(lexeme.length, lexeme.slice(0, 8)).toBe(STRICT_JSON_MAX_NUMBER_CHARACTERS_V1 + 1);
          const error = refusal(lexeme);
          expect(error).toBeInstanceOf(StrictJsonBoundErrorV1);
          expect(error).toBeInstanceOf(TypeError);
          expect(error).toMatchObject({
            bound: "number-characters",
            limit: STRICT_JSON_MAX_NUMBER_CHARACTERS_V1,
          });
        }
      });

      it("refuses the reviewer's hostile token fast (1, a million zeros, 1)", () => {
        const hostile = `{"n":1${"0".repeat(1_000_000)}1}`;
        const started = performance.now();
        let error: unknown;
        try {
          parseStrictJsonV1(hostile, "fixture");
        } catch (caught) {
          error = caught;
        }
        const elapsed = performance.now() - started;
        expect(error).toBeInstanceOf(StrictJsonBoundErrorV1);
        expect(elapsed).toBeLessThan(250);
      });

      it("judges long tokens within the bound in linear time", () => {
        const width = STRICT_JSON_MAX_NUMBER_CHARACTERS_V1 - 2;
        const started = performance.now();
        for (let round = 0; round < 200; round += 1) {
          expect(refusal(`1${"0".repeat(width)}1`)).toMatchObject({ loss: "overflow" });
          expect(parsed(`0.${"0".repeat(width - 2)}`)).toBe(0);
        }
        expect(performance.now() - started).toBeLessThan(1000);
      });
    });
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
