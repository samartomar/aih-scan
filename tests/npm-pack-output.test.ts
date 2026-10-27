import { describe, expect, it } from "vitest";
import { readPackedPackage } from "./support/npm-pack-output.js";

const packed = {
  name: "@example/package",
  filename: "example-package-1.0.0.tgz",
  files: [{ path: "package.json" }, { path: "dist/index.js" }],
};

describe("npm pack JSON inventory", () => {
  it.each([
    ["npm 11 array", [packed]],
    ["npm 12 package-name map", { "@example/package": packed }],
  ])("reads the public inventory from %s", (_format, output) => {
    expect(readPackedPackage(JSON.stringify(output))).toEqual({
      filename: packed.filename,
      files: packed.files,
    });
  });

  it.each(
    [[], {}, [packed, packed], { first: packed, second: packed }, null, "invalid"].map((value) =>
      JSON.stringify(value),
    ),
  )("rejects missing or ambiguous package inventory: %j", (output) => {
    expect(() => readPackedPackage(output)).toThrow();
  });

  it.each([
    { filename: 7, files: [] },
    { filename: packed.filename, files: [{ path: 7 }] },
    { filename: packed.filename, files: [null] },
    { error: "pack failed" },
  ])("rejects malformed package entries: %j", (entry) => {
    expect(() => readPackedPackage(JSON.stringify([entry]))).toThrow();
    expect(() => readPackedPackage(JSON.stringify({ "@example/package": entry }))).toThrow();
  });
});
