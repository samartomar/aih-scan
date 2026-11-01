import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { corpusRoot } from "../support/scan-v1-corpus.js";
import { vectorsPath } from "../support/sigstore-v1-vectors.js";

const root = join(import.meta.dirname, "..", "..");
const out = mkdtempSync(join(tmpdir(), "aih-scan-v1-portable-"));
afterAll(() => rmSync(out, { recursive: true, force: true }));

describe("browser-safe /read and /contracts", () => {
  it("load, read and verify the shared corpus and Sigstore fixtures in a realm without Node globals or built-ins", () => {
    execFileSync(
      process.execPath,
      [
        join(root, "node_modules", "typescript", "bin", "tsc"),
        "-p",
        join(root, "tsconfig.build.json"),
        "--outDir",
        out,
      ],
      {
        cwd: root,
        stdio: "pipe",
      },
    );
    const output = execFileSync(
      process.execPath,
      [
        "--experimental-vm-modules",
        "--no-warnings",
        join(root, "tests", "support", "portable-realm-v1.mjs"),
        out,
        corpusRoot,
        vectorsPath,
      ],
      { encoding: "utf8" },
    );
    expect(output).toBe("portable-realm-ok\n");
  }, 60_000);
});
