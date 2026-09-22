import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The examples are documentation that has to keep working, so they are executed here
 * rather than merely read. They must reach the package through its public entry point:
 * an example that deep-imported `dist/` or `src/` would document a boundary the package
 * does not actually offer.
 */
const root = resolve(import.meta.dirname, "..", "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8").replace(/\r\n/gu, "\n");
const built = existsSync(resolve(root, "dist", "index.js"));

function runExample(script: string, args: readonly string[] = []): string {
  return execFileSync(process.execPath, [resolve(root, "examples", script), ...args], {
    cwd: root,
    encoding: "utf8",
    stdio: "pipe",
  });
}

describe("public API examples", () => {
  it("reaches the package only through its published entry point", () => {
    for (const script of ["load-scan.mjs", "run-detector.mjs", "verify-capture-bundle.mjs"]) {
      const source = read(`examples/${script}`);
      expect(source, script).not.toMatch(/from "\.\.\/src\//u);
      expect(source, script).not.toMatch(/@aihq\/scan\/dist/u);
      // Only the loader may name a build path, and only as the in-repo fallback.
      if (script !== "load-scan.mjs") expect(source, script).not.toContain("dist");
    }
    const loader = read("examples/load-scan.mjs");
    expect(loader).toContain('await import("@aihq/scan")');
    expect(loader).toContain('resolve(here, "..", "dist", "index.js")');
  });

  it("documents that every shipped interface is Node-only", () => {
    const readme = read("README.md");
    expect(readme).toContain("## Node-only interfaces");
    expect(readme).toContain("Every interface this package ships is Node-only.");
    expect(readme).toContain("There is no CommonJS build.");
    expect(readme).toContain("node examples/run-detector.mjs");
    expect(readme).toContain("node examples/verify-capture-bundle.mjs --help");
    // No browser claim may creep into the manifest.
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    for (const field of ["browser", "module", "unpkg", "jsdelivr", "main"])
      expect(manifest[field], field).toBeUndefined();
    expect(manifest.type).toBe("module");
  });

  it.runIf(built)("runs the detector example and refuses the hardened profile honestly", () => {
    const output = runExample("run-detector.mjs");

    expect(output).toContain("loaded @aihq/scan");
    for (const detectorId of [
      "detector.aih-native",
      "detector.cisco",
      "detector.semgrep",
      "detector.skillspector",
    ])
      expect(output, detectorId).toContain(detectorId);
    // The hardened request is always refused before anything is spawned.
    expect(output).toContain('"outcome": "refused"');
    expect(output).toMatch(/"reason": "(unsupported-platform|execution-profile-unavailable)"/u);
    // The in-process analyzer really runs.
    expect(output).toContain('"outcome": "succeeded"');
    expect(output).toContain('"id": "in-process-native-v1"');
    expect(output).toContain('"isolation": "none"');
    expect(output).toContain('"sourceUnchanged": true');
    expect(output).toContain('"authority": "none"');
    expect(output).toContain("not a claim that nothing was found");
  });

  it.runIf(built)("prints usage and refuses missing custody material by name", () => {
    expect(runExample("verify-capture-bundle.mjs", ["--help"])).toContain(
      "usage: node examples/verify-capture-bundle.mjs",
    );

    const failure = (() => {
      try {
        runExample("verify-capture-bundle.mjs", [
          "--bundle",
          "no-such-bundle",
          "--evidence",
          "no-such-evidence.json",
          "--roots",
          "no-such-roots.json",
          "--expected",
          "no-such-expected.json",
        ]);
        return undefined;
      } catch (error) {
        return error as { status?: number; stderr?: string };
      }
    })();

    expect(failure?.status).toBe(2);
    expect(failure?.stderr).toContain("refused:");
    // It ships no trust root of its own, so it cannot verify anything it was not given.
    expect(read("examples/verify-capture-bundle.mjs")).toContain(
      "Every custody input is supplied by the operator.",
    );
  });
});
