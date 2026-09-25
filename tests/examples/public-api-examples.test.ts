import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
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

  it.runIf(built)("refuses malformed trust roots by name, never with a stack trace", () => {
    const fixture = mkdtempSync(join(tmpdir(), "aih-scan-example-roots-"));
    try {
      writeFileSync(join(fixture, "expected.json"), "{}");
      const verify = (roots: string) => {
        writeFileSync(join(fixture, "roots.json"), roots);
        return spawnSync(
          process.execPath,
          [
            resolve(root, "examples", "verify-capture-bundle.mjs"),
            "--bundle",
            join(fixture, "no-such-bundle"),
            "--evidence",
            join(fixture, "no-such-evidence.json"),
            "--roots",
            join(fixture, "roots.json"),
            "--expected",
            join(fixture, "expected.json"),
          ],
          { cwd: root, encoding: "utf8" },
        );
      };
      const validRoot = {
        identity: "organization-root",
        class: "organization",
        keyId: `ed25519:${"0".repeat(64)}`,
      };
      for (const [label, roots, reason] of [
        ["null document", "null", "trust roots must be { roots: [ … ] }"],
        ["array document", "[]", "trust roots must be { roots: [ … ] }"],
        ["null root", JSON.stringify({ roots: [null] }), "trust root 0 is not an object"],
        [
          "malformed key",
          JSON.stringify({ roots: [{ ...validRoot, publicKeySpkiBase64: "bm90LWEta2V5" }] }),
          "trust root 0 publicKeySpkiBase64 is not a readable SPKI public key",
        ],
        [
          "missing key",
          JSON.stringify({ roots: [validRoot] }),
          "trust root 0 publicKeySpkiBase64 is not a readable SPKI public key",
        ],
      ] as const) {
        const result = verify(roots);
        expect(result.status, label).toBe(2);
        expect(result.stderr, label).toContain(`refused: ${reason}`);
        expect(result.stderr, label).not.toMatch(/^\s+at /mu);
      }
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });

  it("falls back to the local build only when the package itself is not found", () => {
    // A throwaway copy of the loader, beside a stand-in local build, outside every repository.
    const fixture = mkdtempSync(join(tmpdir(), "aih-scan-example-loader-"));
    try {
      mkdirSync(join(fixture, "examples"));
      mkdirSync(join(fixture, "dist"));
      copyFileSync(
        resolve(root, "examples", "load-scan.mjs"),
        join(fixture, "examples", "load-scan.mjs"),
      );
      writeFileSync(join(fixture, "dist", "index.js"), 'export const marker = "local-build";\n');
      const load = () =>
        spawnSync(
          process.execPath,
          [
            "--input-type=module",
            "-e",
            [
              `const { loadScan } = await import(${JSON.stringify(
                pathToFileURL(join(fixture, "examples", "load-scan.mjs")).href,
              )});`,
              "const { scan, from } = await loadScan();",
              'process.stdout.write([scan.marker, from.endsWith("index.js")].join(" "));',
            ].join("\n"),
          ],
          { cwd: fixture, encoding: "utf8" },
        );

      // Not installed at all: the package is not found, so the local build is used.
      const missing = load();
      expect(missing.status, missing.stderr).toBe(0);
      expect(missing.stdout).toBe("local-build true");

      // Installed but broken: its own error surfaces instead of being masked by the fallback.
      const installed = join(fixture, "node_modules", "@aihq", "scan");
      mkdirSync(installed, { recursive: true });
      writeFileSync(
        join(installed, "package.json"),
        JSON.stringify({ name: "@aihq/scan", type: "module", exports: "./index.js" }),
      );
      writeFileSync(join(installed, "index.js"), 'throw new Error("installed package failed");\n');
      const broken = load();
      expect(broken.status).not.toBe(0);
      expect(broken.stderr).toContain("installed package failed");
      expect(broken.stdout).toBe("");
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });
});
