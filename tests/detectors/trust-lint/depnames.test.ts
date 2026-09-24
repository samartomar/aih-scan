import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanTrustDependencyNamesV1 } from "../../../src/detectors/trust-lint/depnames.js";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import { coreSelectionV1 } from "./support.js";

/**
 * Parity port of Core's `tests/trust/depnames.test.ts` against
 * `scanTrustDependencyNamesV1(tree, selection, scopes)`, the selection being
 * Core's trust inventory of the fixture tree.
 *
 * Not ported (Core-owned policy, not detection): the two
 * `resolveInternalScopes` cases (org-policy union, malformed policy file, env
 * normalization): Core resolves the scopes and sends them normalized in
 * `detectorOptions.internalScopes` (C2a §2.1, decision 8), which the options
 * validator checks. The `posture` argument is gone
 * with Core's grading; it is identity for these codes, so the "every posture"
 * assertions run once against the raw findings.
 */
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-trust-deps-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const path = join(dir, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

function pkg(deps: Record<string, string>): void {
  write("package.json", JSON.stringify({ dependencies: deps }));
}

function lockfile(): void {
  write("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {} }));
}

function scan(internalScopes: readonly string[]) {
  const tree = buildTrustLintTreeV1(dir);
  return scanTrustDependencyNamesV1(tree, coreSelectionV1(tree), internalScopes);
}

describe("scanTrustDependencyNamesV1 (parity: Core scanTrustDependencyNames)", () => {
  it("flags direct dependencies under configured internal scopes", () => {
    pkg({ "@acme/widget": "1.0.0" });
    lockfile();

    const checks = scan(["@acme"]);

    expect(checks).toEqual([
      expect.objectContaining({
        verdict: "fail",
        code: "trust.dependency-confusion",
        location: expect.objectContaining({ uri: "package.json" }),
        fingerprint: expect.stringMatching(
          /^trust-dependency-confusion:package\.json:[0-9a-f]{64}$/,
        ),
      }),
    ]);
  });

  it("keeps dependency finding identity stable when only its display line shifts", () => {
    const packageJson = [
      "{",
      '  "dependencies": {',
      '    "@acme/widget": "1.0.0"',
      "  }",
      "}",
    ].join("\n");
    write("package.json", packageJson);
    lockfile();
    const first = scan(["@acme"])[0];

    write("package.json", `\n${packageJson}`);
    const shifted = scan(["@acme"])[0];

    expect(first?.location.startLine).toBe(3);
    expect(shifted?.location.startLine).toBe(4);
    expect(shifted?.fingerprint).toBe(first?.fingerprint);
  });

  it("does not flag internal-looking scopes when env scopes are unset", () => {
    pkg({ "@acme/widget": "1.0.0" });
    lockfile();

    expect(scan([])).toEqual([]);
  });

  it("flags distance-one popular package typos", () => {
    lockfile();
    write(
      "package.json",
      JSON.stringify({
        dependencies: { reqeusts: "1.0.0" },
        devDependencies: { expresss: "1.0.0" },
      }),
    );

    expect(scan([]).map((check) => check.code)).toEqual(["trust.typosquat", "trust.typosquat"]);
  });

  it("flags scoped package typos when the scope matches a popular scoped package", () => {
    pkg({ "@types/nod": "1.0.0" });
    lockfile();

    expect(scan([])).toEqual([
      expect.objectContaining({
        verdict: "fail",
        code: "trust.typosquat",
        detail: expect.stringContaining("@types/node"),
        location: expect.objectContaining({ uri: "package.json" }),
      }),
    ]);
  });

  it("does not flag exact popular names or distance-two names", () => {
    pkg({ react: "18.0.0", rxect: "1.0.0", "@types/node": "26.0.0" });
    lockfile();

    expect(scan([])).toEqual([]);
  });

  it("does not scan transitive lockfile packages", () => {
    write("package.json", JSON.stringify({ dependencies: { react: "18.0.0" } }));
    write(
      "package-lock.json",
      JSON.stringify({ packages: { "node_modules/expresss": { version: "1.0.0" } } }),
    );

    expect(scan([])).toEqual([]);
  });

  it("blocks floating direct dependency specs at every posture", () => {
    lockfile();
    write(
      "package.json",
      JSON.stringify({
        dependencies: {
          caret: "^1.2.3",
          exact: "1.2.3",
          floating: "*",
          latest: "latest",
          gitLoose: "git+https://github.com/acme/tool.git",
          gitPinned: `git+https://github.com/acme/tool.git#${"a".repeat(40)}`,
        },
      }),
    );

    // Core's posture grading is the identity function for
    // trust.unpinned-dependency, so the raw findings are what both the "vibe"
    // and "enterprise" Core assertions observe.
    const vibe = scan([]).filter((check) => check.name === "trust.unpinned-dependency");
    expect(vibe).toHaveLength(4);
    expect(vibe.every((check) => check.verdict === "fail")).toBe(true);
    expect(vibe.every((check) => check.code === "trust.unpinned-dependency")).toBe(true);
    expect(vibe.map((check) => check.detail).join("\n")).not.toContain("exact");
    expect(vibe.map((check) => check.detail).join("\n")).not.toContain("gitPinned");

    const enterprise = scan([]).filter((check) => check.code === "trust.unpinned-dependency");
    expect(enterprise).toHaveLength(4);
    expect(enterprise.every((check) => check.verdict === "fail")).toBe(true);
  });

  it("recognizes exact integrity-bound resolutions in a colocated npm lockfile", () => {
    write(
      ".opencode/package.json",
      JSON.stringify({
        peerDependencies: { "@opencode-ai/plugin": ">=1.0.0" },
        devDependencies: {
          "@opencode-ai/plugin": "^1.4.3",
          "@types/node": "^20.0.0",
          typescript: "^5.3.0",
        },
      }),
    );
    write(
      ".opencode/package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": {
            peerDependencies: { "@opencode-ai/plugin": ">=1.0.0" },
            devDependencies: {
              "@opencode-ai/plugin": "^1.4.3",
              "@types/node": "^20.0.0",
              typescript: "^5.3.0",
            },
          },
          "node_modules/@opencode-ai/plugin": {
            version: "1.4.3",
            resolved: "https://registry.npmjs.org/@opencode-ai/plugin/-/plugin-1.4.3.tgz",
            integrity: "sha512-plugin",
          },
          "node_modules/@types/node": {
            version: "20.19.33",
            resolved: "https://registry.npmjs.org/@types/node/-/node-20.19.33.tgz",
            integrity: "sha512-node",
          },
          "node_modules/typescript": {
            version: "5.9.3",
            resolved: "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz",
            integrity: "sha512-typescript",
          },
        },
      }),
    );

    expect(scan([])).toEqual([]);
  });

  it("flags bare git shorthand unless it has a lowercase full SHA pin", () => {
    lockfile();
    write(
      "package.json",
      JSON.stringify({
        dependencies: {
          shorthandLoose: "owner/repo",
          shorthandPinned: `owner/repo#${"a".repeat(40)}`,
          shorthandUpperPinned: `owner/repo#${"A".repeat(40)}`,
        },
      }),
    );

    const details = scan([])
      .filter((check) => check.code === "trust.unpinned-dependency")
      .map((check) => check.detail);

    expect(details).toHaveLength(2);
    expect(details.join("\n")).toContain("shorthandLoose");
    expect(details.join("\n")).toContain("shorthandUpperPinned");
    expect(details.join("\n")).not.toContain("shorthandPinned");
  });

  it("flags npm x-ranges as unpinned dependency specs", () => {
    lockfile();
    write(
      "package.json",
      JSON.stringify({
        dependencies: {
          majorX: "1.x",
          minorX: "1.2.x",
          exact: "1.2.3",
        },
      }),
    );

    const details = scan([])
      .filter((check) => check.code === "trust.unpinned-dependency")
      .map((check) => check.detail)
      .join("\n");

    expect(details).toContain("majorX");
    expect(details).toContain("minorX");
    expect(details).not.toContain("exact");
  });

  it("flags dependencies declared without any lockfile in the trust source", () => {
    pkg({ react: "18.0.0" });

    expect(scan([])).toEqual([
      expect.objectContaining({
        verdict: "fail",
        code: "trust.unpinned-dependency",
        detail: expect.stringContaining("no lockfile"),
        location: expect.objectContaining({ uri: "package.json" }),
      }),
    ]);

    lockfile();

    expect(scan([])).toEqual([]);
  });
});
