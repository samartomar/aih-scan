/**
 * Direct repository checks for `tools/capture-catalog-item.mjs`: the host
 * platform gate and the helper's cross-checks of operator detector inputs.
 *
 * These run on any host. They never invoke a detector, never read a capture
 * bundle and never report findings; the detector-input cases use the labelled
 * fixtures in `capture-catalog-fixtures.ts` because no real operator
 * registration, OCI layout or annex bytes exist in this repository.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BASELINE_DOCKER_EXECUTABLE_V1 } from "../../src/cli/process-runner.js";
import { createDetectorRegistrationV1 } from "../../src/registration/detector-registration-v1.js";
import {
  assertPlatform,
  BROKER_DOCKER_EXECUTABLE,
  createRunDirectory,
  installEnvironment,
  npmCliPath,
  readDetectorInputs,
} from "../../tools/capture-catalog-item.mjs";
import {
  FIXTURE_CONFIG_SHA256,
  FIXTURE_DETECTOR_ID,
  FIXTURE_LOGICAL_REFERENCE,
  FIXTURE_MANIFEST_SHA256,
  fixtureLayout,
  fixtureOptions,
  fixtureProvenanceBytes,
  fixtureRegistration,
  fixtureSbomBytes,
  writeDetectorInputFixtures,
  writeJsonFixture,
} from "./capture-catalog-fixtures.js";

const roots: string[] = [];
const fixtureReader = { createDetectorRegistrationV1 };

afterEach(() => {
  for (const path of roots.splice(0)) rmSync(path, { force: true, recursive: true });
});

/** A fixture-backed run directory; the directory is removed after each test. */
function fixtureRun() {
  const directory = mkdtempSync(join(tmpdir(), "aih-scan-capture-fixture-"));
  roots.push(directory);
  const paths = writeDetectorInputFixtures(directory);
  const options = fixtureOptions(directory, paths);
  return { directory, options, paths, runRoot: createRunDirectory(options.output) };
}

describe("catalog capture host platform gate", () => {
  it("accepts Linux x64, the Node spelling of the OCI amd64 the adapter needs", () => {
    expect(assertPlatform({ arch: "x64", platform: "linux" })).toEqual({
      node: { architecture: "x64", os: "linux" },
      oci: { architecture: "amd64", os: "linux" },
    });
  });

  it("refuses Windows x64 and Linux arm64, naming the host it found and the spelling it needs", () => {
    expect(() => assertPlatform({ arch: "x64", platform: "win32" })).toThrow(/win32\/x64/);
    expect(() => assertPlatform({ arch: "arm64", platform: "linux" })).toThrow(/linux\/arm64/);
    expect(() => assertPlatform({ arch: "arm64", platform: "darwin" })).toThrow(/darwin\/arm64/);
    // The refusal states both vocabularies, so the operator is not sent after a host Node never reports.
    expect(() => assertPlatform({ arch: "x64", platform: "win32" })).toThrow(/linux\/x64/);
  });

  it("refuses the OCI spelling, which Node never reports", () => {
    expect(() => assertPlatform({ arch: "amd64", platform: "linux" })).toThrow(/linux\/amd64/);
  });
});

describe("catalog capture Docker preflight", () => {
  it("probes the exact Docker executable the OCI broker spawns and the profile gates", () => {
    expect(BROKER_DOCKER_EXECUTABLE).toBe(BASELINE_DOCKER_EXECUTABLE_V1);
  });
});

describe("catalog capture consumer installer", () => {
  it("drops npm's exported configuration and keeps what the install needs", () => {
    expect(
      installEnvironment({
        HOME: "/root",
        HTTPS_PROXY: "http://proxy.invalid:3128",
        NPM_CONFIG_REGISTRY: "https://private.invalid/",
        PATH: "/usr/bin:/bin",
        TEMP: "/tmp",
        npm_config_allow_scripts: "left-pad",
        npm_lifecycle_event: "test",
        npm_package_name: "consumer",
      }),
    ).toEqual({
      HOME: "/root",
      HTTPS_PROXY: "http://proxy.invalid:3128",
      PATH: "/usr/bin:/bin",
      TEMP: "/tmp",
    });
  });

  it("resolves an npm CLI entrypoint to run under Node, ignoring a shell shim or a missing file", () => {
    const directory = mkdtempSync(join(tmpdir(), "aih-scan-capture-npm-"));
    roots.push(directory);
    const npmCli = join(directory, "npm-cli.js");
    writeFileSync(npmCli, "// fixture npm CLI entrypoint\n");
    expect(npmCliPath({ npm_execpath: npmCli })).toBe(npmCli);
    for (const npm_execpath of [join(directory, "npm.cmd"), join(directory, "absent-npm-cli.js")]) {
      let resolved: string | undefined;
      try {
        resolved = npmCliPath({ npm_execpath });
      } catch {
        // No npm beside this Node is the documented refusal, not a silent shim spawn.
        resolved = undefined;
      }
      if (resolved !== undefined) {
        expect(resolved).not.toBe(npm_execpath);
        expect(resolved.endsWith("npm-cli.js")).toBe(true);
        expect(existsSync(resolved)).toBe(true);
      }
    }
  });
});

describe("catalog capture detector-input cross-checks (labelled fixtures)", () => {
  it("accepts a self-consistent fixture and stages the operator's own annex bytes", () => {
    const { options, runRoot } = fixtureRun();
    const detector = readDetectorInputs(fixtureReader, options, runRoot);
    expect(detector.detectorId).toBe(FIXTURE_DETECTOR_ID);
    expect(detector.layout.logicalReference).toBe(FIXTURE_LOGICAL_REFERENCE);
    expect(detector.annexFiles.map((entry) => entry.descriptorId)).toEqual([
      "annex.sbom",
      "annex.provenance",
    ]);
    expect(
      detector.annexFiles.map((entry) => readFileSync(entry.path).equals(fixtureSbomBytes())),
    ).toEqual([true, false]);
    expect(
      detector.annexFiles.map((entry) => readFileSync(entry.path).equals(fixtureProvenanceBytes())),
    ).toEqual([false, true]);
  });

  it("carries the authoring registration forward, never the computed wire form", () => {
    const { options, runRoot } = fixtureRun();
    const detector = readDetectorInputs(fixtureReader, options, runRoot);
    expect(Object.hasOwn(detector.registrationInput as object, "registrationSha256")).toBe(false);
    expect(detector.registrationRecord.registrationSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a registration that already carries computed wire fields", () => {
    const { options, runRoot } = fixtureRun();
    writeJsonFixture(options.registration, {
      ...fixtureRegistration(),
      registrationSha256: "f".repeat(64),
    });
    expect(() => readDetectorInputs(fixtureReader, options, runRoot)).toThrow(
      /computed field\(s\) registrationSha256/,
    );
  });

  it("refuses a layout that does not carry the image name CiscoOciLayoutV1 fixes", () => {
    const { options, runRoot } = fixtureRun();
    writeJsonFixture(options.layout, {
      ...fixtureLayout(),
      logicalReference: `example.invalid/other/scanner@sha256:${FIXTURE_MANIFEST_SHA256}`,
    });
    expect(() => readDetectorInputs(fixtureReader, options, runRoot)).toThrow(
      /logical reference must be 'local\.invalid\/aih-scan\/cisco@/,
    );
  });

  it("refuses an image ID that is not the config digest the layout declares", () => {
    const { options, runRoot } = fixtureRun();
    writeFileSync(options.imageId, `sha256:${"9".repeat(64)}\n`);
    expect(() => readDetectorInputs(fixtureReader, options, runRoot)).toThrow(
      /--image-id does not match the config digest the layout declares/,
    );
  });

  it("refuses annex bytes that do not match the registered digests", () => {
    const { options, runRoot } = fixtureRun();
    writeFileSync(options.sbom, `${JSON.stringify({ name: "tampered-fixture-sbom" })}\n`);
    expect(() => readDetectorInputs(fixtureReader, options, runRoot)).toThrow(
      /--sbom sha256 .* does not match the registered annex\.sbom digest/,
    );
  });

  it("refuses a layout whose config digest is not the registered runtime config", () => {
    const { options, runRoot } = fixtureRun();
    writeJsonFixture(options.layout, {
      ...fixtureLayout(),
      configDigestSha256: `sha256:${"7".repeat(64)}`,
    });
    expect(() => readDetectorInputs(fixtureReader, options, runRoot)).toThrow(
      /--layout config digest does not match the registration runtime config digest/,
    );
  });

  it("keeps the fixture's own config digest distinct from its manifest digest", () => {
    expect(FIXTURE_CONFIG_SHA256).not.toBe(FIXTURE_MANIFEST_SHA256);
    expect(fixtureLayout().manifestDigestSha256).not.toBe(fixtureLayout().configDigestSha256);
  });
});
