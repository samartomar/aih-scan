import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { admitDetectorDefinitionsV1 } from "../../src/assessment/detector-definition.js";
import { SEMGREP_VERSION_V1 } from "../../src/baseline/runtime-v1.js";
import { processRunner } from "../../src/cli/process-runner.js";
import { runDefinedDetectorV1 } from "../../src/runner/run-detector-v1.js";

vi.mock("../../src/cli/process-runner.js", async (original) => ({
  ...(await original<typeof import("../../src/cli/process-runner.js")>()),
  processRunner: vi.fn(),
}));
vi.mock("../../src/cli/residual-processes.js", () => ({
  sweepResidualProcessesV1: vi.fn(async () => ({ found: [], surviving: [] })),
}));

const roots: string[] = [];
const customRules =
  "rules:\n  - id: organization.prompt\n    languages: [generic]\n    message: Review instruction\n    severity: WARNING\n    pattern: unsafe instruction\n";
const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
function temporary() {
  const root = mkdtempSync(join(tmpdir(), "aih-defined-"));
  roots.push(root);
  return root;
}
async function definition() {
  const rules = Buffer.from(customRules);
  const admitted = await admitDetectorDefinitionsV1([
    {
      definition: {
        schema: "urn:aihq:scan:detector-definition:1.0.0",
        detectorId: "organization.prompt",
        version: "policy-revision-7",
        adapter: "semgrep-sarif-v1",
        profileId: "host-process-uv-v1",
        rules: {
          sha256: createHash("sha256").update(rules).digest("hex"),
          byteLength: rules.length,
        },
      },
      rules,
    },
  ]);
  const result = admitted.get("organization.prompt");
  if (!result) throw new Error("Test definition was not admitted");
  return result;
}
let source: string;
let ruleBytes: string;
let scanOutput: string | undefined;
let scanEffect: (() => void) | undefined;
beforeEach(() => {
  source = temporary();
  writeFileSync(join(source, "README.md"), "unsafe instruction\n");
  const host = temporary(),
    bin = join(host, "bin"),
    home = join(host, "home");
  mkdirSync(bin);
  mkdirSync(home);
  const uv = join(bin, process.platform === "win32" ? "uv.exe" : "uv"),
    python = join(bin, "python");
  writeFileSync(uv, "fake uv");
  chmodSync(uv, 0o755);
  writeFileSync(python, "fake python");
  vi.stubEnv("PATH", bin);
  vi.stubEnv("HOME", home);
  vi.stubEnv("USERPROFILE", home);
  vi.stubEnv("LOCALAPPDATA", join(home, "local"));
  vi.stubEnv("APPDATA", join(home, "roaming"));
  if (process.platform !== "win32") vi.spyOn(process, "getuid").mockReturnValue(1000);
  ruleBytes = "";
  scanOutput = undefined;
  scanEffect = undefined;
  vi.mocked(processRunner).mockImplementation(async (argv, options) => {
    if (argv[1] === "--version") return okay("uv 0.12.13");
    if (argv[1] === "python") return okay(argv.includes("--show-version") ? "3.12.13" : python);
    if (argv[1] === "sync") return okay("");
    if (argv.at(-1) === "--version") return okay(SEMGREP_VERSION_V1);
    if (!options.cwd) throw new Error("Semgrep must run in its private directory");
    ruleBytes = readFileSync(join(options.cwd, "rules.yml"), "utf8");
    scanEffect?.();
    if (scanOutput !== undefined) return okay(scanOutput);
    return okay(
      JSON.stringify({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "semgrep", version: SEMGREP_VERSION_V1 } },
            invocations: [{ executionSuccessful: true }],
            results: [
              {
                ruleId: "organization.prompt",
                level: "warning",
                message: { text: "Review instruction" },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: "README.md" },
                      region: { startLine: 1 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.mocked(processRunner).mockReset();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function request() {
  return {
    detectorId: "organization.prompt",
    executionProfileId: "host-process-uv-v1" as const,
    subject: {
      kind: "source-tree" as const,
      sourceRoot: source,
      selectedClosurePaths: ["README.md"],
    },
  };
}
it("executes exact supplied rules while preserving custom detector identity and actual analyzer facts", async () => {
  const admitted = await definition();
  const result = await runDefinedDetectorV1(request(), admitted);
  expect(result.outcome, JSON.stringify(result)).toBe("succeeded");
  if (result.outcome !== "succeeded" || result.evidence.kind !== "baseline-analyzer-observation-v1")
    throw new Error(JSON.stringify(result));
  expect(ruleBytes).toBe(customRules);
  expect(result.capability.detectorId).toBe("organization.prompt");
  expect(result.executionProfile.id).toBe("host-process-uv-v1");
  const observation = result.evidence.observation;
  expect(observation.analyzer).toBe("semgrep");
  expect(observation.analyzerVersion).toMatch(/^1\.178\.0\+uvlock\./u);
  const run = JSON.parse(observation.bytes.toString("utf8")).runs[0];
  expect(run.tool.driver).toEqual({ name: "semgrep", version: SEMGREP_VERSION_V1 });
  expect(run.invocations[0].properties.aihScanCompletionV1.detectorId).toBe("organization.prompt");
  expect(run.properties.aihDetectorDefinitionV1).toEqual({
    detectorId: "organization.prompt",
    version: "policy-revision-7",
    definitionSha256: admitted.definitionSha256,
    rulesSha256: admitted.rules.sha256,
  });
  expect(result.findings.findings[0]?.detector).toMatchObject({
    value: { id: "organization.prompt" },
  });
});
it("refuses a mismatched identity, unadmitted definition and unsupported controls before execution", async () => {
  const admitted = await definition();
  const mismatched = await runDefinedDetectorV1(
    { ...request(), detectorId: "another.detector" },
    admitted,
  );
  expect(mismatched).toMatchObject({ outcome: "refused", reason: "unknown-detector" });
  expect(await runDefinedDetectorV1(request(), { ...admitted })).toMatchObject({
    outcome: "refused",
    reason: "unknown-detector",
  });
  for (const field of ["runner", "prerequisiteProbe", "env", "args", "executable", "network"])
    expect(
      await runDefinedDetectorV1(
        {
          ...request(),
          [field]: () => {
            throw new Error("must not execute");
          },
        },
        admitted,
      ),
    ).toMatchObject({ outcome: "refused", reason: "execution-profile-unavailable" });
  expect(
    await runDefinedDetectorV1(
      { ...request(), executionProfileId: "linux-namespace-uv-v1" as never },
      admitted,
    ),
  ).toMatchObject({ outcome: "refused", reason: "execution-profile-unavailable" });
  expect(processRunner).not.toHaveBeenCalled();
});

it.each([
  "malformed",
  "escaped-location",
  "forged-definition",
])("rejects %s analyzer output rather than minting successful definition evidence", async (scenario) => {
  const run = {
    tool: { driver: { name: "semgrep" } },
    invocations: [{ executionSuccessful: true }],
    results: [] as unknown[],
    properties: {},
  };
  if (scenario === "escaped-location")
    run.results.push({
      ruleId: "organization.prompt",
      level: "warning",
      message: { text: "outside" },
      locations: [{ physicalLocation: { artifactLocation: { uri: "../outside.md" } } }],
    });
  if (scenario === "forged-definition")
    run.properties = { aihDetectorDefinitionV1: { detectorId: "forged" } };
  scanOutput =
    scenario === "malformed" ? "not JSON" : JSON.stringify({ version: "2.1.0", runs: [run] });
  expect(await runDefinedDetectorV1(request(), await definition())).toMatchObject({
    outcome: "failed",
  });
});

it("does not keep a definition result when its declared source changes during execution", async () => {
  scanEffect = () =>
    writeFileSync(join(source, "README.md"), "changed during analyzer execution\n");
  expect(await runDefinedDetectorV1(request(), await definition())).toMatchObject({
    outcome: "failed",
  });
});
