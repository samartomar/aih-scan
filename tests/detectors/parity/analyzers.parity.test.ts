import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  deriveCiscoMcpToolsV1,
  planCiscoMcpScannerRequestV1,
  runCiscoMcpScannerPlanV1,
} from "../../../src/detectors/cisco-mcp-scanner/index.js";
import {
  type CiscoMultiSkillRunResultV1,
  runCiscoSourceTreeScanV1,
} from "../../../src/detectors/cisco-multi-skill/index.js";
import { runSkillspectorScanV1 } from "../../../src/detectors/skillspector-approval/index.js";
import { runSnykAgentScanRequestV1 } from "../../../src/detectors/snyk-agent-scan/index.js";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/index.js";
import { coreMcpConfigPathsV1, coreSelectionV1 } from "../trust-lint/support.js";
import {
  type GoldenRawOccurrenceV1,
  goldenCaseV1,
  materializeCaseV1,
  type ParityCaseV1,
  parityCasesV1,
  placeholderPathV1,
  recordedSnykGoldenV1,
  recordedSnykV1,
  type TranscriptCallV1,
  transcriptV1,
} from "./support.js";

/**
 * Third-party detector parity: W2's recorded analyzer runs replayed through
 * the Scan engines. The injected runner answers each call from the
 * transcript (never invents output) and checks that the engine made the
 * same call Core made: argv with `<root>`/`<tmp>` placeholders, cwd, and the
 * environment keys. The engine's SARIF is then projected to the fields of
 * Core's `rawOccurrences` (ruleId, level, message, uri, startLine) and
 * compared, in order, with the golden for that environment.
 */

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function materialize(parityCase: ParityCaseV1): string {
  const root = materializeCaseV1(parityCase);
  roots.push(root);
  return root;
}

const HOST_ENV = {
  HOME: "/home/parity",
  LANG: "C.UTF-8",
  PATH: "/usr/bin",
  AWS_SECRET_ACCESS_KEY: "must-not-reach-the-analyzer",
};

interface SarifLike {
  readonly runs: readonly Readonly<{
    results?: readonly Readonly<{
      ruleId?: string;
      level?: string;
      message: Readonly<{ text: string }>;
      locations?: readonly Readonly<{
        physicalLocation?: Readonly<{
          artifactLocation?: Readonly<{ uri?: string }>;
          region?: Readonly<{ startLine?: number }>;
        }>;
      }>[];
    }>[];
  }>[];
}

/** The SARIF facts Core records per raw occurrence. */
function occurrences(sarif: SarifLike) {
  return sarif.runs.flatMap((run) =>
    (run.results ?? []).map((result) => ({
      ruleId: result.ruleId,
      level: result.level ?? null,
      message: result.message.text,
      uri: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
      startLine: result.locations?.[0]?.physicalLocation?.region?.startLine ?? 1,
    })),
  );
}

function goldenOccurrences(raw: readonly GoldenRawOccurrenceV1[] | undefined) {
  return (raw ?? []).map((entry) => ({
    ruleId: entry.ruleId,
    level: entry.level,
    message: entry.message,
    uri: entry.uri,
    startLine: entry.startLine,
  }));
}

/** argv with the root and a private temp directory replaced by the transcript placeholders. */
function placeholdered(argv: readonly string[], root: string, tmpPrefix: string): string[] {
  return argv.map((arg) => {
    const forward = arg.replace(/\\/g, "/");
    const rootForward = root.replace(/\\/g, "/");
    if (forward.includes(`/${tmpPrefix}`)) {
      return forward.replace(/^.*\/(aih-[a-z-]+-)[^/]+\//, "<tmp>/$1<random>/");
    }
    return forward.split(rootForward).join("<root>");
  });
}

function withProject(argv: readonly string[], project: string): string[] {
  const index = argv.indexOf("--project");
  return argv.map((arg, position) => (position === index + 1 ? project : arg));
}

function projectOf(argv: readonly string[]): string {
  return argv[argv.indexOf("--project") + 1] ?? "";
}

describe("cisco parity (linux-x64 transcripts, C2a §3)", () => {
  for (const parityCase of parityCasesV1()) {
    const transcript = transcriptV1("linux-x64", parityCase.id, "cisco");
    const golden = goldenCaseV1(parityCase.id).detectors.cisco?.byEnvironment["linux-x64"];
    if (transcript === undefined || golden === undefined) continue;
    it(`replays ${parityCase.id} to Core's ${golden.outcome} outcome`, async () => {
      const root = materialize(parityCase);
      const scans = transcript.calls.filter((call) => call.argv.includes("scan"));
      const version = transcript.calls.find((call) => call.argv.includes("--version"));
      const project = projectOf(version?.argv ?? []);
      const seen: string[] = [];
      const run = async (
        argv: readonly string[],
        options?: Readonly<{ cwd?: string; env?: NodeJS.ProcessEnv }>,
      ): Promise<CiscoMultiSkillRunResultV1> => {
        expect(Object.keys(options?.env ?? {}).sort()).toEqual(["HOME", "LANG", "PATH"]);
        const shown = placeholdered(argv, root, "aih-cisco-sarif-");
        let call: TranscriptCallV1 | undefined;
        if (argv.includes("--version")) call = version;
        else {
          const target = argv[argv.indexOf("scan") + 1] ?? "";
          call = scans.find(
            (entry) =>
              entry.argv[entry.argv.indexOf("scan") + 1] === placeholderPathV1(root, target),
          );
          expect(options?.cwd === undefined ? null : placeholderPathV1(root, options.cwd)).toBe(
            call?.cwd,
          );
          seen.push(placeholderPathV1(root, target));
        }
        if (call === undefined) throw new Error(`no recorded call for ${shown.join(" ")}`);
        expect(shown).toEqual([...call.argv]);
        if (typeof call.outputSarif === "string") {
          writeFileSync(argv[argv.indexOf("--output-sarif") + 1] ?? "", call.outputSarif);
        }
        return {
          code: call.code,
          stdout: call.stdout,
          stderr: call.stderr,
          spawnError: call.spawnError,
          truncated: call.truncated,
        };
      };
      const tree = buildTrustLintTreeV1(root);

      const outcome = await runCiscoSourceTreeScanV1({
        run,
        platform: "linux",
        env: HOST_ENV,
        sourceRoot: root,
        selectedClosurePaths: coreSelectionV1(tree),
        detectorOptions: { concurrency: 1 },
        analyzerProject: project,
      });

      if (golden.outcome === "completed") {
        if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
        expect(seen.sort()).toEqual(
          scans.map((call) => call.argv[call.argv.indexOf("scan") + 1]).sort(),
        );
        expect(occurrences(JSON.parse(outcome.sarifText) as SarifLike)).toEqual(
          goldenOccurrences(golden.rawOccurrences),
        );
      } else if (scans.length === 0) {
        // Core found no SKILL.md directory: the engine refuses before any call.
        expect(outcome).toMatchObject({ kind: "refused", reason: "subject-requirement-unmet" });
        expect(golden.reason).toContain(outcome.kind === "refused" ? outcome.detail : "");
      } else {
        expect(outcome).toMatchObject({ kind: "failed", stage: "execution" });
        const failing = scans.find((call) => call.code !== 0);
        expect(outcome.kind === "failed" ? outcome.detail : "").toContain(
          failing?.stderr.trim().split("\n").at(-1) ?? "",
        );
      }
    });
  }
});

describe("cisco-mcp-scanner parity (linux-x64 transcripts, C2a §4)", () => {
  for (const parityCase of parityCasesV1()) {
    const golden = goldenCaseV1(parityCase.id).detectors["mcp-scanner"]?.byEnvironment["linux-x64"];
    if (golden === undefined) continue;
    const transcript = transcriptV1("linux-x64", parityCase.id, "mcp-scanner");
    it(`replays ${parityCase.id} to Core's ${golden.outcome} outcome`, async () => {
      const root = materialize(parityCase);
      const tree = buildTrustLintTreeV1(root);
      const selectedClosurePaths = coreSelectionV1(tree);
      const mcpConfigPaths = coreMcpConfigPathsV1(root, selectedClosurePaths);
      if (golden.outcome === "not-applicable") {
        // Core sends no request when it declares no config path (§4).
        expect(mcpConfigPaths).toEqual([]);
        return;
      }
      if (transcript === undefined) throw new Error("missing transcript");
      const scan = transcript.calls.find((call) => call.argv.includes("--tools"));
      if (scan === undefined || scan.toolsInput === undefined) throw new Error("no scan call");
      const inputPath = scan.argv[scan.argv.indexOf("--tools") + 1] ?? "";

      const derived = deriveCiscoMcpToolsV1(root, mcpConfigPaths);
      const planned = planCiscoMcpScannerRequestV1({
        root,
        selectedClosurePaths,
        detectorOptions: { mcpConfigPaths },
        platform: "linux",
        env: HOST_ENV,
        inputPath,
      });

      expect(derived.status).toBe("derived");
      if (planned.status !== "planned") throw new Error(JSON.stringify(planned));
      // The tools manifest is byte-identical to the file Core wrote.
      expect(planned.plan.inputBytes).toBe(scan.toolsInput);
      expect(withProject(planned.plan.argv, projectOf(scan.argv))).toEqual([...scan.argv]);
      const outcome = await runCiscoMcpScannerPlanV1(planned.plan, async (argv, options) => {
        expect(argv).toEqual(planned.plan.argv);
        expect(Object.keys(options.env).sort()).toEqual(["HOME", "LANG", "PATH"]);
        return { stdout: scan.stdout, stderr: scan.stderr, exitCode: scan.code };
      });
      if (outcome.status !== "completed") throw new Error(JSON.stringify(outcome));
      expect(occurrences(outcome.sarif)).toEqual(goldenOccurrences(golden.rawOccurrences));
    });
  }
});

describe("skillspector parity (win32-x64 transcripts, C2a §6)", () => {
  for (const parityCase of parityCasesV1()) {
    const transcript = transcriptV1("win32-x64", parityCase.id, "skillspector");
    const golden = goldenCaseV1(parityCase.id).detectors.skillspector?.byEnvironment["win32-x64"];
    if (transcript === undefined || golden === undefined) continue;
    it(`replays ${parityCase.id} to Core's ${golden.outcome} outcome`, async () => {
      const root = materialize(parityCase);
      const version = transcript.calls.find((call) => call.argv.includes("--version"));
      const inspect = transcript.calls.find((call) => call.argv.includes("inspect"));
      const scan = transcript.calls.find((call) => call.argv[1] === "run");
      if (scan === undefined) throw new Error("no recorded docker run");
      const containerName = scan.argv[scan.argv.indexOf("--name") + 1] ?? "";

      const outcome = await runSkillspectorScanV1({
        run: async (argv) => {
          const call = argv.includes("--version")
            ? version
            : argv.includes("inspect")
              ? inspect
              : argv[1] === "run"
                ? scan
                : undefined;
          if (call === undefined) return { code: 0, stdout: "", stderr: "" };
          // Deliberate deviation from legacy Core: the local profile adds
          // `--pull never` after `run` (C2a §6.1 never-pull; review finding P2).
          const expected =
            call === scan
              ? [...call.argv.slice(0, 2), "--pull", "never", ...call.argv.slice(2)]
              : [...call.argv];
          expect(placeholdered(argv, root, "\u0000")).toEqual(expected);
          return {
            code: call.code,
            stdout: call.stdout,
            stderr: call.stderr,
            spawnError: call.spawnError,
            truncated: call.truncated,
          };
        },
        platform: "windows",
        env: HOST_ENV,
        tree: root,
        containerName,
      });

      expect(golden.outcome).toBe("completed");
      if (outcome.status !== "succeeded") throw new Error(JSON.stringify(outcome));
      expect(outcome.image.acceptance).toBe("pinned");
      expect(occurrences(outcome.sarif as SarifLike)).toEqual(
        goldenOccurrences(golden.rawOccurrences),
      );
    });
  }
});

interface RecordedSnykCaseV1 {
  readonly id: string;
  readonly files: Readonly<Record<string, string>>;
  readonly scanExitCode: number;
  readonly report?: unknown;
  readonly scanStdout?: string;
}

interface RecordedSnykGoldenCaseV1 {
  readonly id: string;
  readonly outcome: string;
  readonly reason?: string;
  readonly rawOccurrences: readonly GoldenRawOccurrenceV1[];
}

describe("snyk-agent-scan parity (recorded outputs, C2a §5)", () => {
  const recorded = recordedSnykV1<{ cases: RecordedSnykCaseV1[] }>().cases;
  const goldens = recordedSnykGoldenV1<{ cases: RecordedSnykGoldenCaseV1[] }>().cases;
  for (const recordedCase of recorded) {
    const golden = goldens.find((entry) => entry.id === recordedCase.id);
    it(`replays ${recordedCase.id} to Core's ${golden?.outcome} outcome`, async () => {
      if (golden === undefined) throw new Error("missing golden");
      const root = realpathSync(mkdtempSync(join(tmpdir(), "aih-parity-snyk-")));
      roots.push(root);
      for (const [rel, text] of Object.entries(recordedCase.files)) {
        const target = join(root, ...rel.split("/"));
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, text, "utf8");
      }
      // `<ROOT>` stands for the scan root inside the recorded JSON strings.
      const stdout =
        recordedCase.scanStdout ??
        JSON.stringify(recordedCase.report).split("<ROOT>").join(JSON.stringify(root).slice(1, -1));

      const outcome = await runSnykAgentScanRequestV1(
        async (argv, options) => {
          expect(options.env.SNYK_TOKEN).toBe("recorded-replay-token");
          expect(options.env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
          expect(argv).toContain(root);
          return { code: recordedCase.scanExitCode, stdout, stderr: "" };
        },
        {
          platform: "windows",
          tree: root,
          hostEnv: HOST_ENV,
          requestEnv: { SNYK_TOKEN: "recorded-replay-token" },
        },
      );

      if (golden.outcome === "completed") {
        if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
        expect(occurrences(outcome.sarif)).toEqual(goldenOccurrences(golden.rawOccurrences));
      } else {
        expect(outcome.kind).toBe("failed");
        // Scan's detail is Core's fixed message plus the exit status and output byte
        // counts; the analyzer's own text never reaches it.
        const detail = outcome.kind === "failed" ? outcome.detail : "";
        const coreMessage = detail.replace(/; exit \S+, stdout \d+ bytes, stderr \d+ bytes$/, "");
        expect(coreMessage).not.toBe(detail);
        expect(golden.reason).toContain(`(${coreMessage})`);
      }
    });
  }
});
