import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  exitCodes,
  runFindingsCommand,
  runReadCommand,
  runScanCommandV1,
} from "../../src/cli/commands-v1.js";
import { corpusRoot } from "../support/scan-v1-corpus.js";
import {
  cleanSkill,
  type FixtureRoot,
  fixtureRoot,
  riskySkill,
} from "../support/scan-v1-fixture.js";

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-cli-");
});
afterEach(() => fixture.dispose());

function capture(cancellation?: AbortSignal) {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (t: string) => void out.push(t),
      stderr: (t: string) => void err.push(t),
      cwd: fixture.root,
      ...(cancellation ? { cancellation } : {}),
    },
    out: () => out.join(""),
    err: () => err.join(""),
  };
}

/** Copies a committed corpus case into the fixture root so the CLI reads only disposable files. */
function corpus(name: string): string {
  const target = fixture.path("corpus", name);
  mkdirSync(join(target, ".."), { recursive: true });
  cpSync(join(corpusRoot, name), target, { recursive: true });
  return join(target, "summary.json");
}

describe("aih-scan read and findings over complete summary/SARIF fixtures", () => {
  it("prints a summary with its coverage-adjusted label and returns 0, or 1 only with --fail-at", () => {
    const summary = corpus("clean");
    const plain = capture();
    expect(runReadCommand([summary], plain.io)).toBe(exitCodes.ok);
    expect(plain.out()).toContain("CAUTION (partial)  score 0");
    expect(plain.out()).toContain("skillspector 2.13.2 static: not-run (unavailable)");
    expect(runReadCommand([summary, "--fail-at", "CAUTION"], capture().io)).toBe(exitCodes.failAt);
    expect(runReadCommand([summary, "--fail-at", "DO_NOT_INSTALL"], capture().io)).toBe(
      exitCodes.ok,
    );
    const json = capture();
    expect(runReadCommand([summary, "--json"], json.io)).toBe(0);
    expect(JSON.parse(json.out())).toMatchObject({
      format: "aih-scan-summary/1",
      label: "CAUTION",
    });
  });

  it("never lets NOT ASSESSED meet a threshold", () => {
    expect(runReadCommand([corpus("not-assessed"), "--fail-at", "CAUTION"], capture().io)).toBe(
      exitCodes.ok,
    );
  });

  it("exits 2 for malformed and unsupported summaries", () => {
    const bad = fixture.path("bad.json");
    writeFileSync(bad, "{");
    const malformed = capture();
    expect(runReadCommand([bad], malformed.io)).toBe(exitCodes.input);
    expect(malformed.err()).toContain("summary invalid");
    const summary = corpus("clean");
    const document = JSON.parse(readFileSync(summary, "utf8"));
    writeFileSync(bad, JSON.stringify({ ...document, format: "aih-scan-summary/2" }));
    const unsupported = capture();
    expect(runReadCommand([bad], unsupported.io)).toBe(exitCodes.input);
    expect(unsupported.err()).toContain("unsupported-version");
    expect(runReadCommand([], capture().io)).toBe(exitCodes.input);
  });

  it("prints one line per finding for the summary's key and only the mismatch message otherwise", async () => {
    const summary = corpus("risky");
    const key = JSON.parse(readFileSync(summary, "utf8")).scanKey;
    const ok = capture();
    expect(await runFindingsCommand([summary, "--key", key], ok.io)).toBe(exitCodes.ok);
    expect(ok.out()).toMatch(
      /^HIGH {5}trust\.prompt-injection {2}SKILL\.md:7 {2}\[aih-trust-lint trust\.prompt-injection\]/m,
    );
    expect(ok.out()).toContain("trust.malicious-code  hooks/hooks.json:4");
    const wrong = capture();
    expect(
      await runFindingsCommand([summary, "--key", `git-sha1:${"0".repeat(40)}`], wrong.io),
    ).toBe(exitCodes.input);
    expect(wrong.err()).toBe("aih-scan: Findings don't match this scan\n");
    expect(wrong.out()).toBe("");
    expect(await runFindingsCommand([summary], capture().io)).toBe(exitCodes.input);
  });
});

describe("aih-scan scan", () => {
  it("scans folders into a new --out folder, and the result reads back through read/findings", async () => {
    const risky = fixture.folder("risky", riskySkill);
    const run = capture();
    expect(await runScanCommandV1([risky, "--out", "out"], run.io)).toBe(exitCodes.ok);
    expect(run.out()).toContain("score 46");
    const json = capture();
    expect(await runScanCommandV1([risky, "--out", "out2", "--json"], json.io)).toBe(0);
    const result = JSON.parse(json.out());
    // A folder is the source route: the root SKILL.md makes the whole folder one skill.
    expect(result).toMatchObject({
      status: "ok",
      targets: [
        {
          target: risky,
          status: "ok",
          acquisition: { type: "folder", fetched: false },
          results: [
            {
              status: "ok",
              kind: "skill",
              path: ".",
              source: { type: "folder", path: risky, item: "." },
            },
          ],
          rollup: { label: "CAUTION", items: 1 },
        },
      ],
    });
    const entry = result.targets[0].results[0];
    const findings = capture();
    expect(await runFindingsCommand([entry.summaryPath, "--key", entry.scanKey], findings.io)).toBe(
      0,
    );
    expect(findings.out()).toContain("trust.prompt-injection");
  });

  it("implements exits 0/1/2/130 and opt-in --fail-at against the stored label", async () => {
    const clean = fixture.folder("clean", cleanSkill);
    // Score 0 with partial coverage (SkillSpector unavailable) is stored CAUTION.
    expect(await runScanCommandV1([clean, "--out", "o1", "--quiet"], capture().io)).toBe(
      exitCodes.ok,
    );
    expect(
      await runScanCommandV1(
        [clean, "--out", "o2", "--quiet", "--fail-at", "CAUTION"],
        capture().io,
      ),
    ).toBe(exitCodes.failAt);
    expect(
      await runScanCommandV1(
        [clean, "--out", "o3", "--quiet", "--fail-at", "DO_NOT_INSTALL"],
        capture().io,
      ),
    ).toBe(exitCodes.ok);
    // The output folder must be new.
    expect(await runScanCommandV1([clean, "--out", "o1", "--quiet"], capture().io)).toBe(
      exitCodes.input,
    );
    // One unreadable folder: exit 2, the other is still written.
    const missing = fixture.path("missing");
    const several = capture();
    expect(await runScanCommandV1([missing, clean, "--out", "o4", "--json"], several.io)).toBe(
      exitCodes.input,
    );
    expect(
      JSON.parse(several.out()).targets.map((entry: { status: string }) => entry.status),
    ).toEqual(["refused", "ok"]);
    // Bad usage.
    expect(await runScanCommandV1([clean], capture().io)).toBe(exitCodes.input);
    expect(await runScanCommandV1([clean, "--out", "o5", "--tools", "semgrep"], capture().io)).toBe(
      exitCodes.input,
    );
    expect(await runScanCommandV1([clean, "--out", "o5", "--fail-at", "SAFE"], capture().io)).toBe(
      exitCodes.input,
    );
    // Cancelled before anything finished.
    const controller = new AbortController();
    controller.abort();
    const cancelled = capture(controller.signal);
    expect(await runScanCommandV1([clean, "--out", "o6"], cancelled.io)).toBe(exitCodes.cancelled);
  });

  it("sanitizes untrusted text in terminal output", async () => {
    const folder = fixture.folder("item‮name", { "SKILL.md": "# x\n" });
    const run = capture();
    await runScanCommandV1([folder, "--out", "o"], run.io);
    expect(run.out()).not.toContain("‮");
  });
});

describe("coverage-adjusted stored label through the CLI", () => {
  it("score 8 with partial coverage is stored CAUTION, shown CAUTION (partial), exits 1 only at --fail-at CAUTION", async () => {
    const { scanWith } = await import("../../src/host/scan.js");
    const item = fixture.folder("eight", { "run.sh": "echo calm\n" });
    const finding = {
      ruleId: "X1",
      message: "risky",
      path: "run.sh",
      line: 1,
      part: "code",
      severity: "MEDIUM",
      confidence: 0.6,
    };
    const result = await scanWith(
      { format: "aih-scan-request/1", origin: "local", items: [{ path: item }] },
      { outDir: fixture.path("eight-out") },
      {
        adapters: {
          skillspector: {
            id: "skillspector",
            version: "2.13.2",
            run: async () => ({
              status: "ran",
              version: "2.13.2",
              mode: "static",
              findings: [finding],
            }),
          },
          "aih-trust-lint": {
            id: "aih-trust-lint",
            version: "1.0.0",
            run: async () => ({
              status: "not-run",
              version: "1.0.0",
              mode: "static",
              reason: "failed",
            }),
          },
        } as never,
      },
    );
    const entry = result.results[0];
    if (entry?.status !== "ok") throw new Error(JSON.stringify(result));
    const summary = JSON.parse(readFileSync(entry.summaryPath, "utf8"));
    expect(summary).toMatchObject({
      score: 8,
      label: "CAUTION",
      coverage: "partial",
      reason: "failed",
    });
    const shown = capture();
    expect(runReadCommand([entry.summaryPath], shown.io)).toBe(exitCodes.ok);
    expect(shown.out()).toMatch(/^CAUTION \(partial\) {2}score 8/);
    expect(runReadCommand([entry.summaryPath, "--fail-at", "CAUTION"], capture().io)).toBe(
      exitCodes.failAt,
    );
  });
});
