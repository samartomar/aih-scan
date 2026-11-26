import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { expect, it } from "vitest";
import { scanWith } from "../../src/host/scan.js";
import { readSummary } from "../../src/public/read.js";
import { compatibleAiServiceV1 } from "../support/compatible-ai-service-v1.js";
import { fixtureRoot, readBytes } from "../support/scan-v1-fixture.js";

const analyzer = process.env.AIH_SCAN_TEST_SKILLSPECTOR;

it.runIf(analyzer !== undefined)(
  "checks the paired Python runtime version before opening any provider connection",
  async () => {
    if (!analyzer) throw new Error("Fixture needs the locked SkillSpector executable");
    const fixture = fixtureRoot("scan-provider-version-");
    const service = await compatibleAiServiceV1();
    try {
      const python = join(
        dirname(analyzer),
        process.platform === "win32" ? "python.exe" : "python",
      );
      const bridge = resolve(import.meta.dirname, "../../runtime/provider-batching.py");
      const result = spawnSync(
        python,
        ["-I", bridge, "2.13.7+mismatch", analyzer, "scan", fixture.root],
        {
          cwd: fixture.root,
          env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            SKILLSPECTOR_PROVIDER: "openai_compatible",
            SKILLSPECTOR_COMPAT_BASE_URL: service.endpoint,
            SKILLSPECTOR_COMPAT_API_KEY: "fixture-only-not-a-real-key",
          },
          timeout: 15_000,
          windowsHide: true,
        },
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(2);
      expect(existsSync(fixture.path("aih-scan-python-version-mismatch"))).toBe(true);
      expect(service.requests).toHaveLength(0);
    } finally {
      await service.close();
      fixture.dispose();
    }
  },
);

it.runIf(analyzer !== undefined)(
  "refuses unknown limits before inference and applies the declared output budget to ordinary requests",
  async () => {
    const fixture = fixtureRoot("scan-provider-controls-");
    const service = await compatibleAiServiceV1({ attributedFindings: true, ambiguousGroup: true });
    try {
      const item = fixture.folder("item", {
        "SKILL.md":
          "---\nname: notes\ndescription: Summarises notes.\n---\n# Notes\nalpha-fixture\n",
        "notes/detail.md": "# Detail\nSummarise beta-fixture.\n",
      });
      const registry = fixture.path("registry.json");
      async function run(output?: number, name?: string) {
        service.setOutcome("complete");
        if (output !== undefined)
          writeFileSync(
            registry,
            JSON.stringify({
              models: {
                "opaque-fixture-model": { context_length: 65536, max_output_tokens: output },
              },
            }),
          );
        const report = await scanWith(
          { format: "aih-scan-request/1", origin: "local", mode: "ai", items: [{ path: item }] },
          { outDir: fixture.path(`out-${name ?? output ?? "unknown"}`) },
          {
            env: {
              PATH: process.env.PATH,
              SystemRoot: process.env.SystemRoot,
              AIH_SCAN_SKILL_SCANNER: "none",
              AIH_SCAN_SKILLSPECTOR: analyzer,
              SKILLSPECTOR_PROVIDER: "openai_compatible",
              SKILLSPECTOR_COMPAT_BASE_URL: service.endpoint,
              SKILLSPECTOR_COMPAT_API_KEY: "fixture-only-not-a-real-key",
              SKILLSPECTOR_MODEL: "opaque-fixture-model",
              SKILLSPECTOR_REASONING_EFFORT: "none",
              SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD: "function_calling",
              AIH_SCAN_BATCH_PORT: "1",
              AIH_SCAN_BATCH_TOKEN: "a".repeat(64),
              ...(output === undefined ? {} : { SKILLSPECTOR_MODEL_REGISTRY: registry }),
            },
          },
        );
        const entry = report.results[0];
        if (entry?.status !== "ok") throw new Error(JSON.stringify(entry));
        const checked = readSummary(readBytes(entry.summaryPath));
        if (checked.status !== "ok") throw new Error(JSON.stringify(checked));
        return { entry, summary: checked.summary };
      }

      const unknown = await run();
      expect(service.requests).toHaveLength(0);
      expect(unknown.summary.coverage).toBe("partial");
      expect(unknown.summary.tools).toContainEqual(
        expect.objectContaining({
          tool: "skillspector",
          mode: "static",
        }),
      );
      expect(unknown.entry.notes?.join("\n")).toContain("SKILLSPECTOR_MODEL_REGISTRY");

      const narrow = await run(420);
      expect(narrow.summary.coverage, JSON.stringify(narrow.entry.notes)).toBe("complete");
      const ssd = () =>
        service.requests.filter((request) =>
          JSON.stringify(request.messages).includes("intent and attack-phrasing risks"),
        );
      expect(ssd()).toHaveLength(2);
      for (const request of ssd()) expect(request.max_completion_tokens).toBe(420);
      expect(JSON.stringify(ssd())).not.toContain("GroupedResponse");

      // The fake service duplicates a key in the grouped response. Scan obtains
      // independent native results and never assigns that ambiguous response.
      const recovered = await run(8192);
      expect(recovered.summary.coverage, JSON.stringify(recovered.entry.notes)).toBe("complete");
      const requests = ssd();
      expect(requests).toHaveLength(3);
      expect(requests[0]?.tool_choice).toMatchObject({ function: { name: "GroupedResponse" } });
      expect(requests.slice(1).map((request) => request.tool_choice)).toEqual([
        expect.objectContaining({ function: { name: "LLMAnalysisResult" } }),
        expect.objectContaining({ function: { name: "LLMAnalysisResult" } }),
      ]);
      expect(
        recovered.summary.tools.find((tool) => tool.tool === "skillspector")?.counts?.high,
      ).toBe(1);

      service.setGrouping("context");
      const split = await run(8192, "provider-context-refusal");
      expect(split.summary.coverage, JSON.stringify(split.entry.notes)).toBe("complete");
      const rejectedGroup = ssd();
      expect(rejectedGroup).toHaveLength(3);
      expect(rejectedGroup[0]?.tool_choice).toMatchObject({
        function: { name: "GroupedResponse" },
      });
      expect(rejectedGroup.slice(1).map((request) => request.tool_choice)).toEqual([
        expect.objectContaining({ function: { name: "LLMAnalysisResult" } }),
        expect.objectContaining({ function: { name: "LLMAnalysisResult" } }),
      ]);
    } finally {
      await service.close();
      fixture.dispose();
    }
  },
  90_000,
);
