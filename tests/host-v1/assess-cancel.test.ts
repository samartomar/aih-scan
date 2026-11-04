import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { assessItem, routeFiles } from "../../src/host/assess.js";
import type { ToolAdapter } from "../../src/host/tools.js";

it("keeps the actual version when a completed adapter races with cancellation", async () => {
  const controller = new AbortController();
  const bytes = new TextEncoder().encode("# Skill\nSummarise local text.\n");
  const files = [
    {
      path: "SKILL.md",
      mode: "100644" as const,
      bytes,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
  ];
  const adapter: ToolAdapter = {
    id: "skillspector",
    version: "expected-version",
    run: () => {
      // Abort after the adapter promise settles, before the assessment continuation.
      queueMicrotask(() => queueMicrotask(() => controller.abort()));
      return Promise.resolve({
        status: "ran",
        version: "actual-version",
        mode: "static",
        findings: [],
      });
    },
  };
  const result = await assessItem(
    {
      scanKey: `git-sha1:${"0".repeat(40)}`,
      files,
      routed: routeFiles(files),
      snapshotRoot: "/unused",
    },
    new Map([["skillspector", adapter]]),
    {
      origin: "local",
      mode: "static",
      tools: ["skillspector"],
      internalScopes: [],
      signal: controller.signal,
      now: () => new Date("2026-11-04T00:00:00Z"),
      timeoutMs: 1000,
    },
  );
  expect(result.summary.tools.find((tool) => tool.tool === "skillspector")).toMatchObject({
    version: "actual-version",
    result: "not-run",
    reason: "cancelled",
  });
});
