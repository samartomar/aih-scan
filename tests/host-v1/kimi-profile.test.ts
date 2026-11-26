import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { inferAdaptiveSsd } from "../../src/host/kimi-inference.js";

const roots: string[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(model: string, reply = true) {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-kimi-profile-"));
  roots.push(root);
  vi.stubEnv("PATH", root);
  vi.stubEnv("KIMI_CODE_HOME", root);
  vi.stubEnv("AIH_SCAN_KIMI_REGION", "global");
  writeFileSync(
    join(root, "kimi"),
    `#!${process.execPath}
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";
assert.equal(process.argv[2], "acp");
const config = readFileSync(join(process.env.KIMI_CODE_HOME, "config.toml"), "utf8");
assert.ok(config.includes('default_model = "kimi-code/k3"'));
assert.ok(config.includes('model = "k3"'));
assert.ok(config.includes('effort = "max"'));
assert.ok(config.includes('enabled = ["*"]'));
const emit = (event) => console.log(JSON.stringify({ jsonrpc: "2.0", ...event }));
for await (const line of createInterface({ input: process.stdin })) {
  const { id, method, params } = JSON.parse(line);
  if (method === "initialize") {
    emit({ id, result: { protocolVersion: 1, agentInfo: { version: "2.7.2" } } });
  } else if (method === "session/new") {
    assert.deepEqual(params.mcpServers, []);
    emit({ id, result: { sessionId: "fixture", configOptions: [
      { id: "model", currentValue: ${JSON.stringify(model)} },
      { id: "thinking", currentValue: "max" },
    ] } });
  } else if (method === "session/prompt") {
    assert.equal(params.sessionId, "fixture");
    assert.deepEqual(params.prompt, [{ type: "text", text: "synthetic detector prompt" }]);
    if (!${reply}) continue;
    emit({ method: "session/update", params: { sessionId: "fixture", update: {
      sessionUpdate: "agent_message_chunk", content: { type: "text", text: JSON.stringify({ findings: [] }) },
    } } });
    emit({ id, result: { stopReason: "end_turn" } });
  } else assert.fail("unexpected ACP method");
}
`,
    { mode: 0o700 },
  );
  return root;
}

it.skipIf(process.platform === "win32")(
  "uses an isolated K3/max ACP session and rejects a substituted model",
  async () => {
    const prompt = "synthetic detector prompt";
    const signal = new AbortController().signal;
    await expect(inferAdaptiveSsd(prompt, signal, fixture("kimi-code/k3"))).resolves.toBe(
      '{"findings":[]}',
    );
    await expect(
      inferAdaptiveSsd(prompt, signal, fixture("kimi-code/kimi-for-coding")),
    ).rejects.toThrow("selected model and effort");
  },
);

it.skipIf(process.platform === "win32")("cancels a pending adaptive ACP request", async () => {
  const controller = new AbortController();
  const scratch = fixture("kimi-code/k3", false);
  const request = inferAdaptiveSsd("synthetic detector prompt", controller.signal, scratch);
  const timer = setTimeout(() => controller.abort(), 200);
  try {
    await expect(request).rejects.toThrow("cancelled");
  } finally {
    clearTimeout(timer);
  }
});
