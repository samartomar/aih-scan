import { existsSync, statSync } from "node:fs";
import { createConnection } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
// The publisher runs this module directly under Node.
import { startAdaptiveSsd } from "../../tools/publisher/adaptive-ssd.mjs";

type Input = { key: string; document: string };
type Finding = {
  rule_id: string;
  message: string;
  severity: string;
  start_line: number;
};
type Output = { result?: { findings: Finding[] }; error?: string };
const closures: (() => Promise<void>)[] = [];
const decode = (prompt: string): Input[] => JSON.parse(prompt.split("\n\n").at(-1) ?? "[]");
const result = (key: string, findings: Finding[] = []) => ({ key, result: { findings } });
const finding = (start_line: number) => ({
  rule_id: "SSD-3",
  message: "A fixture-only privacy finding",
  severity: "HIGH",
  start_line,
});

function request(
  socketPath: string,
  document: string,
  startLine = 1,
  timeoutMs = 10_000,
): Promise<Output> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let output = "";
    socket.setEncoding("utf8");
    socket.once("connect", () => {
      socket.write(
        `${JSON.stringify({
          profile: "adaptive-ssd/1",
          instructions: "Trusted detector instructions",
          schema: { type: "object" },
          document,
          lines: 1,
          startLine,
          timeoutMs,
        })}\n`,
      );
    });
    socket.on("data", (chunk: string) => {
      output += chunk;
    });
    socket.on("error", reject);
    socket.on("end", () => {
      if (!output) resolve({ error: "closed" });
      else resolve(JSON.parse(output));
    });
  });
}

afterEach(async () => {
  await Promise.all(closures.splice(0).map((close) => close()));
});

describe.skipIf(process.platform === "win32")("adaptive SSD trusted broker", () => {
  it("groups native jobs and confirms the positive reply against its original input", async () => {
    const prompts: string[] = [];
    const broker = await startAdaptiveSsd({
      batchDelayMs: 100,
      async infer(prompt: string) {
        prompts.push(prompt);
        return JSON.stringify({
          items: decode(prompt)
            .reverse()
            .map(({ key, document }) =>
              result(key, document.includes("positive fixture") ? [finding(17)] : []),
            ),
        });
      },
    });
    closures.push(broker.close);
    expect(statSync(broker.socketPath).mode & 0o777).toBe(0o600);
    expect(
      await Promise.all([
        request(broker.socketPath, "SKILL.md positive fixture", 17),
        request(broker.socketPath, "SKILL.md clean fixture", 19),
      ]),
    ).toEqual([{ result: { findings: [finding(17)] } }, { result: { findings: [] } }]);
    expect(prompts.map((prompt) => decode(prompt).map(({ document }) => document))).toEqual([
      ["SKILL.md positive fixture", "SKILL.md clean fixture"],
      ["SKILL.md positive fixture"],
    ]);
    expect(broker.stats()).toEqual({
      submittedTasks: 2,
      validatedTasks: 2,
      failedTasks: 0,
      modelRequests: 2,
      multiItemRequests: 1,
      maxBatchWidth: 2,
    });
    await broker.close();
    expect(existsSync(broker.socketPath)).toBe(false);
  });

  it("splits a ready pack on output reservation and rejects an oversized singleton before inference", async () => {
    const widths: number[] = [];
    const broker = await startAdaptiveSsd({
      contextTokens: 6_000,
      outputTokens: 800,
      batchDelayMs: 75,
      async infer(prompt: string) {
        const inputs = decode(prompt);
        widths.push(inputs.length);
        return JSON.stringify({ items: inputs.map(({ key }) => result(key)) });
      },
    });
    closures.push(broker.close);
    const responses = await Promise.all([
      request(broker.socketPath, "clean A"),
      request(broker.socketPath, "clean B"),
      request(broker.socketPath, "x".repeat(7_000)),
    ]);
    expect(responses).toEqual([
      { result: { findings: [] } },
      { result: { findings: [] } },
      { error: "input-budget" },
    ]);
    expect(widths).toEqual([1, 1]);
  });

  it("reconciles missing and invalid native results without redoing attributable results", async () => {
    const calls: string[][] = [];
    const broker = await startAdaptiveSsd({
      batchDelayMs: 75,
      async infer(prompt: string) {
        const inputs = decode(prompt);
        calls.push(inputs.map((input) => input.document));
        if (calls.length === 1) {
          const clean = inputs.find((input) => input.document === "clean");
          const bad = inputs.find((input) => input.document === "invalid");
          return JSON.stringify({
            items: [result(clean?.key ?? ""), result(bad?.key ?? "", [finding(900)])],
          });
        }
        return JSON.stringify({ items: inputs.map(({ key }) => result(key)) });
      },
    });
    closures.push(broker.close);
    const responses = await Promise.all(
      ["clean", "invalid", "missing"].map((document) => request(broker.socketPath, document)),
    );
    expect(responses).toEqual(Array.from({ length: 3 }, () => ({ result: { findings: [] } })));
    expect(calls[0]).toHaveLength(3);
    expect(calls.slice(1).flat().sort()).toEqual(["invalid", "missing"]);
  });

  it("discards ambiguous association and does not split or resend transport failures", async () => {
    let calls = 0;
    const broker = await startAdaptiveSsd({
      batchDelayMs: 75,
      async infer(prompt: string) {
        calls++;
        const [first] = decode(prompt);
        if (calls === 1 && first) {
          return `{"items":[{"key":${JSON.stringify(first.key)},"key":"other","result":{"findings":[]}}]}`;
        }
        throw new Error("fixture transport failure");
      },
    });
    closures.push(broker.close);
    const responses = await Promise.all([
      request(broker.socketPath, "A"),
      request(broker.socketPath, "B"),
    ]);
    expect(responses).toEqual([{ error: "inference-failed" }, { error: "inference-failed" }]);
    expect(calls).toBe(3);
  });
  it("scopes a classified quota refusal to the affected provider request", async () => {
    const broker = await startAdaptiveSsd({
      batchDelayMs: 75,
      async infer(prompt: string) {
        const rows = decode(prompt);
        if (rows.some(({ document }) => document === "quota-a"))
          throw Object.assign(new Error("private provider detail"), { code: "kimi-quota-refusal" });
        return JSON.stringify({ items: rows.map(({ key }) => result(key)) });
      },
    });
    closures.push(broker.close);
    await expect(
      Promise.all([request(broker.socketPath, "quota-a"), request(broker.socketPath, "quota-b")]),
    ).resolves.toEqual([{ error: "quota-refused" }, { error: "quota-refused" }]);
    await expect(request(broker.socketPath, "unaffected")).resolves.toEqual({
      result: { findings: [] },
    });
    expect(broker.stats()).toMatchObject({ modelRequests: 2, failedTasks: 2, validatedTasks: 1 });
  });

  it("expires only the short-lived task and cancels inference once all tasks expire", async () => {
    let release: (() => void) | undefined;
    let sharedSignal: AbortSignal | undefined;
    let observeAbort: (() => void) | undefined;
    const aborted = new Promise<void>((resolve) => {
      observeAbort = resolve;
    });
    const broker = await startAdaptiveSsd({
      batchDelayMs: 10,
      async infer(prompt, signal) {
        const rows = decode(prompt);
        sharedSignal = signal;
        await new Promise<void>((resolve, reject) => {
          release = resolve;
          signal.addEventListener(
            "abort",
            () => {
              observeAbort?.();
              reject(signal.reason);
            },
            { once: true },
          );
        });
        return JSON.stringify({ items: rows.map(({ key }) => result(key)) });
      },
    });
    closures.push(broker.close);
    const [short, long] = [
      request(broker.socketPath, "short", 1, 100),
      request(broker.socketPath, "long", 1, 10_000),
    ];
    await expect(short).resolves.toEqual({ error: "deadline-expired" });
    expect(sharedSignal?.aborted).toBe(false);
    release?.();
    await expect(long).resolves.toEqual({ result: { findings: [] } });
    await expect(request(broker.socketPath, "alone", 1, 100)).resolves.toEqual({
      error: "deadline-expired",
    });
    await aborted;
    expect(sharedSignal?.aborted).toBe(true);
    expect(broker.stats()).toMatchObject({ modelRequests: 2, maxBatchWidth: 2 });
  });

  it("reconciles an explicit output limit only by shrinking the group", async () => {
    const widths: number[] = [];
    const broker = await startAdaptiveSsd({
      batchDelayMs: 75,
      async infer(prompt) {
        const rows = decode(prompt);
        widths.push(rows.length);
        if (rows.length > 1 || rows.some(({ document }) => document === "too-verbose"))
          throw Object.assign(new Error("Kimi response limit"), { code: "kimi-output-limit" });
        return JSON.stringify({ items: rows.map(({ key }) => result(key)) });
      },
    });
    closures.push(broker.close);
    await expect(
      Promise.all([
        request(broker.socketPath, "normal"),
        request(broker.socketPath, "too-verbose"),
      ]),
    ).resolves.toEqual([{ result: { findings: [] } }, { error: "invalid-output" }]);
    expect(widths).toEqual([2, 1, 1]);
  });
});
