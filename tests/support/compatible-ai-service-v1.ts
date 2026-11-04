import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/** A synthetic inference service: real SkillSpector parses these fixed responses; no model runs. */
export async function compatibleAiServiceV1(
  options: { delayMs?: number; tp4Mismatch?: boolean } = {},
) {
  const requests: Record<string, unknown>[] = [];
  let outcome: "complete" | "malformed" | "quota" | "unfinished" = "complete";
  const security = { started: 0, completed: 0, active: 0, maxActive: 0 };
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    if (request.method !== "POST" || request.url !== "/chat/completions") {
      response.writeHead(404).end();
      return;
    }
    const payload = JSON.parse(body) as Record<string, unknown>;
    requests.push(payload);
    const semantic = JSON.stringify(payload.messages).includes("intent and attack-phrasing risks");
    if (semantic) {
      security.started++;
      security.active++;
      security.maxActive = Math.max(security.maxActive, security.active);
    }
    if (options.delayMs) await new Promise((resolve) => setTimeout(resolve, options.delayMs));
    if (semantic) {
      security.active--;
      security.completed++;
    }
    response.setHeader("Content-Type", "application/json");
    if (outcome === "quota") {
      response.writeHead(402).end(
        JSON.stringify({
          error: { message: "Fixture quota exhausted", type: "insufficient_quota" },
        }),
      );
      return;
    }
    const choice = payload.tool_choice as { function?: { name?: string } } | undefined;
    response.end(
      JSON.stringify({
        id: "chatcmpl-fixture",
        object: "chat.completion",
        created: 1793750400,
        model: "deepseek-flash",
        choices: [
          {
            index: 0,
            finish_reason: outcome === "unfinished" ? "length" : "tool_calls",
            message: {
              role: "assistant",
              content: null,
              tool_calls: [
                {
                  id: "call-fixture",
                  type: "function",
                  function: {
                    name: choice?.function?.name ?? "LLMAnalysisResult",
                    arguments:
                      outcome === "malformed"
                        ? "{"
                        : JSON.stringify(
                            JSON.stringify(payload.messages).includes("Determine whether a skill")
                              ? {
                                  is_mismatch: options.tp4Mismatch ?? false,
                                  confidence: 0.9,
                                  declared_purpose_summary: "Calculations",
                                  actual_behavior_summary: "Network",
                                  mismatched_capabilities: [body.slice(-180)],
                                  explanation: body.slice(-180),
                                }
                              : { findings: [] },
                          ),
                  },
                },
              ],
            },
          },
        ],
        usage: { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 },
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    endpoint: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    requests,
    security,
    setOutcome(value: typeof outcome) {
      outcome = value;
      requests.length = 0;
    },
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
