import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/** A synthetic inference service: real SkillSpector parses these fixed responses; no model runs. */
export async function compatibleAiServiceV1() {
  const requests: Record<string, unknown>[] = [];
  let outcome: "complete" | "malformed" | "quota" = "complete";
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    if (request.method !== "POST" || request.url !== "/chat/completions") {
      response.writeHead(404).end();
      return;
    }
    const payload = JSON.parse(body) as Record<string, unknown>;
    requests.push(payload);
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
            finish_reason: "tool_calls",
            message: {
              role: "assistant",
              content: null,
              tool_calls: [
                {
                  id: "call-fixture",
                  type: "function",
                  function: {
                    name: choice?.function?.name ?? "LLMAnalysisResult",
                    arguments: outcome === "malformed" ? "{" : '{"findings":[]}',
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
