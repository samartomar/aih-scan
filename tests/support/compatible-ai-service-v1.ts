import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/** A synthetic inference service: real SkillSpector parses these fixed responses; no model runs. */
export async function compatibleAiServiceV1(
  options: {
    delayMs?: number;
    tp4Mismatch?: boolean;
    attributedFindings?: boolean;
    ambiguousGroup?: boolean;
  } = {},
) {
  const requests: Record<string, unknown>[] = [];
  let outcome:
    | "complete"
    | "repaired"
    | "recovered"
    | "malformed"
    | "refused"
    | "quota"
    | "unfinished" = "complete";
  let securityInitial = 0;
  let grouping = options.ambiguousGroup ? "ambiguous" : "complete";
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
    const prompt = JSON.stringify(payload.messages);
    const content = (payload.messages as { content: string }[]).at(-1)?.content ?? "";
    const grouped = content.split("\nAIH_SCAN_TASKS\n")[1]?.split("\n")[0];
    if (grouped && grouping === "context") {
      response.writeHead(400).end(
        JSON.stringify({
          error: { message: "fixture request exceeded context", code: "context_length_exceeded" },
        }),
      );
      return;
    }
    const resultFor = (input: string) => {
      if (input.includes("Determine whether a skill"))
        return {
          is_mismatch: options.tp4Mismatch ?? false,
          confidence: 0.9,
          declared_purpose_summary: "Calculations",
          actual_behavior_summary: "Network",
          mismatched_capabilities: [body.slice(-180)],
          explanation: body.slice(-180),
        };
      if (options.attributedFindings && semantic && input.includes("alpha-fixture"))
        return {
          findings: [
            {
              rule_id: "SSD-1",
              message: grouped ? "cross-key prose sentinel" : "Alpha fixture finding",
              severity: "HIGH",
              start_line: 6,
              end_line: 6,
              confidence: 0.8,
              explanation: "Alpha evidence",
              remediation: "Review the alpha text",
            },
          ],
        };
      return { findings: [] };
    };
    const recoveryField = prompt.match(/Requested field: ([a-z_]+)/)?.[1];
    const message: Record<string, unknown> = { role: "assistant", content: null };
    if (outcome === "recovered" && semantic && recoveryField) {
      const answers: Record<string, string> = {
        finding_count: "1",
        rule_id: "SSD-1",
        severity: "HIGH",
        message: "UNKNOWN",
        start_line: "1",
        end_line: "1",
        confidence: "0.8",
        explanation: "UNKNOWN",
        remediation: "UNKNOWN",
      };
      message.content = answers[recoveryField] ?? "UNKNOWN";
    } else {
      if (semantic) securityInitial += 1;
      const args =
        outcome === "malformed" && semantic
          ? "{"
          : outcome === "repaired" && semantic && securityInitial === 1
            ? '{"findings":[],}'
            : outcome === "recovered" && semantic && securityInitial === 1
              ? JSON.stringify({
                  findings: { rule_id: "SSD-1", severity: "HIGH", start_line: 1 },
                })
              : JSON.stringify(
                  grouped
                    ? {
                        items: (JSON.parse(grouped) as { key: string; prompt: string }[])
                          .reverse()
                          .map(({ key, prompt }) => ({
                            key: grouping === "ambiguous" ? "t0" : key,
                            result: resultFor(prompt),
                          })),
                      }
                    : resultFor(content),
                );
      message.tool_calls = [
        {
          id: "call-fixture",
          type: "function",
          function: { name: choice?.function?.name ?? "LLMAnalysisResult", arguments: args },
        },
      ];
    }
    response.end(
      JSON.stringify({
        id: "chatcmpl-fixture",
        object: "chat.completion",
        created: 1793750400,
        model: payload.model,
        choices: [
          {
            index: 0,
            finish_reason:
              outcome === "unfinished"
                ? "length"
                : outcome === "refused"
                  ? "content_filter"
                  : message.tool_calls
                    ? "tool_calls"
                    : "stop",
            message,
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
      securityInitial = 0;
      requests.length = 0;
    },
    setGrouping(value: "ambiguous" | "complete" | "context") {
      grouping = value;
    },
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
