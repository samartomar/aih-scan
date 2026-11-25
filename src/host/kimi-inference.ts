import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

export const KIMI_VERSION = "2.7.2";
export const KIMI_MODEL = "kimi-for-coding";
export const KIMI_EFFORTS = Object.freeze(["low", "high", "max"] as const);
const managedAlias = "kimi-code/kimi-for-coding";
const maxBytes = 16 * 1024 * 1024;

function config(region: string, effort: string): string {
  const domain = region === "global" ? "kimi.ai" : "kimi.com";
  const baseUrl = `https://api.${domain}/coding/v1`;
  const oauthHost = `https://auth.${domain}`;
  // Kimi Code 2.7.2 scopes OAuth credential names to the official endpoints.
  const oauthKey =
    region === "global"
      ? `oauth/kimi-code-env-${createHash("sha256").update(JSON.stringify({ oauthHost, baseUrl })).digest("hex").slice(0, 16)}`
      : "oauth/kimi-code";
  return `default_model = "${managedAlias}"
default_permission_mode = "manual"
builtin_product_skills = false
merge_all_available_skills = false
telemetry = false
auto_session_title = false

[tools]
# Kimi Code treats this nonempty allowlist as matching no tool names.
enabled = ["*"]

[thinking]
enabled = true
effort = "${effort}"

[providers."managed:kimi-code"]
type = "kimi"
base_url = "${baseUrl}"

[providers."managed:kimi-code".oauth]
storage = "file"
key = "${oauthKey}"
oauth_host = "${oauthHost}"

[models."${managedAlias}"]
provider = "managed:kimi-code"
model = "${KIMI_MODEL}"
max_context_size = 262144
capabilities = ["thinking", "always_thinking"]
support_efforts = ["low", "high", "max"]
default_effort = "${effort}"
`;
}

type Reply = {
  sessionId?: unknown;
  configOptions?: { id: string; currentValue: string }[];
  agentInfo?: { name: string; version: string };
  stopReason?: string;
};

async function infer(
  binary: string,
  home: string,
  scratch: string,
  effort: string,
  region: string,
  prompt?: string,
) {
  if (region !== "mainland-cn" && region !== "global") throw new Error("Unknown Kimi login region");
  const cwd = mkdtempSync(join(scratch, "kimi-call-"));
  try {
    const state = join(cwd, "state");
    mkdirSync(state, { mode: 0o700 });
    // The signed-in client owns credential handling and token refresh. All other Kimi state
    // is created from scratch, including the configuration, plug-ins, hooks and MCP registry.
    symlinkSync(join(home, "credentials"), join(state, "credentials"), "dir");
    writeFileSync(join(state, "config.toml"), config(region, effort), { mode: 0o600 });
    writeFileSync(join(state, "region"), region, { mode: 0o600 });
    const child = spawn(binary, ["acp"], {
      cwd,
      env: {
        PATH: process.env.PATH,
        HOME: cwd,
        KIMI_CODE_HOME: state,
        KIMI_CODE_OAUTH_HOST:
          region === "global" ? "https://auth.kimi.ai" : "https://auth.kimi.com",
        KIMI_CODE_NO_AUTO_UPDATE: "1",
        KIMI_DISABLE_TELEMETRY: "1",
      },
      stdio: ["pipe", "pipe", "ignore"],
    });
    const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
    const pending = new Map<number, { resolve: (reply: Reply) => void; reject: () => void }>();
    const lines = createInterface({ input: child.stdout });
    let bytes = 0;
    let nextId = 0;
    let sessionId: string | undefined;
    let text = "";
    let failed = false;
    let classified = "Kimi inference did not complete with the selected model and effort.";
    const stop = () => {
      failed = true;
      for (const reply of pending.values()) reply.reject();
      pending.clear();
    };
    child.once("error", stop);
    child.once("exit", stop);
    child.stdin.on("error", stop);
    child.stdout.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        stop();
        child.kill("SIGKILL");
      }
    });
    lines.on("line", (line) => {
      try {
        const event = JSON.parse(line);
        if (event.jsonrpc !== "2.0" || failed) throw new Error();
        if (event.method === "session/update" && event.id === undefined) {
          const { sessionId: actual, update } = event.params;
          if (sessionId !== undefined && actual !== sessionId) throw new Error();
          switch (update.sessionUpdate) {
            case "agent_message_chunk":
              if (
                sessionId === undefined ||
                update.content.type !== "text" ||
                typeof update.content.text !== "string"
              )
                throw new Error();
              text += update.content.text;
              break;
            case "available_commands_update":
            case "session_info_update":
            case "agent_thought_chunk":
            case "config_option_update":
              break;
            default:
              throw new Error();
          }
          return;
        }
        if (event.error?.code === -32000)
          classified = "Kimi login is unavailable for the selected account.";
        if (
          event.error?.data?.status === 429 ||
          event.error?.data?.statusCode === 429 ||
          /\b(?:rate.limit|quota|429)\b/iu.test(event.error?.message ?? "")
        )
          classified = "Kimi rate or quota limit refused the request.";
        if (event.method !== undefined || !pending.has(event.id) || event.error || !event.result)
          throw new Error();
        const reply = pending.get(event.id);
        pending.delete(event.id);
        reply?.resolve(event.result);
      } catch {
        stop();
        child.kill("SIGKILL");
      }
    });
    const call = (method: string, params: object) =>
      new Promise<Reply>((resolve, reject) => {
        if (failed) {
          reject(new Error("Kimi inference failed"));
          return;
        }
        const id = ++nextId;
        pending.set(id, { resolve, reject: () => reject(new Error("Kimi inference failed")) });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      });
    try {
      const { agentInfo } = await call("initialize", {
        protocolVersion: 1,
        clientCapabilities: {},
      });
      if (agentInfo?.version !== KIMI_VERSION) throw new Error("Kimi version mismatch");
      const session = await call("session/new", { cwd, mcpServers: [] });
      if (typeof session.sessionId !== "string") throw new Error("Kimi session missing");
      sessionId = session.sessionId;
      if (
        session.configOptions?.find((entry) => entry.id === "model")?.currentValue !==
          managedAlias ||
        session.configOptions?.find((entry) => entry.id === "thinking")?.currentValue !== effort
      )
        throw new Error("Kimi model or effort mismatch");
      if (prompt === undefined) return '{"loggedIn":true}\n';
      const result = await call("session/prompt", {
        sessionId,
        prompt: [{ type: "text", text: prompt }],
      });
      if (failed || result.stopReason !== "end_turn" || !text.trim())
        throw new Error("Kimi response incomplete");
      return text;
    } catch {
      throw new InferenceError(classified);
    } finally {
      lines.close();
      child.stdin.end();
      child.kill("SIGKILL");
      await closed;
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

class InferenceError extends Error {}

async function main() {
  const [binary, home, scratch, effort, region, ...flags] = process.argv.slice(2);
  if (
    !binary ||
    !home ||
    !scratch ||
    !region ||
    !effort ||
    !KIMI_EFFORTS.some((level) => level === effort)
  )
    throw new Error();
  if (flags.length === 2 && flags[0] === "auth" && flags[1] === "status") {
    // ACP session creation requires a signed-in client and checks the selected configuration.
    process.stdout.write(await infer(binary, home, scratch, effort, region));
    return;
  }
  if (flags[0] !== "-p" || flags[flags.indexOf("--model") + 1] !== KIMI_MODEL) throw new Error();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > maxBytes) throw new Error();
    chunks.push(chunk);
  }
  const prompt = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  if (!prompt.trim()) throw new Error();
  const output = await infer(binary, home, scratch, effort, region, prompt);
  writeFileSync(join(scratch, "kimi-inference-completed"), "", { mode: 0o600 });
  process.stdout.write(output);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    // Never serialize provider errors, prompts or credentials to analyzer diagnostics.
    const message =
      error instanceof InferenceError
        ? error.message
        : "Kimi inference did not complete with the selected model and effort.";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
