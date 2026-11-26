import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, posix } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import { pathDirectoriesV1, resolveHostExecutableV1 } from "../cli/host-executable.js";
import { KIMI_CLIENT_VERSION, KIMI_K3_MODEL } from "../contracts/ai-profile.js";

export const KIMI_VERSION = KIMI_CLIENT_VERSION;
export const KIMI_MODEL = "kimi-for-coding";
export const KIMI_INFERENCE_RECEIPT = "kimi-inference-completed";
export const KIMI_QUOTA_RECEIPT = "kimi-quota-refusal";
export const KIMI_EFFORTS = Object.freeze(["low", "high", "max"] as const);
const maxBytes = 16 * 1024 * 1024;
// Leave time to reap ACP before SkillSpector's 15s auth and 300s call limits.
const authTimeoutMs = 14_000;
const inferenceTimeoutMs = 299_000;
const quotaMessage = "Kimi rate or quota limit refused the request.";

function config(region: string, effort: string, model: string): string {
  const managedAlias = modelAlias(model);
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
model = "${model}"
max_context_size = 1048576
capabilities = ["thinking", "always_thinking"]
support_efforts = ["low", "high", "max"]
default_effort = "${effort}"
`;
}

type Reply = {
  sessionId?: unknown;
  configOptions?: { id: string; currentValue: string }[];
  agentInfo?: { name: string; version: string };
  protocolVersion?: number;
  stopReason?: string;
};

const modelAlias = (model: string) => `kimi-code/${model}`;

export function supportedKimiSelection(model: string | undefined, effort: string): boolean {
  return model === KIMI_K3_MODEL
    ? effort === "max"
    : model === KIMI_MODEL && KIMI_EFFORTS.some((level) => level === effort);
}

function selectedConfig(options: Reply["configOptions"], effort: string, model: string) {
  return (
    options?.find((entry) => entry.id === "model")?.currentValue === modelAlias(model) &&
    options?.find((entry) => entry.id === "thinking")?.currentValue === effort
  );
}

async function infer(
  binary: string,
  home: string,
  scratch: string,
  effort: string,
  region: string,
  model: string,
  prompt?: string,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  if (region !== "mainland-cn" && region !== "global") throw new Error("Unknown Kimi login region");
  const cwd = mkdtempSync(join(scratch, "kimi-call-"));
  try {
    const state = join(cwd, "state");
    mkdirSync(state, { mode: 0o700 });
    // The signed-in client owns credential handling and token refresh. All other Kimi state
    // is created from scratch, including the configuration, plug-ins, hooks and MCP registry.
    symlinkSync(join(home, "credentials"), join(state, "credentials"), "dir");
    writeFileSync(join(state, "config.toml"), config(region, effort, model), { mode: 0o600 });
    writeFileSync(join(state, "region"), region, { mode: 0o600 });
    const child = spawn(binary, ["acp"], {
      cwd,
      env: {
        PATH: pathDirectoriesV1(process.env).join(":"),
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
    const abort = () => {
      classified = "Kimi inference was cancelled.";
      stop();
      child.kill("SIGKILL");
    };
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const timer = setTimeout(
      () => {
        classified = "Kimi inference did not respond before the request deadline.";
        stop();
        child.kill("SIGKILL");
      },
      prompt === undefined ? authTimeoutMs : inferenceTimeoutMs,
    );
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
              break;
            case "config_option_update":
              if (!selectedConfig(update.configOptions, effort, model)) throw new Error();
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
          classified = quotaMessage;
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
      const { agentInfo, protocolVersion } = await call("initialize", {
        protocolVersion: 1,
        clientCapabilities: {},
      });
      if (protocolVersion !== 1 || agentInfo?.version !== KIMI_VERSION)
        throw new Error("Kimi version or protocol mismatch");
      const session = await call("session/new", { cwd, mcpServers: [] });
      if (typeof session.sessionId !== "string") throw new Error("Kimi session missing");
      sessionId = session.sessionId;
      if (!selectedConfig(session.configOptions, effort, model))
        throw new Error("Kimi model or effort mismatch");
      if (prompt === undefined) return '{"loggedIn":true}\n';
      const result = await call("session/prompt", {
        sessionId,
        prompt: [{ type: "text", text: prompt }],
      });
      if (!failed && signal !== undefined && result.stopReason === "max_tokens")
        throw new InferenceError("Kimi reached its response limit.", "kimi-output-limit");
      if (failed || result.stopReason !== "end_turn" || !text.trim())
        throw new Error("Kimi response incomplete");
      return text;
    } catch (error) {
      if (error instanceof InferenceError && error.code === "kimi-output-limit") throw error;
      if (classified === quotaMessage) {
        if (signal === undefined)
          writeFileSync(join(scratch, KIMI_QUOTA_RECEIPT), "", { mode: 0o600 });
        throw new InferenceError(classified, "kimi-quota-refusal");
      }
      throw new InferenceError(classified);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      lines.close();
      child.stdin.end();
      child.kill("SIGKILL");
      await closed;
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

class InferenceError extends Error {
  constructor(
    message: string,
    readonly code?: "kimi-quota-refusal" | "kimi-output-limit",
  ) {
    super(message);
  }
}

export function kimiLogin(env: Readonly<NodeJS.ProcessEnv>) {
  const home = env.KIMI_CODE_HOME ?? (env.HOME ? posix.join(env.HOME, ".kimi-code") : "");
  if (!posix.isAbsolute(home)) return "Kimi Code requires an absolute login directory";
  const region = env.AIH_SCAN_KIMI_REGION ?? "global";
  if (region !== "global" && region !== "mainland-cn")
    return "AIH_SCAN_KIMI_REGION must be global or mainland-cn";
  return { home, region };
}

/** Run one adaptive detector prompt with the same isolated ACP transport as ordinary Kimi AI. */
export async function inferAdaptiveSsd(prompt: string, signal: AbortSignal, scratch: string) {
  if (process.platform === "win32") throw new InferenceError("Kimi Code AI requires a POSIX host.");
  const binary = resolveHostExecutableV1("kimi", process.env)?.path;
  const login = kimiLogin(process.env);
  if (!binary) throw new InferenceError("Kimi Code CLI is unavailable.");
  if (typeof login === "string") throw new InferenceError(login);
  if (!validPrompt(prompt) || Buffer.byteLength(prompt) > maxBytes)
    throw new InferenceError("Kimi inference prompt refused.");
  return infer(binary, login.home, scratch, "max", login.region, KIMI_K3_MODEL, prompt, signal);
}

const validPrompt = (prompt: string) => prompt.trim() && !prompt.trimStart().startsWith("/");

async function main() {
  const [binary, home, scratch, effort, region, model, ...flags] = process.argv.slice(2);
  if (
    !binary ||
    !home ||
    !scratch ||
    !region ||
    !model ||
    !effort ||
    !supportedKimiSelection(model, effort)
  )
    throw new Error();
  if (flags.length === 2 && flags[0] === "auth" && flags[1] === "status") {
    // ACP session creation requires a signed-in client and checks the selected configuration.
    process.stdout.write(await infer(binary, home, scratch, effort, region, model));
    return;
  }
  if (flags[0] !== "-p" || flags[flags.indexOf("--model") + 1] !== model) throw new Error();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > maxBytes) throw new Error();
    chunks.push(chunk);
  }
  const prompt = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  // ACP recognizes slash commands at the beginning of a prompt. Analyzer instructions
  // start with ordinary text; refuse any input that could select a CLI command.
  if (!validPrompt(prompt)) throw new Error();
  const output = await infer(binary, home, scratch, effort, region, model, prompt);
  writeFileSync(join(scratch, KIMI_INFERENCE_RECEIPT), "", { mode: 0o600 });
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
