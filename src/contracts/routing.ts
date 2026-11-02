import { parse as parseToml } from "smol-toml";
import { parseJsonc } from "../shared/jsonc.js";
import { isRecord, type Json } from "../shared/values.js";
import { formats } from "./formats.js";

export type Part = "config" | "dependencies" | "code" | "text";
export type ToolId = "skillspector" | "aih-trust-lint" | "cisco";

export interface Dependency {
  readonly ecosystem: "npm" | "pypi";
  readonly name: string;
  /** The version exactly as written, or null when none is written. */
  readonly version: string | null;
  readonly file: string;
}

export interface InlineCommand {
  /** The command text of a hook or MCP entry (MCP: command and args joined by spaces). */
  readonly command: string;
  readonly line: number;
}

export interface RoutedFile {
  /** The first matching part, or null when no part matches (the file is listed in `notAnalysed`). */
  readonly part: Part | null;
  /** Valid UTF-8 without NUL bytes. Every text file receives the trust-lint secret check. */
  readonly text: boolean;
  readonly inlineCommands: readonly InlineCommand[];
  readonly dependencies: readonly Dependency[];
}

const CODE_EXTENSIONS = Object.freeze([
  "js",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "jsx",
  "py",
  "sh",
  "ps1",
  "cmd",
  "bat",
  "rs",
  "go",
  "rb",
  "lua",
]);
const TEXT_EXTENSIONS = Object.freeze(["md", "txt", "mdc", "json", "toml"]);
const CONFIG_NAMES = Object.freeze(["hooks.json", ".mcp.json", "mcp.json", "plugin.json"]);
const SERVER_MAP_KEYS = Object.freeze(["mcpServers", "servers", "mcp", "mcp_servers"]);

/**
 * `aih-scan-routing/1`. Each file gets exactly one part: the first that matches in the order
 * Config, Dependencies, Code, Text. Matching reads only the item-relative path, the bytes and
 * nothing else (not ancestor folders, labels, discovery kind or acquisition route). Extension
 * and name comparisons ignore ASCII case. A file that is not text (invalid UTF-8 or a NUL byte)
 * matches no part. trust-lint's secret check runs on every text file whatever its part.
 */
export const routing = Object.freeze({
  format: formats.routing,
  order: Object.freeze(["config", "dependencies", "code", "text"] as const),
  parts: Object.freeze({
    config: Object.freeze({
      names: CONFIG_NAMES,
      content:
        "a JSON or TOML (.toml) hook entry (an event with a command) or MCP entry (command and args, or url), at the top level or under mcpServers, servers, mcp or mcp_servers; the named files may use JSONC comments and trailing commas",
      tools: Object.freeze(["aih-trust-lint", "skillspector"] as const),
    }),
    dependencies: Object.freeze({
      names: Object.freeze(["package.json", "requirements*.txt"]),
      content: "npx/uvx commands in MCP config entries are extracted as dependencies",
      tools: Object.freeze(["aih-trust-lint"] as const),
    }),
    code: Object.freeze({
      extensions: CODE_EXTENSIONS,
      content: "a first line starting with #!",
      tools: Object.freeze(["skillspector", "aih-trust-lint"] as const),
    }),
    text: Object.freeze({
      extensions: TEXT_EXTENSIONS,
      tools: Object.freeze(["skillspector", "aih-trust-lint"] as const),
    }),
  }),
  /** Inline commands inside a config entry also go to the code checks; their findings have part `code`. */
  inlineCommandPart: "code" as const,
  /** Always runs, on every text file for secrets. */
  baseline: "aih-trust-lint" as const,
  /** Optional second opinion; never routed for coverage. */
  optional: Object.freeze(["cisco"] as const),
  /** Item layouts recognised on the `source` route. */
  layouts: Object.freeze([
    Object.freeze({ kind: "skill", rule: "a folder holding SKILL.md: the whole folder" }),
    Object.freeze({
      kind: "agent",
      rule: "a .md file, or a .json/.toml agent definition, under a folder named agents",
    }),
    Object.freeze({ kind: "command", rule: "a .md file under a folder named commands" }),
    Object.freeze({
      kind: "rule",
      rule: "a file under a folder named rules at any depth, .cursor/rules/*.mdc, or .kiro/steering/*.md",
    }),
    Object.freeze({
      kind: "hook",
      rule: "a hooks.json in a folder named hooks: that whole folder; elsewhere the hooks.json file alone",
    }),
    Object.freeze({
      kind: "mcp",
      rule: "a .mcp.json or mcp.json file, whole; or an npm, npm-file or remote source",
    }),
  ]),
  ownership:
    "the outermost skill folder owns everything inside it, then a hooks folder, then single files",
});

export const kinds = Object.freeze(["skill", "agent", "command", "rule", "hook", "mcp"] as const);
export type Kind = (typeof kinds)[number];
export const optionalTools = Object.freeze(["skillspector", "aih-trust-lint", "cisco"] as const);

/** Tools routed for a part. */
export function toolsForPart(part: Part): readonly ToolId[] {
  return routing.parts[part].tools;
}

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/** The text of a file, or undefined when it is not text (invalid UTF-8 or contains NUL). */
export function textOf(bytes: Uint8Array): string | undefined {
  if (bytes.includes(0)) return undefined;
  try {
    return decoder.decode(bytes);
  } catch {
    return undefined;
  }
}

function baseName(path: string): string {
  return (path.split("/").at(-1) ?? "").toLowerCase();
}

function extension(path: string): string {
  const name = baseName(path);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1) : "";
}

const isObject = isRecord<Json>;

/** JSON, or JSONC (comments, trailing commas) for the named config files editors write. */
function parseJson(text: string, jsonc: boolean): Json | undefined {
  try {
    return (jsonc ? parseJsonc(text) : JSON.parse(text)) as Json;
  } catch {
    return undefined;
  }
}

/**
 * A `.toml` file's document as plain data, or undefined when it is not valid TOML. Keys such as
 * `__proto__` and `constructor` are kept as own data properties (never assigned through a
 * prototype), so a server with such a name is still routed; the library's default depth applies.
 */
function parseTomlDocument(text: string): Json | undefined {
  try {
    return parseToml(text, {
      integersAsBigInt: "asNeeded",
      unsafeKeyBehaviour: "keep",
    }) as unknown as Json;
  } catch {
    return undefined;
  }
}

function isMcpEntry(value: unknown): value is Record<string, Json> {
  if (!isObject(value)) return false;
  return (
    (typeof value.command === "string" && Array.isArray(value.args)) ||
    typeof value.url === "string"
  );
}

function mcpEntries(document: Json | undefined): Record<string, Json>[] {
  if (!isObject(document)) return [];
  if (isMcpEntry(document)) return [document];
  const entries: Record<string, Json>[] = [];
  for (const key of SERVER_MAP_KEYS) {
    const map = document[key];
    if (!isObject(map)) continue;
    for (const name of Object.keys(map)) {
      const entry = map[name];
      if (isMcpEntry(entry)) entries.push(entry);
    }
  }
  return entries;
}

/** Commands of hook entries: `{ Event: [ { command } | { hooks: [ { command } ] } ] }`, optionally under `hooks`. */
function hookCommands(document: Json | undefined): string[] {
  if (!isObject(document)) return [];
  const commands: string[] = [];
  const events = (map: Record<string, Json>) => {
    for (const event of Object.keys(map)) {
      const list = map[event];
      if (!Array.isArray(list)) continue;
      for (const entry of list) {
        if (!isObject(entry)) continue;
        if (typeof entry.command === "string") commands.push(entry.command);
        const nested = entry.hooks;
        if (Array.isArray(nested))
          for (const hook of nested)
            if (isObject(hook) && typeof hook.command === "string") commands.push(hook.command);
      }
    }
  };
  if (isObject(document.hooks)) events(document.hooks);
  events(document);
  return commands;
}

function lineOf(text: string, needle: string): number {
  const encoded = JSON.stringify(needle).slice(1, -1);
  let index = text.indexOf(encoded);
  if (index < 0) index = text.indexOf(needle);
  return index < 0 ? 1 : text.slice(0, index).split("\n").length;
}

const stripBom = (text: string) => (text.startsWith("\uFEFF") ? text.slice(1) : text);

function splitNpmSpec(spec: string): { name: string; version: string | null } {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  return at > 0
    ? { name: spec.slice(0, at), version: spec.slice(at + 1) }
    : { name: spec, version: null };
}

function splitPypiSpec(spec: string): { name: string; version: string | null } {
  const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(spec.trim());
  if (match === null) return { name: spec.trim(), version: null };
  const rest = (match[2] ?? "").split(";")[0]?.trim() ?? "";
  if (rest.startsWith("@"))
    return { name: match[1] as string, version: rest.slice(1).trim() || null };
  return { name: match[1] as string, version: rest.length > 0 ? rest : null };
}

function launcherDependency(entry: Record<string, Json>, file: string): Dependency | undefined {
  if (typeof entry.command !== "string" || !Array.isArray(entry.args)) return undefined;
  const launcher = (entry.command.split(/[\\/]/).at(-1) ?? "")
    .toLowerCase()
    .replace(/\.(cmd|exe)$/, "");
  if (launcher !== "npx" && launcher !== "uvx") return undefined;
  const spec = entry.args.find((arg) => typeof arg === "string" && !arg.startsWith("-"));
  if (typeof spec !== "string" || spec.length === 0) return undefined;
  const parsed = launcher === "npx" ? splitNpmSpec(spec) : splitPypiSpec(spec.replace("==", " =="));
  return Object.freeze({
    ecosystem: launcher === "npx" ? ("npm" as const) : ("pypi" as const),
    name: parsed.name,
    version: parsed.version,
    file,
  });
}

function packageDependencies(document: Json | undefined, file: string): Dependency[] {
  if (!isObject(document)) return [];
  const result: Dependency[] = [];
  for (const block of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const map = document[block];
    if (!isObject(map)) continue;
    for (const name of Object.keys(map)) {
      const version = map[name];
      result.push(
        Object.freeze({
          ecosystem: "npm" as const,
          name,
          version: typeof version === "string" ? version : null,
          file,
        }),
      );
    }
  }
  return result;
}

function requirementDependencies(text: string, file: string): Dependency[] {
  const result: Dependency[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (line.length === 0 || line.startsWith("-")) continue;
    const parsed = splitPypiSpec(line);
    result.push(Object.freeze({ ecosystem: "pypi" as const, ...parsed, file }));
  }
  return result;
}

/** Routes one file of an item by its item-relative path and bytes. */
export function routeFile(path: string, bytes: Uint8Array): RoutedFile {
  const text = textOf(bytes);
  const empty = Object.freeze([]) as readonly never[];
  if (text === undefined)
    return Object.freeze({ part: null, text: false, inlineCommands: empty, dependencies: empty });
  const name = baseName(path);
  const ext = extension(path);
  const body = stripBom(text);
  const named = CONFIG_NAMES.includes(name);
  const looksJson = /^\s*[{[]/.test(body);
  // A .toml file is read as TOML (its tables also start with "["); a named config file always as
  // JSONC (it may start with a comment); other files as JSON when they look like JSON.
  const document =
    ext === "toml"
      ? parseTomlDocument(body)
      : named || looksJson
        ? parseJson(body, named)
        : undefined;
  const servers = mcpEntries(document);
  const hooks = hookCommands(document);
  if (named || servers.length > 0 || hooks.length > 0) {
    const inlineCommands = [
      ...hooks.map((command) => ({ command, line: lineOf(body, command) })),
      ...servers
        .filter((entry) => typeof entry.command === "string")
        .map((entry) => {
          const args = Array.isArray(entry.args)
            ? entry.args.filter((arg) => typeof arg === "string")
            : [];
          return {
            command: [entry.command as string, ...args].join(" "),
            line: lineOf(body, entry.command as string),
          };
        }),
    ].map((entry) => Object.freeze(entry));
    const dependencies = servers
      .map((entry) => launcherDependency(entry, path))
      .filter((entry): entry is Dependency => entry !== undefined);
    return Object.freeze({
      part: "config" as const,
      text: true,
      inlineCommands: Object.freeze(inlineCommands),
      dependencies: Object.freeze(dependencies),
    });
  }
  if (name === "package.json")
    return Object.freeze({
      part: "dependencies" as const,
      text: true,
      inlineCommands: empty,
      dependencies: Object.freeze(packageDependencies(document, path)),
    });
  if (/^requirements.*\.txt$/.test(name))
    return Object.freeze({
      part: "dependencies" as const,
      text: true,
      inlineCommands: empty,
      dependencies: Object.freeze(requirementDependencies(body, path)),
    });
  if (CODE_EXTENSIONS.includes(ext) || body.startsWith("#!"))
    return Object.freeze({
      part: "code" as const,
      text: true,
      inlineCommands: empty,
      dependencies: empty,
    });
  if (TEXT_EXTENSIONS.includes(ext))
    return Object.freeze({
      part: "text" as const,
      text: true,
      inlineCommands: empty,
      dependencies: empty,
    });
  return Object.freeze({ part: null, text: true, inlineCommands: empty, dependencies: empty });
}
