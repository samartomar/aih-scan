import type { TrustLintFindingV1 } from "./findings.js";
import type { TrustLintTreeV1 } from "./inventory.js";
import { scanTrustDocumentV1 } from "./lint.js";

/**
 * Port of the MCP server description lint half of Core's `incomingMcpChecks`
 * (`src/trust/scan.ts`), C2a §2.2(5). For each declared MCP config path in
 * declared order, the UTF-8 text is parsed with strict `JSON.parse` (never
 * JSONC); a read or parse failure yields NO description lint for the file —
 * Core reports the malformed file as policy, which stays in Core.
 *
 * Server maps follow Core's `incomingServerMaps`: own properties
 * `mcpServers`, then `servers`, then `mcp`; if any present map is not a
 * plain object, or the document is not an object, the WHOLE file has no
 * description lint. `mcp` (OpenCode) servers are converted by
 * `openCodeServer`, which keeps `description`. Per map, servers are sorted
 * by name with `localeCompare`; a server whose `description` is a string is
 * linted with the full document lint under the pseudo path
 * `<configPath>#<mapKey>.<safeMcpName(name)>.description`. Every emitted
 * finding carries `mcpDescription` metadata (§2.3) so Core can interleave
 * these results with its own MCP policy checks.
 *
 * The MCP POLICY checks (`mcp.policy-denied`, skills-provider evidence) are
 * not detection and are not ported.
 */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** Port of Core's `safeMcpName`. */
export function safeMcpNameV1(name: string): string {
  const safe = name.replace(/[^A-Za-z0-9._-]/g, "_");
  return safe.length > 0 ? safe : "server";
}

/** Port of Core's `openCodeServer`; keeps `description` via the spread. */
function openCodeServer(server: unknown): unknown {
  if (!isRecord(server)) return server;
  if (server.type === "remote") {
    return { ...server, url: stringValue(server.url) };
  }
  const command = Array.isArray(server.command) ? server.command : [];
  const executable = command[0];
  return {
    ...server,
    command: typeof executable === "string" ? executable : undefined,
    args: command.slice(1).filter((item): item is string => typeof item === "string"),
    env: server.environment ?? server.env,
  };
}

interface IncomingServerMap {
  readonly key: string;
  readonly servers: Record<string, unknown>;
}

/** Port of Core's `incomingServerMaps`; undefined means "no lint for the file". */
function incomingServerMaps(parsed: unknown): IncomingServerMap[] | undefined {
  if (!isRecord(parsed)) return undefined;
  const maps: IncomingServerMap[] = [];
  for (const key of ["mcpServers", "servers"] as const) {
    if (!Object.hasOwn(parsed, key)) continue;
    const value = parsed[key];
    if (!isRecord(value)) return undefined;
    maps.push({ key, servers: value });
  }
  if (Object.hasOwn(parsed, "mcp")) {
    const value = parsed.mcp;
    if (!isRecord(value)) return undefined;
    maps.push({
      key: "mcp",
      servers: Object.fromEntries(
        Object.entries(value).map(([name, server]) => [name, openCodeServer(server)]),
      ),
    });
  }
  return maps;
}

/**
 * Lints the MCP server descriptions of each declared config path, in order.
 * Read follows symlinks, exactly like Core's `readFileSync` in
 * `incomingMcpChecks` (a symlinked config is still description-linted even
 * though §2.2(4) flags it `mcp.config-invalid`).
 */
export function scanMcpServerDescriptionsV1(
  tree: TrustLintTreeV1,
  configPaths: readonly string[],
): TrustLintFindingV1[] {
  const findings: TrustLintFindingV1[] = [];
  for (const rel of configPaths) {
    const text = tree.readText(rel);
    if (text === undefined) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      continue;
    }
    const maps = incomingServerMaps(parsed);
    if (maps === undefined) continue;
    for (const map of maps) {
      for (const [name, server] of Object.entries(map.servers).sort(([a], [b]) =>
        a.localeCompare(b),
      )) {
        if (!isRecord(server) || typeof server.description !== "string") continue;
        const pseudoPath = `${rel}#${map.key}.${safeMcpNameV1(name)}.description`;
        for (const finding of scanTrustDocumentV1(pseudoPath, server.description)) {
          findings.push({
            ...finding,
            mcpDescription: { configPath: rel, mapKey: map.key, server: name },
          });
        }
      }
    }
  }
  return findings;
}
