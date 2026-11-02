import type { FileMode } from "./git-tree.js";

/** The one file a remote MCP source becomes. */
export interface RemoteMcpFile {
  readonly path: ".mcp.json";
  readonly mode: FileMode;
  readonly bytes: Uint8Array;
}

/**
 * Materializes a validated remote MCP URL as configuration only: exactly one regular file
 * `.mcp.json`, mode `100644`, whose bytes are UTF-8 without BOM, the compact JSON of
 * `{"mcpServers":{"remote":{"url":URL}}}` (that property order, ECMAScript string escaping)
 * and exactly one LF. The URL string is preserved as given: never lowercased, resolved,
 * re-escaped or otherwise normalized, and never contacted.
 */
export function remoteMcpFile(url: string): RemoteMcpFile {
  const text = `${JSON.stringify({ mcpServers: { remote: { url } } })}\n`;
  return Object.freeze({
    path: ".mcp.json" as const,
    mode: "100644" as const,
    bytes: new TextEncoder().encode(text),
  });
}
