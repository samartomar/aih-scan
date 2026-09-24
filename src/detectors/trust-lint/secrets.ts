import { type ParseError, parse as parseJsonc } from "jsonc-parser";
import type { TrustLintFindingV1 } from "./findings.js";
import type { TrustLintTreeV1 } from "./inventory.js";

/**
 * Port of the secrets detection Core's trust scan uses (`src/secrets/scan.ts`
 * as consumed by `src/trust/scan.ts`, plus the finding shapes from
 * `src/secrets/probes.ts` minus posture grading):
 *
 * - `scanPlaintextSecretsV1`: `.env` / `.env.*` files at the root or one level
 *   deep (never `.env.example` / `.env.sample`) and a root-level `secrets/`
 *   directory → `secrets.plaintext-detected`;
 * - `scanMcpConfigSecretsV1`: content scan of known MCP config files for
 *   provider token shapes, authorization bearer literals, and secret-looking
 *   keys holding literal values → `mcp.hardcoded-secret` (or
 *   `mcp.config-invalid` when the file cannot be read safely).
 *
 * Findings never include a secret value — only file, key and match kind. The
 * MCP POLICY classification of those config files (`mcp.policy-denied`) is not
 * detection and stays in Core.
 */

export const PLAINTEXT_SECRET_RULE_V1 = "plaintext-secret";
export const MCP_SECRET_RULE_V1 = "mcp-hardcoded-secret";

/** `.env.example` / `.env.sample` are templates, not real secrets — never flag them. */
const EXAMPLE_SUFFIXES = [".example", ".sample"] as const;

function isEnvFile(name: string): boolean {
  if (name !== ".env" && !name.startsWith(".env.")) return false;
  return !EXAMPLE_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

/**
 * Port of Core's `scanSecrets` over the tree seam: `.env` files shallow plus
 * one level deep, and a credential directory named `secrets/` at the repo
 * ROOT only. Nested directories named `secrets` are code, not secret stores.
 */
export function scanPlaintextSecretsV1(tree: TrustLintTreeV1): TrustLintFindingV1[] {
  const envFiles = new Set<string>();
  const secretDirs = new Set<string>();
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    const parts = rel.split("/");
    const name = parts.at(-1) ?? "";
    // Root plus exactly one level deep, matching Core's depth-bounded walk.
    if (parts.length <= 2 && isEnvFile(name)) envFiles.add(rel);
  }
  if (tree.isDirectory("secrets")) secretDirs.add("secrets");
  const envList = [...envFiles].sort();
  const dirList = [...secretDirs].sort();
  const matches = [...envList, ...dirList].sort();
  return matches.map((path) => ({
    name: PLAINTEXT_SECRET_RULE_V1,
    verdict: "fail" as const,
    detail: `${path} — plaintext secret on disk; migrate to a vault and rotate the exposed credential`,
    code: "secrets.plaintext-detected" as const,
    location: { uri: path, startLine: 1 },
    fingerprint: `${PLAINTEXT_SECRET_RULE_V1}:${path}`,
  }));
}

/**
 * Repo-relative MCP config files aih writes or knows about, in Core's
 * `MCP_CONFIG_FILES` order.
 */
export const MCP_CONFIG_FILES_V1: readonly string[] = [
  ".mcp.json",
  ".cursor/mcp.json",
  ".kiro/settings/mcp.json",
  "mcp-configs/mcp-servers.json",
  ".vscode/mcp.json",
  "opencode.json",
];

/** Core's incoming set: `MCP_CONFIG_FILES` plus `mcp.json`. */
export const INCOMING_MCP_CONFIG_FILES_V1: readonly string[] = [...MCP_CONFIG_FILES_V1, "mcp.json"];

/** One secret-scan finding inside or at a config file boundary (not a `.env`). */
interface ConfigSecretHit {
  file: string;
  key: string;
  kind: string;
  code?: "mcp.config-invalid" | "mcp.hardcoded-secret";
}

/** High-confidence provider credential shapes — a match is a secret regardless of key. */
const TOKEN_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  { kind: "aws access key id", re: /AKIA[0-9A-Z]{16}/ },
  { kind: "github personal access token", re: /\bghp_[A-Za-z0-9]{36,}\b/ },
  { kind: "github fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { kind: "openai/anthropic-style key", re: /\bsk-[A-Za-z0-9_-]{20,}/ },
  { kind: "slack token", re: /\bxox[abprsoe]-[A-Za-z0-9-]{10,}\b/ },
  { kind: "google api key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { kind: "azure storage account key", re: /\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}/i },
  {
    kind: "azure storage shared access signature",
    re: /\bSharedAccessSignature=(?=[^\s"']*\bsig=)[^\s"']*\bsig=[A-Za-z0-9%+/=_-]{8,}[^\s"']*/i,
  },
  { kind: "npm access token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
];

/** Keys whose literal (non-placeholder) value is almost certainly a credential. */
const SECRET_KEY_RE =
  /token|secret|password|passwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|\bpat\b/i;

/** Minimum length for a secret-key literal to count — skips trivial flags like "1"/"on". */
const MIN_SECRET_VALUE_LEN = 8;

/** Path-designating key suffixes (`*_PATH`, `*_DIR`, `*_FILE`, ...) — end-anchored so `PATH_TOKEN` never matches. */
const PATH_KEY_RE = /(?:^|[_.-])(?:path|paths|dir|dirs|file|files|home)$/i;

/** Drive-letter, UNC, or absolute-POSIX form — the value designates a filesystem location. */
function isPathShapedValue(value: string): boolean {
  const t = value.trim();
  return /^[A-Za-z]:[\\/]/.test(t) || t.startsWith("\\\\") || t.startsWith("/");
}

/**
 * A path-designating key holding a path-shaped value is configuration, not a
 * credential — "rotate the exposed value" is meaningless for the path to
 * node.exe (#499). The carve-out needs BOTH conditions: a secret-shaped value
 * under `API_KEY_PATH` still fails, and provider token shapes are matched
 * before the key rule in both scan branches, so they stay flagged regardless.
 */
function isPathConfigEntry(key: string, value: string): boolean {
  return PATH_KEY_RE.test(key) && isPathShapedValue(value);
}

/** An env reference (`${VAR}` / `$VAR` / `%VAR%`) or empty value is the sanctioned form — not a leak. */
function isPlaceholderOrEmpty(value: string): boolean {
  const t = value.trim();
  return (
    t.length === 0 ||
    /^\$\{[^}]+\}$/.test(t) ||
    /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(t) ||
    /^%[A-Za-z0-9_]+%$/.test(t)
  );
}

function isBearerPlaceholder(value: string): boolean {
  const m = /^Bearer\s+(.+)$/i.exec(value.trim());
  return m?.[1] !== undefined && isPlaceholderOrEmpty(m[1]);
}

/** First provider token shape that matches `value`, if any. */
function matchProvider(value: string): string | undefined {
  return TOKEN_PATTERNS.find((p) => p.re.test(value))?.kind;
}

function hasRawBearerLiteral(value: string): boolean {
  const re = /["']?\bauthorization\b["']?\s*[:=]\s*["']?Bearer\s+([^"'\r\n]*)/gi;
  for (const m of value.matchAll(re)) {
    const credential = m[1]?.trim();
    if (credential !== undefined && !isPlaceholderOrEmpty(credential)) return true;
  }
  return false;
}

function rawSecretKeyHits(value: string, file: string): ConfigSecretHit[] {
  const hits: ConfigSecretHit[] = [];
  const re =
    /["']?([A-Za-z0-9_.-]*(?:token|secret|password|passwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|pat)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']([^"'\r\n]{8,})/gi;
  for (const match of value.matchAll(re)) {
    const key = match[1] ?? "";
    const literal = match[2] ?? "";
    if (isPlaceholderOrEmpty(literal) || /^https?:\/\//i.test(literal.trim())) continue;
    if (isPathConfigEntry(key, literal)) continue;
    hits.push({ file, key, kind: "secret-looking key with a literal value" });
  }
  return hits;
}

/**
 * Walk parsed JSON collecting hits — `key` is the nearest object key for context.
 * A provider-shape match wins (and returns) so a token under a secret-looking key is
 * reported once, by its precise kind.
 */
function walkJson(node: unknown, key: string, file: string, hits: ConfigSecretHit[]): void {
  if (typeof node === "string") {
    const provider = matchProvider(node);
    if (provider !== undefined) {
      hits.push({ file, key, kind: provider });
      return;
    }
    if (
      key.toLowerCase() === "authorization" &&
      /^Bearer\s+\S+/i.test(node.trim()) &&
      !isBearerPlaceholder(node)
    ) {
      hits.push({ file, key, kind: "authorization bearer literal" });
      return;
    }
    if (
      SECRET_KEY_RE.test(key) &&
      !isPlaceholderOrEmpty(node) &&
      node.trim().length >= MIN_SECRET_VALUE_LEN &&
      !/^https?:\/\//i.test(node.trim()) &&
      !isPathConfigEntry(key, node)
    ) {
      hits.push({ file, key, kind: "secret-looking key with a literal value" });
    }
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) walkJson(item, key, file, hits);
    return;
  }
  if (node !== null && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) walkJson(v, k, file, hits);
  }
}

function parseJsoncText(text: string): unknown {
  if (text.trim().length === 0) return undefined;
  const errors: ParseError[] = [];
  const value = parseJsonc(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) throw new TypeError("malformed JSON/JSONC config text");
  return value;
}

function scanConfigSecretText(raw: string, file: string, hits: ConfigSecretHit[]): void {
  try {
    walkJson(parseJsoncText(raw), "", file, hits);
  } catch {
    // Malformed JSON/TOML/raw text: a structural walk is impossible, but a provider
    // token in the raw bytes is still a leak — catch that rather than skip the file.
    const provider = matchProvider(raw);
    if (provider !== undefined) hits.push({ file, key: "", kind: provider });
    else if (hasRawBearerLiteral(raw)) {
      hits.push({ file, key: "", kind: "authorization bearer literal" });
    } else {
      hits.push(...rawSecretKeyHits(raw, file));
    }
  }
}

/**
 * Port of Core's `scanConfigSecrets` over the tree seam. `files` are
 * source-relative POSIX paths the runtime selected (see
 * `collectIncomingMcpConfigFilesV1`); absent files are skipped, an unreadable
 * listed file is `mcp.config-invalid` (fail closed).
 */
export function scanMcpConfigSecretsV1(
  tree: TrustLintTreeV1,
  files: readonly string[],
): TrustLintFindingV1[] {
  const hits: ConfigSecretHit[] = [];
  for (const rel of files) {
    if (!tree.hasFile(rel)) continue;
    const raw = tree.readText(rel);
    if (raw === undefined) {
      hits.push({
        file: rel,
        key: "",
        kind: "MCP config path is not a contained regular file",
        code: "mcp.config-invalid",
      });
      continue;
    }
    scanConfigSecretText(raw, rel, hits);
  }
  return hits.map((hit) => {
    const code = hit.code ?? "mcp.hardcoded-secret";
    const detail =
      code === "mcp.config-invalid"
        ? `${hit.file} could not be safely inspected: ${hit.kind}`
        : `${hit.file}${hit.key ? ` → "${hit.key}"` : ""} holds a ${hit.kind} — move it to an env var referenced as \${ENV_VAR} and rotate the exposed value`;
    return {
      name: code === "mcp.config-invalid" ? "mcp-config-invalid" : MCP_SECRET_RULE_V1,
      verdict: "fail" as const,
      detail,
      code,
      location: { uri: hit.file, startLine: 1 },
      fingerprint: `${code}:${hit.file}:${hit.key}`,
    };
  });
}

/**
 * Port of Core's `collectIncomingMcpConfigFiles`: each incoming MCP config
 * file name present at the tree root or in any directory holding a
 * `SKILL.md`, root first then skill dirs in localeCompare order, deduplicated.
 */
export function collectIncomingMcpConfigFilesV1(tree: TrustLintTreeV1): string[] {
  const skillDirs = [
    ...new Set(
      [...tree.matching((entry) => entry.relativePath.split("/").at(-1) === "SKILL.md")].map(
        (entry) => {
          const rel = entry.relativePath;
          const index = rel.lastIndexOf("/");
          return index === -1 ? "" : rel.slice(0, index);
        },
      ),
    ),
  ].sort((a, b) => a.localeCompare(b));
  const roots = [...new Set(["", ...skillDirs])];
  const out: string[] = [];
  for (const root of roots) {
    for (const name of INCOMING_MCP_CONFIG_FILES_V1) {
      const rel = root.length === 0 ? name : `${root}/${name}`;
      if (tree.hasFile(rel) && !out.includes(rel)) out.push(rel);
    }
  }
  return out;
}
