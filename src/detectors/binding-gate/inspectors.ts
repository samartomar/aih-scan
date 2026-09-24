import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import type { TrustLintTreeV1 } from "../trust-lint/inventory.js";
import { isStrictUnicodeSurfaceV1 } from "../trust-lint/lint.js";
import {
  isInstallScriptEvidenceFilePathV1,
  isMaliciousCodeScanFilePathV1,
} from "../trust-lint/script-files.js";
import {
  BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1,
  BINDING_GATE_MAX_SCAN_BYTES_V1,
  BINDING_GATE_STRUCTURE_MAX_FILE_BYTES_V1,
  BINDING_GATE_STRUCTURE_MAX_FILES_V1,
  type BindingGateDimensionReportV1,
  type BindingGateFindingV1,
  type BindingGateSeverityV1,
} from "./findings.js";

/**
 * The nine inventory-driven FAST-tier inspectors of Core's
 * `src/binding/scan-gate.ts` (`inspectStructure`, `inspectScripts`,
 * `inspectBinaries`, `inspectHooks`, `inspectMcp`, `inspectLicenses` and the
 * `scanForPatterns`-driven network-update / telemetry / write-destinations),
 * ported verbatim over the shared `TrustLintTreeV1` tree seam instead of
 * Core's `{treePath, inventory}` context. Codes, severities, detail strings,
 * ordering (inventory order, then pattern order), and caps (50 findings per
 * dimension, 512 KiB text scan, 50 MiB / 20 000-file structure limits) are
 * byte-identical to Core.
 *
 * File content is read through `tree.readText` (UTF-8 with U+FFFD
 * replacement). Core's extensionless-binary NUL sniff reads raw bytes; a NUL
 * byte is valid UTF-8 and decodes to U+0000, so the text read detects exactly
 * the same files.
 */

interface SurfacePattern {
  label: string;
  pattern: RegExp;
}

// FAST-tier static heuristics over text surfaces (Core's tables, verbatim).
const NETWORK_PATTERNS: readonly SurfacePattern[] = [
  { label: "outbound HTTP(S) URL", pattern: /https?:\/\/[^\s"'`)]+/i },
  {
    label: "curl/wget/Invoke-WebRequest download",
    pattern: /\b(?:curl|wget|Invoke-WebRequest|iwr)\b/i,
  },
  {
    label: "network client call",
    pattern:
      /\b(?:fetch|axios|got|node-fetch|urllib|requests\.(?:get|post|put))\b|https?\.request\b/i,
  },
  {
    label: "npm registry version check",
    pattern: /registry\.npmjs\.org|\bnpm\s+(?:view|outdated|dist-tag)\b/i,
  },
  {
    label: "auto-update marker",
    pattern: /\b(?:auto[-_]?update|self[-_]?update|check[-_ ]for[-_ ]updates?)\b/i,
  },
];
const TELEMETRY_PATTERNS: readonly SurfacePattern[] = [
  {
    label: "telemetry/analytics vendor",
    pattern:
      /\b(?:telemetry|analytics|posthog|segment(?:\.io)?|sentry|mixpanel|amplitude|datadog|google-analytics|gtag)\b/i,
  },
  {
    label: "telemetry env toggle",
    pattern: /\b[A-Z0-9_]*(?:TELEMETRY|ANALYTICS)[A-Z0-9_]*\b|\bDO_NOT_TRACK\b/,
  },
];
const WRITE_DEST_PATTERNS: readonly SurfacePattern[] = [
  {
    label: "redirect to HOME/absolute path",
    pattern: /(?:>>?|\btee\b)\s*["']?(?:~\/|\/[A-Za-z]|\$HOME|\$\{HOME\}|%USERPROFILE%)/,
  },
  {
    label: "write to HOME/absolute path",
    pattern:
      /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*["'`](?:~\/|\/|\$\{?HOME)/,
  },
  {
    label: "HOME/homedir reference",
    pattern: /\$HOME\b|\$\{HOME\}|%USERPROFILE%|os\.homedir\(\)|\bhomedir\(\)/,
  },
];

const BINARY_EXTENSIONS = new Set([
  ".a",
  ".apk",
  ".bin",
  ".class",
  ".deb",
  ".dll",
  ".dmg",
  ".dylib",
  ".exe",
  ".img",
  ".jar",
  ".lib",
  ".msi",
  ".node",
  ".o",
  ".obj",
  ".pyc",
  ".pyd",
  ".rpm",
  ".so",
  ".wasm",
]);

const HOOK_EVENT_KEYS = new Set([
  "SessionStart",
  "SessionEnd",
  "PreToolUse",
  "PostToolUse",
  "UserPromptSubmit",
  "Stop",
  "SubagentStop",
  "Notification",
  "PreCompact",
]);

const LICENSE_NAME = /^(?:LICENSE|LICENCE|COPYING|NOTICE)(?:\..+)?$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonRecord(text: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(text);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

// node:path `extname` semantics, re-implemented over POSIX paths: the final
// dot must not be the basename's first character.
function extnameLower(rel: string): string {
  const name = rel.split("/").at(-1) ?? "";
  const index = name.lastIndexOf(".");
  return index > 0 ? name.slice(index).toLowerCase() : "";
}

// Core's `isDocSurface` (scan-gate.ts), verbatim; also the doc-surface half of
// the content-risk detection pass.
export function isBindingGateDocSurfaceV1(rel: string): boolean {
  const name = rel.split("/").at(-1) ?? "";
  if (name === "SKILL.md") return true;
  if (!rel.includes("/") && ["AGENTS.md", "CLAUDE.md", "GEMINI.md"].includes(name)) return true;
  return name.toLowerCase().endsWith(".md");
}

function isExecutableSurface(rel: string): boolean {
  return isMaliciousCodeScanFilePathV1(rel) || isInstallScriptEvidenceFilePathV1(rel);
}

function isScannableTextSurface(rel: string): boolean {
  return (
    isExecutableSurface(rel) || isStrictUnicodeSurfaceV1(rel) || isBindingGateDocSurfaceV1(rel)
  );
}

function fileFinding(
  code: string,
  severity: BindingGateSeverityV1,
  rel: string,
  detail: string,
): BindingGateFindingV1 {
  // Core's `ScanFinding` carries no line for these file-level findings; the
  // SARIF locator pins the exact file at line 1 (the §1.4 default).
  return { code, severity, detail, coverage: "complete", location: { uri: rel, startLine: 1 } };
}

function freezeReport(report: BindingGateDimensionReportV1): BindingGateDimensionReportV1 {
  return deepFreezeStrictJsonV1(structuredClone(report));
}

// Core's `scanForPatterns`, verbatim (inventory order, then pattern order).
function scanForPatterns(
  dimension: string,
  tree: TrustLintTreeV1,
  patterns: readonly SurfacePattern[],
  severityFor: (executable: boolean) => BindingGateSeverityV1,
  onlyExecutable = false,
): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  for (const entry of tree.files) {
    if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
    const rel = entry.relativePath;
    const executable = isExecutableSurface(rel);
    if (onlyExecutable ? !executable : !isScannableTextSurface(rel)) continue;
    if (entry.size > BINDING_GATE_MAX_SCAN_BYTES_V1) continue;
    const text = tree.readText(rel);
    if (text === undefined) continue;
    for (const { label, pattern } of patterns) {
      if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
      if (pattern.test(text)) {
        findings.push(
          fileFinding(`binding.${dimension}`, severityFor(executable), rel, `${rel}: ${label}`),
        );
      }
    }
  }
  return freezeReport({ dimension, status: "produced", findings });
}

/** Core's `inspectStructure` (50 MiB per-file / 20 000-file limits). */
export function inspectBindingGateStructureV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  if (tree.files.length > BINDING_GATE_STRUCTURE_MAX_FILES_V1) {
    findings.push({
      code: "binding.structure.file-count",
      severity: "info",
      detail: `tree contains ${tree.files.length} files (over ${BINDING_GATE_STRUCTURE_MAX_FILES_V1})`,
      coverage: "complete",
    });
  }
  for (const entry of tree.files) {
    if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
    if (entry.size > BINDING_GATE_STRUCTURE_MAX_FILE_BYTES_V1) {
      findings.push({
        code: "binding.structure.large-file",
        severity: "low",
        detail: `${entry.relativePath}: unusually large file (${entry.size} bytes)`,
        coverage: "complete",
        location: { uri: entry.relativePath, startLine: 1 },
      });
    }
  }
  return freezeReport({ dimension: "structure", status: "produced", findings });
}

/** Core's `inspectScripts` (install scripts at medium, presence roll-up at info). */
export function inspectBindingGateScriptsV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  const scripts: string[] = [];
  const installScripts: string[] = [];
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    if (isMaliciousCodeScanFilePathV1(rel)) scripts.push(rel);
    if (isInstallScriptEvidenceFilePathV1(rel)) installScripts.push(rel);
  }
  const findings: BindingGateFindingV1[] = installScripts
    .slice(0, BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1)
    .map((rel) =>
      fileFinding(
        "binding.scripts.install-script",
        "medium",
        rel,
        `${rel}: install/setup script (executes on install)`,
      ),
    );
  if (scripts.length > 0) {
    const shown = scripts.slice(0, 5).join(", ");
    findings.push({
      code: "binding.scripts.present",
      severity: "info",
      detail: `${scripts.length} script file(s): ${shown}${scripts.length > 5 ? ", …" : ""}`,
      coverage: "complete",
    });
  }
  return freezeReport({ dimension: "scripts", status: "produced", findings });
}

/** Core's `inspectBinaries` (extension table plus the extensionless NUL sniff). */
export function inspectBindingGateBinariesV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  for (const entry of tree.files) {
    if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
    const rel = entry.relativePath;
    const ext = extnameLower(rel);
    let binary = BINARY_EXTENSIONS.has(ext);
    if (!binary && ext === "" && entry.size > 0 && entry.size <= BINDING_GATE_MAX_SCAN_BYTES_V1) {
      const text = tree.readText(rel);
      binary = text !== undefined && text.includes("\0");
    }
    if (binary) {
      findings.push(
        fileFinding("binding.binaries.blob", "medium", rel, `${rel}: binary/executable blob`),
      );
    }
  }
  return freezeReport({ dimension: "binaries", status: "produced", findings });
}

function hookEventsIn(text: string): string[] {
  const parsed = parseJsonRecord(text);
  if (parsed === undefined) return [];
  if (isRecord(parsed.hooks)) return Object.keys(parsed.hooks);
  return Object.keys(parsed).filter((key) => HOOK_EVENT_KEYS.has(key));
}

/** Core's `inspectHooks` (any file under a `hooks/` directory; settings hook keys). */
export function inspectBindingGateHooksV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  for (const entry of tree.files) {
    if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
    const rel = entry.relativePath;
    const parts = rel.split("/");
    const name = parts.at(-1) ?? "";
    if (parts.slice(0, -1).includes("hooks")) {
      findings.push(
        fileFinding("binding.hooks.dir", "medium", rel, `${rel}: file under a hooks/ surface`),
      );
      continue;
    }
    if (!/^settings.*\.json$/.test(name) && name !== ".claude.json") continue;
    if (entry.size > BINDING_GATE_MAX_SCAN_BYTES_V1) continue;
    const text = tree.readText(rel);
    if (text === undefined) continue;
    const events = hookEventsIn(text);
    if (events.length > 0) {
      findings.push(
        fileFinding(
          "binding.hooks.settings",
          "medium",
          rel,
          `${rel}: hook events ${events.join(", ")}`,
        ),
      );
    }
  }
  return freezeReport({ dimension: "hooks", status: "produced", findings });
}

function mcpServersIn(text: string): string[] {
  const parsed = parseJsonRecord(text);
  if (parsed === undefined) return [];
  const out: string[] = [];
  for (const key of ["mcpServers", "servers", "mcp"]) {
    const value = parsed[key];
    if (isRecord(value)) out.push(...Object.keys(value));
  }
  return out;
}

/** Core's `inspectMcp` (server names, else config-present for MCP files). */
export function inspectBindingGateMcpV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  const findings: BindingGateFindingV1[] = [];
  for (const entry of tree.files) {
    if (findings.length >= BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1) break;
    const rel = entry.relativePath;
    const name = rel.split("/").at(-1) ?? "";
    const isMcpFile = name === ".mcp.json" || name === "mcp.json";
    const isSettings = /^settings.*\.json$/.test(name) || name === ".claude.json";
    if (!isMcpFile && !isSettings) continue;
    if (entry.size > BINDING_GATE_MAX_SCAN_BYTES_V1) continue;
    const text = tree.readText(rel);
    if (text === undefined) continue;
    const servers = mcpServersIn(text);
    if (servers.length > 0) {
      findings.push(
        fileFinding(
          "binding.mcp.declaration",
          "medium",
          rel,
          `${rel}: MCP servers ${servers.slice(0, 5).join(", ")}`,
        ),
      );
    } else if (isMcpFile) {
      findings.push(
        fileFinding("binding.mcp.declaration", "medium", rel, `${rel}: MCP config present`),
      );
    }
  }
  return freezeReport({ dimension: "mcp", status: "produced", findings });
}

/** Core's `inspectLicenses` (LICENSE-style file or package.json license field). */
export function inspectBindingGateLicensesV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  let hasLicenseFile = false;
  let hasLicenseField = false;
  for (const entry of tree.files) {
    const name = entry.relativePath.split("/").at(-1) ?? "";
    if (LICENSE_NAME.test(name)) hasLicenseFile = true;
    if (name === "package.json" && entry.size <= BINDING_GATE_MAX_SCAN_BYTES_V1) {
      const license = parseJsonRecord(tree.readText(entry.relativePath) ?? "")?.license;
      if (typeof license === "string" && license.trim().length > 0) hasLicenseField = true;
    }
  }
  const findings: BindingGateFindingV1[] =
    hasLicenseFile || hasLicenseField
      ? []
      : [
          {
            code: "binding.licenses.missing",
            severity: "info",
            detail: "no LICENSE file or package.json license field found",
            coverage: "complete",
          },
        ];
  return freezeReport({ dimension: "licenses", status: "produced", findings });
}

/** Core's `network-update` inspector (`NETWORK_PATTERNS`; executable surfaces rate medium). */
export function inspectBindingGateNetworkUpdateV1(
  tree: TrustLintTreeV1,
): BindingGateDimensionReportV1 {
  return scanForPatterns("network-update", tree, NETWORK_PATTERNS, (exec) =>
    exec ? "medium" : "low",
  );
}

/** Core's `telemetry` inspector (`TELEMETRY_PATTERNS`; executable surfaces rate medium). */
export function inspectBindingGateTelemetryV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1 {
  return scanForPatterns("telemetry", tree, TELEMETRY_PATTERNS, (exec) =>
    exec ? "medium" : "low",
  );
}

/** Core's `write-destinations` inspector (`WRITE_DEST_PATTERNS`, executable surfaces only). */
export function inspectBindingGateWriteDestinationsV1(
  tree: TrustLintTreeV1,
): BindingGateDimensionReportV1 {
  return scanForPatterns("write-destinations", tree, WRITE_DEST_PATTERNS, () => "medium", true);
}
