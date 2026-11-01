import { formats } from "./formats.js";

/** Codes a scan finding can carry (`aih-codes/1`). */
export const scanCodes = Object.freeze([
  "trust.prompt-injection",
  "trust.hidden-unicode",
  "trust.visible-unicode",
  "trust.malicious-code",
  "trust.external-egress",
  "trust.auto-exec-hook",
  "trust.permission-risk",
  "trust.plaintext-secret",
  "trust.mcp-hardcoded-secret",
  "trust.mcp-tool-poisoning",
  "trust.typosquat",
  "trust.dependency-confusion",
  "trust.unpinned-dependency",
  "trust.unmapped-rule",
] as const);

/** Used only in `checkAdvisories` results; never in a scan, SARIF or score. */
export const advisoryCodes = Object.freeze(["trust.known-vulnerability"] as const);

export type ScanCode = (typeof scanCodes)[number];
export type AdvisoryCode = (typeof advisoryCodes)[number];
export type Code = ScanCode | AdvisoryCode;

/**
 * Every tool rule maps to one code. Rules missing from a tool's table become
 * `trust.unmapped-rule` and are still scored. Adapters add their own table here.
 */
export const toolRuleCodes: Readonly<Record<string, Readonly<Record<string, ScanCode>>>> =
  Object.freeze({
    "aih-trust-lint": Object.freeze({
      "trust.prompt-injection": "trust.prompt-injection",
      "trust.hidden-unicode": "trust.hidden-unicode",
      "trust.visible-unicode": "trust.visible-unicode",
      "trust.malicious-code": "trust.malicious-code",
      "trust.external-egress": "trust.external-egress",
      "trust.auto-exec-hook": "trust.auto-exec-hook",
      "trust.permission-risk": "trust.permission-risk",
      "secrets.plaintext-detected": "trust.plaintext-secret",
      "mcp.hardcoded-secret": "trust.mcp-hardcoded-secret",
      "mcp.tool-poisoning": "trust.mcp-tool-poisoning",
      "trust.typosquat": "trust.typosquat",
      "trust.dependency-confusion": "trust.dependency-confusion",
      "trust.unpinned-dependency": "trust.unpinned-dependency",
    } satisfies Record<string, ScanCode>),
  });

export const codes = Object.freeze({
  format: formats.codes,
  scan: scanCodes,
  advisory: advisoryCodes,
  unmapped: "trust.unmapped-rule" as const,
  tools: toolRuleCodes,
});

export function codeForRule(tool: string, ruleId: string): ScanCode {
  const table = Object.hasOwn(toolRuleCodes, tool) ? toolRuleCodes[tool] : undefined;
  if (table !== undefined && Object.hasOwn(table, ruleId)) return table[ruleId] as ScanCode;
  return "trust.unmapped-rule";
}

export function isScanCode(value: unknown): value is ScanCode {
  return typeof value === "string" && (scanCodes as readonly string[]).includes(value);
}
