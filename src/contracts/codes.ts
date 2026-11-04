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
    /**
     * SkillSpector 2.13.3 rule ids. SC4 (known vulnerable dependency) is not a scan finding:
     * known vulnerabilities come only from `checkAdvisories`. Rules without a clear code
     * (for example SC5, OH2, OH3, TR1-TR3, AE1, AE7) stay `trust.unmapped-rule`.
     */
    skillspector: Object.freeze({
      AR1: "trust.prompt-injection",
      AR2: "trust.prompt-injection",
      AR3: "trust.prompt-injection",
      AS1: "trust.malicious-code",
      AS2: "trust.malicious-code",
      AS3: "trust.malicious-code",
      AST1: "trust.malicious-code",
      AST2: "trust.malicious-code",
      AST3: "trust.malicious-code",
      AST4: "trust.malicious-code",
      AST5: "trust.malicious-code",
      AST6: "trust.malicious-code",
      AST7: "trust.malicious-code",
      AST8: "trust.malicious-code",
      AST9: "trust.malicious-code",
      AST10: "trust.malicious-code",
      BH1: "trust.auto-exec-hook",
      BH2: "trust.external-egress",
      BH3: "trust.permission-risk",
      BH4: "trust.auto-exec-hook",
      DS1: "trust.malicious-code",
      DS2: "trust.malicious-code",
      DS3: "trust.malicious-code",
      DS4: "trust.malicious-code",
      E1: "trust.external-egress",
      E2: "trust.malicious-code",
      E3: "trust.malicious-code",
      E4: "trust.external-egress",
      E5: "trust.external-egress",
      EA1: "trust.permission-risk",
      EA2: "trust.permission-risk",
      EA3: "trust.permission-risk",
      EA4: "trust.permission-risk",
      EA5: "trust.permission-risk",
      LP1: "trust.permission-risk",
      LP2: "trust.permission-risk",
      LP3: "trust.permission-risk",
      LP4: "trust.permission-risk",
      MP1: "trust.prompt-injection",
      MP2: "trust.prompt-injection",
      MP3: "trust.prompt-injection",
      OH1: "trust.malicious-code",
      P1: "trust.prompt-injection",
      P2: "trust.prompt-injection",
      P3: "trust.external-egress",
      P4: "trust.prompt-injection",
      P5: "trust.prompt-injection",
      P6: "trust.prompt-injection",
      P7: "trust.prompt-injection",
      P8: "trust.external-egress",
      P9: "trust.prompt-injection",
      PE1: "trust.permission-risk",
      PE2: "trust.permission-risk",
      PE3: "trust.malicious-code",
      PE4: "trust.permission-risk",
      PE5: "trust.permission-risk",
      RA1: "trust.malicious-code",
      RA2: "trust.malicious-code",
      RP1: "trust.unpinned-dependency",
      RP2: "trust.permission-risk",
      RP3: "trust.unpinned-dependency",
      SC1: "trust.unpinned-dependency",
      SC2: "trust.malicious-code",
      SC3: "trust.malicious-code",
      SC6: "trust.typosquat",
      SC7: "trust.permission-risk",
      SC8: "trust.malicious-code",
      SC9: "trust.malicious-code",
      SC10: "trust.dependency-confusion",
      SSRF1: "trust.external-egress",
      SSRF2: "trust.external-egress",
      SSRF3: "trust.external-egress",
      TM1: "trust.malicious-code",
      TM2: "trust.malicious-code",
      TM3: "trust.permission-risk",
      TM4: "trust.permission-risk",
      TP1: "trust.mcp-tool-poisoning",
      TP2: "trust.mcp-tool-poisoning",
      TP3: "trust.mcp-tool-poisoning",
      TP4: "trust.mcp-tool-poisoning",
      TT1: "trust.malicious-code",
      TT2: "trust.malicious-code",
      TT3: "trust.external-egress",
      TT4: "trust.external-egress",
      TT5: "trust.malicious-code",
      TT6: "trust.malicious-code",
      YR1: "trust.malicious-code",
      YR2: "trust.malicious-code",
      YR3: "trust.malicious-code",
      YR4: "trust.malicious-code",
    } satisfies Record<string, ScanCode>),
  });

/**
 * Codes by a tool's own finding category, for tools whose rule ids are open-ended (Cisco
 * skill-scanner names YARA and signature rules dynamically). A rule id in
 * {@link toolRuleCodes} wins; otherwise the finding's category decides; otherwise
 * `trust.unmapped-rule`.
 */
export const toolCategoryCodes: Readonly<Record<string, Readonly<Record<string, ScanCode>>>> =
  Object.freeze({
    cisco: Object.freeze({
      autonomy_abuse: "trust.permission-risk",
      command_injection: "trust.malicious-code",
      data_exfiltration: "trust.external-egress",
      hardcoded_secrets: "trust.plaintext-secret",
      malware: "trust.malicious-code",
      obfuscation: "trust.malicious-code",
      prompt_injection: "trust.prompt-injection",
      supply_chain_attack: "trust.malicious-code",
      tool_chaining_abuse: "trust.malicious-code",
      unauthorized_tool_use: "trust.permission-risk",
      unicode_steganography: "trust.hidden-unicode",
    } satisfies Record<string, ScanCode>),
  });

export const codes = Object.freeze({
  format: formats.codes,
  scan: scanCodes,
  advisory: advisoryCodes,
  unmapped: "trust.unmapped-rule" as const,
  tools: toolRuleCodes,
  categories: toolCategoryCodes,
});

export function codeForRule(tool: string, ruleId: string, category?: string): ScanCode {
  const table = Object.hasOwn(toolRuleCodes, tool) ? toolRuleCodes[tool] : undefined;
  if (table !== undefined && Object.hasOwn(table, ruleId)) return table[ruleId] as ScanCode;
  const categories = Object.hasOwn(toolCategoryCodes, tool) ? toolCategoryCodes[tool] : undefined;
  if (category !== undefined && categories !== undefined && Object.hasOwn(categories, category))
    return categories[category] as ScanCode;
  return "trust.unmapped-rule";
}

export function isScanCode(value: unknown): value is ScanCode {
  return typeof value === "string" && (scanCodes as readonly string[]).includes(value);
}
