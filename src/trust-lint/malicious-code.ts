import type { TrustLintFindingV1 } from "./findings.js";
import { contentFindingFingerprintV1 } from "./fingerprint.js";

/**
 * Three raw malicious-code shapes matched per line, with `${IFS…}`/`$IFS` obfuscation
 * normalized to a space before matching. Applied to routed Code files and inline config
 * commands.
 */

interface MaliciousPattern {
  label: string;
  pattern: RegExp;
}

const MALICIOUS_PATTERNS: MaliciousPattern[] = [
  {
    label: "interactive bash reverse shell over /dev/tcp",
    pattern: /\bbash\s+-i\b.*(?:>&|&>)\s*\/dev\/tcp\/[A-Za-z0-9._-]+\/\d+/,
  },
  {
    label: "base64-decoded payload piped to shell",
    pattern: /\bbase64\b[^\n|;&]*(?:-d|--decode)?[^\n|;&]*\|\s*(?:bash|sh)\b/,
  },
  {
    label: "netcat exec shell",
    pattern: /\bnc(?:at)?\b[^\n]*(?:-e|-c)\s*(?:\/bin\/)?(?:bash|sh)\b/,
  },
];

function normalizeShellWhitespace(line: string): string {
  // Collapse any ${IFS...} parameter-expansion form (plain, #/% removal, :offset
  // substring, //pattern substitution) and bare $IFS to a space, so IFS-obfuscated
  // reverse shells still match the patterns below.
  return line.replace(/\$\{IFS[^}]*\}|\$IFS\b/g, " ");
}

function maliciousCodeCheck(
  occurrences: Map<string, number>,
  rel: string,
  line: number,
  text: string,
  label: string,
): TrustLintFindingV1 {
  const ruleId = `native:${label}`;
  const content = `${text}\0${label}`;
  const key = JSON.stringify(["trust.malicious-code", rel, ruleId, content]);
  const occurrence = occurrences.get(key) ?? 0;
  occurrences.set(key, occurrence + 1);
  return {
    name: "trust.malicious-code",
    verdict: "fail",
    code: "trust.malicious-code",
    detail: `${rel}:${line} — bundled script matches ${label}; static trust gate rejects raw malicious-code shapes`,
    location: { uri: rel, startLine: line },
    fingerprint: contentFindingFingerprintV1({
      code: "trust.malicious-code",
      path: rel,
      ruleId,
      content,
      occurrence,
      displayLine: line,
    }),
  };
}

/**
 * The per-line malicious-code shapes over one text, whatever its path (routed Code files
 * and inline config commands). `lineOffset` places an inline command at its config line.
 */
export function scanMaliciousCodeTextV1(
  rel: string,
  source: string,
  occurrences: Map<string, number> = new Map(),
  lineOffset = 0,
): TrustLintFindingV1[] {
  const checks: TrustLintFindingV1[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((line, index) => {
    const normalizedLine = normalizeShellWhitespace(line);
    for (const rule of MALICIOUS_PATTERNS) {
      if (rule.pattern.test(normalizedLine)) {
        checks.push(maliciousCodeCheck(occurrences, rel, index + 1 + lineOffset, line, rule.label));
      }
    }
  });
  return checks;
}
