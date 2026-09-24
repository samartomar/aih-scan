import type { TrustLintFindingV1 } from "./findings.js";
import { contentFindingFingerprintV1 } from "./fingerprint.js";
import type { TrustLintTreeV1 } from "./inventory.js";
import { isMaliciousCodeScanFilePathV1 } from "./script-files.js";

/**
 * Port of Core's `scanNativeMaliciousCode` (`src/trust/detectors.ts`):
 * three raw malicious-code shapes matched per line over script-ish files of
 * at most 512 KiB, with `${IFS…}`/`$IFS` obfuscation normalized to a space
 * before matching. Pure over the tree seam.
 */

const MAX_SCRIPT_SCAN_BYTES = 512 * 1024;

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

/** Port of Core's `scanNativeMaliciousCode` over the tree seam. */
export function scanNativeMaliciousCodeV1(tree: TrustLintTreeV1): TrustLintFindingV1[] {
  const checks: TrustLintFindingV1[] = [];
  const occurrences = new Map<string, number>();
  for (const entry of tree.matching(
    (candidate) =>
      isMaliciousCodeScanFilePathV1(candidate.relativePath) &&
      candidate.size <= MAX_SCRIPT_SCAN_BYTES,
  )) {
    const rel = entry.relativePath;
    const source = tree.readText(rel);
    if (source === undefined) throw new TypeError(`trust-lint: unreadable script file ${rel}`);
    const lines = source.split(/\r?\n/);
    lines.forEach((line, index) => {
      const normalizedLine = normalizeShellWhitespace(line);
      for (const rule of MALICIOUS_PATTERNS) {
        if (rule.pattern.test(normalizedLine)) {
          checks.push(maliciousCodeCheck(occurrences, rel, index + 1, line, rule.label));
        }
      }
    });
  }
  return checks;
}
