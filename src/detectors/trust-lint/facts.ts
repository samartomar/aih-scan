import { codeUnitCompare } from "../../contract/strict-json-v1.js";
import type {
  TrustLintArtifactV1,
  TrustLintFileFactsV1,
  TrustLintLintLineV1,
  TrustLintRunFactsV1,
} from "./findings.js";
import type { TrustLintTreeEntryV1, TrustLintTreeV1 } from "./inventory.js";
import {
  classifyUnicodeRiskV1,
  isStrictUnicodeSurfaceV1,
  scanTrustDocumentV1,
  shouldScanTrustDocV1,
} from "./lint.js";
import { isInstallScriptEvidenceFilePathV1 } from "./script-files.js";

/**
 * C2a §2.5/§2.6 — the per-run and per-file facts Core's classification
 * consumes from `detector.aih-trust-lint`, replacing every lint/detection
 * call Core still made for classification:
 *
 * - run facts (`runs[0].properties["aih-trust/v1"]`): `trustDocumentCount`
 *   (selected paths where `shouldScanTrustDocV1` holds, for Core's summary
 *   check) and `repositoryLicenseFile` (the first of LICENSE, LICENSE.md,
 *   LICENSE.txt, COPYING present at the root as a regular file, stat
 *   following links — replacing Core's `repositoryLicensePath`);
 * - per-file facts (`runs[0].artifacts[]`, one entry per regular file in the
 *   sealed tree, skip directories included, in tree order): the ports of
 *   `isStrictUnicodeSurface`, `reviewableLegalTextContent`,
 *   `classifyUnicodeRisk`, the corroboration `lintTrustDocument` line index,
 *   and the file half of `skillspectorAdvisory`'s YR4 Corepack carve-out.
 *
 * Facts are computed over the full file text with no size bound below the
 * 16 MiB file bound; a file above the bound (or one that cannot be read) is
 * listed with `unreadable: true` and no other properties.
 */

/** Scan's per-file read bound (§2.6): files larger than this are `unreadable`. */
export const TRUST_LINT_MAX_FACT_FILE_BYTES_V1 = 16 * 1024 * 1024;

const MAX_LEGAL_TEXT_BYTES = 2 * 1024 * 1024;
const LEGAL_TEXT_BASENAME = /^(?:LICENSE|COPYING|NOTICE)(?:$|[._-])/i;
const REPOSITORY_LICENSE_FILES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"] as const;

/** Port of Core's `NON_TEXT_LEGAL_EXTENSIONS` (`src/trust/detectors.ts`). */
const NON_TEXT_LEGAL_EXTENSIONS = new Set([
  ".bat",
  ".bin",
  ".c",
  ".cc",
  ".cfg",
  ".cjs",
  ".cmd",
  ".com",
  ".conf",
  ".cpp",
  ".cs",
  ".dll",
  ".dylib",
  ".env",
  ".exe",
  ".fish",
  ".go",
  ".h",
  ".hpp",
  ".ini",
  ".jar",
  ".java",
  ".js",
  ".json",
  ".jsonc",
  ".jsx",
  ".kt",
  ".kts",
  ".mjs",
  ".php",
  ".pl",
  ".properties",
  ".ps1",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".sql",
  ".so",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
  ".wasm",
  ".xml",
  ".zsh",
]);

/**
 * Port of Core's six `SKILLSPECTOR_YR4_*` Gate-B co-signal regexes
 * (`src/trust/detectors.ts`), in Core's order: hidden HTML, hidden Markdown,
 * data URI, long opaque blob, parameter injection, directional control.
 */
const SKILLSPECTOR_YR4_CO_SIGNALS: readonly RegExp[] = [
  /<!--[^>]{0,240}(?:SYSTEM|IGNORE|OVERRIDE|DEVELOPER|ASSISTANT)[^>]{0,240}-->/i,
  /\[\/\/\]:\s*#\s*\([^)]{0,240}(?:SYSTEM|IGNORE|OVERRIDE|DEVELOPER|ASSISTANT)[^)]{0,240}\)/i,
  /data:text\/[a-zA-Z0-9.+-]+;base64,/i,
  /[A-Za-z0-9+/]{120,}={0,2}/,
  /(?:parameter|argument|description)[\s\S]{0,160}(?:ignore previous|override safety|send to|transmit|exfiltrate|SYSTEM:)/i,
  /[\u200b-\u200d\u202d\u202e]/,
];

/** Port of Core's `COREPACK_PACKAGE_MANAGER_INTEGRITY`. */
const COREPACK_PACKAGE_MANAGER_INTEGRITY = /^[A-Za-z0-9._-]+@[^+\s"]+\+sha512\.[a-f0-9]{128}$/i;

function baseName(rel: string): string {
  return rel.split("/").at(-1) ?? "";
}

/** node:path `extname` semantics: the final dot must not be the first character. */
function extNameLower(name: string): string {
  const index = name.lastIndexOf(".");
  return index > 0 ? name.slice(index).toLowerCase() : "";
}

/**
 * Port of Core's `reviewableLegalTextContent` predicate
 * (`src/trust/detectors.ts` ~1650), over the tree seam. The exec bit is
 * always false on Windows; `realpathContained` covers Core's realpath
 * containment check; the NUL-byte and `#!` checks read the same bytes as
 * Core through the UTF-8 text (NUL decodes to U+0000 and `#!` is ASCII).
 */
function isLegalText(entry: TrustLintTreeEntryV1, text: string): boolean {
  const rel = entry.relativePath;
  if (!LEGAL_TEXT_BASENAME.test(baseName(rel))) return false;
  if (isStrictUnicodeSurfaceV1(rel)) return false;
  if (isInstallScriptEvidenceFilePathV1(rel)) return false;
  if (NON_TEXT_LEGAL_EXTENSIONS.has(extNameLower(baseName(rel)))) return false;
  if (!entry.realpathContained) return false;
  if (entry.size > MAX_LEGAL_TEXT_BYTES) return false;
  if (entry.executable) return false;
  if (text.includes("\u0000")) return false;
  return !text.startsWith("#!");
}

/**
 * Port of the file half of Core's `skillspectorAdvisory` /
 * `hasSkillspectorYr4PoisoningSignal`: the YR4 Corepack carve-out holds when
 * the file parses as a JSON object, `packageManager` matches the pinned
 * Corepack integrity shape, its `JSON.stringify` encoding occurs in the
 * source, and after replacing that first occurrence with `""` none of the
 * six Gate-B co-signals match.
 */
function hasYr4CorepackIntegrityOnly(source: string): boolean {
  let manifest: unknown;
  try {
    manifest = JSON.parse(source);
  } catch {
    return false;
  }
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) return false;
  const packageManager = (manifest as Record<string, unknown>).packageManager;
  if (
    typeof packageManager !== "string" ||
    !COREPACK_PACKAGE_MANAGER_INTEGRITY.test(packageManager)
  )
    return false;
  const encoded = JSON.stringify(packageManager);
  if (!source.includes(encoded)) return false;
  const without = source.replace(encoded, '""');
  return !SKILLSPECTOR_YR4_CO_SIGNALS.some((signal) => signal.test(without));
}

/** Core's `classifyUnicodeRisk` as the plain `{category, code, reason}` fact, or `null`. */
function unicodeRiskOf(rel: string, text: string): TrustLintFileFactsV1["unicodeRisk"] {
  const risk = classifyUnicodeRiskV1(rel, text);
  return risk === undefined
    ? null
    : { category: risk.category, code: risk.code, reason: risk.reason };
}

/** Whole-file `lintTrustDocument`, indexed by line: prompt-injection / external-egress codes. */
function lintLinesOf(rel: string, text: string): TrustLintLintLineV1[] {
  const codesByLine = new Map<number, Set<string>>();
  for (const finding of scanTrustDocumentV1(rel, text)) {
    if (finding.code !== "trust.prompt-injection" && finding.code !== "trust.external-egress")
      continue;
    const line = finding.location.startLine;
    const codes = codesByLine.get(line) ?? new Set<string>();
    codes.add(finding.code);
    codesByLine.set(line, codes);
  }
  return [...codesByLine.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([line, codes]) => ({ line, codes: [...codes].sort(codeUnitCompare) }));
}

/** §2.6 run facts: trust-document count over the selection, repository license file. */
export function trustLintRunFactsV1(
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintRunFactsV1 {
  let trustDocumentCount = 0;
  for (const rel of selection) if (shouldScanTrustDocV1(rel)) trustDocumentCount++;
  let repositoryLicenseFile: string | null = null;
  for (const name of REPOSITORY_LICENSE_FILES) {
    // Core stats the candidate, following links, so a symlink to a regular
    // file counts — exactly what the tree lists as a file entry.
    if (tree.hasFile(name)) {
      repositoryLicenseFile = name;
      break;
    }
  }
  return Object.freeze({ trustDocumentCount, repositoryLicenseFile });
}

/**
 * §2.6 per-file facts: one artifact entry per regular file in the sealed
 * tree (skip directories included), in tree order. Files above the 16 MiB
 * bound, or files that cannot be read, are listed with `unreadable: true`.
 */
export function trustLintTreeArtifactFactsV1(
  tree: TrustLintTreeV1,
): readonly TrustLintArtifactV1[] {
  const artifacts: TrustLintArtifactV1[] = [];
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    const text = entry.size > TRUST_LINT_MAX_FACT_FILE_BYTES_V1 ? undefined : tree.readText(rel);
    if (text === undefined) {
      artifacts.push(Object.freeze({ uri: rel, facts: Object.freeze({ unreadable: true }) }));
      continue;
    }
    const facts: TrustLintFileFactsV1 = {
      strictUnicodeSurface: isStrictUnicodeSurfaceV1(rel),
      legalText: isLegalText(entry, text),
      unicodeRisk: unicodeRiskOf(rel, text),
      lintLines: lintLinesOf(rel, text),
      ...(baseName(rel) === "package.json" && hasYr4CorepackIntegrityOnly(text)
        ? { yr4CorepackIntegrityOnly: true as const }
        : {}),
    };
    artifacts.push(Object.freeze({ uri: rel, facts: Object.freeze(facts) }));
  }
  return Object.freeze(artifacts);
}
