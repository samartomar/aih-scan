import type { TrustLintFindingV1 } from "./findings.js";
import { contentFindingFingerprintV1 } from "./fingerprint.js";
import { parseFrontmatterYamlV1 } from "./frontmatter-yaml.js";
import type { TrustLintTreeV1 } from "./inventory.js";

/**
 * Port of Core's `src/trust/manifest.ts` checks (`trust.auto-exec-hook` and
 * `trust.permission-risk`): SKILL/agent/command frontmatter permission grants,
 * `!` auto-run lines, package.json lifecycle scripts, `.npmrc`
 * `ignore-scripts=false`, settings hooks, and the `.claude/hooks` directory.
 * Runs against the inventory/file-read seam instead of the filesystem. The
 * `yaml` dependency is replaced by the fail-closed subset parser in
 * `frontmatter-yaml.ts` (any unsupported YAML shape — anchors, aliases,
 * deeper nesting — yields Core's "unparseable YAML frontmatter" finding).
 */

type ManifestRiskCode = Extract<
  import("./findings.js").TrustLintCheckCodeV1,
  "trust.auto-exec-hook" | "trust.permission-risk"
>;

const AUTO_EXEC_CODE: ManifestRiskCode = "trust.auto-exec-hook";
const PERMISSION_RISK_CODE: ManifestRiskCode = "trust.permission-risk";
const LIFECYCLE_SCRIPTS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
]);

interface ManifestCheckDraft {
  code: ManifestRiskCode;
  path: string;
  line: number;
  detail: string;
}

function linesOf(source: string): string[] {
  return source.split(/\r?\n/);
}

function lineText(source: string, line: number): string {
  return linesOf(source)[line - 1] ?? "";
}

function lineForNeedle(source: string, needle: string): number {
  const lines = linesOf(source);
  const found = lines.findIndex((line) => line.includes(needle));
  return found >= 0 ? found + 1 : 1;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFrontmatterDoc(rel: string): boolean {
  const parts = rel.split("/");
  const name = parts.at(-1) ?? "";
  if (name === "SKILL.md") return true;
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || name.slice(dot).toLowerCase() !== ".md") return false;
  return parts.includes("agents") || parts.includes("commands");
}

function isSkillDoc(rel: string): boolean {
  return rel.split("/").at(-1) === "SKILL.md";
}

function isDocumentationMirror(rel: string): boolean {
  return rel.split("/")[0]?.toLowerCase() === "docs";
}

interface Frontmatter {
  yaml: string;
  endLine: number;
}

function leadingFrontmatter(source: string): Frontmatter | undefined {
  const lines = linesOf(source);
  if (lines[0]?.trim() !== "---") return undefined;
  for (let index = 1; index < lines.length; index++) {
    if (lines[index]?.trim() === "---") {
      return {
        yaml: lines.slice(1, index).join("\n"),
        endLine: index + 1,
      };
    }
  }
  return { yaml: lines.slice(1).join("\n"), endLine: 1 };
}

function containsBashWildcard(value: unknown): boolean {
  if (value === undefined) return false;
  if (typeof value === "string") {
    return value
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .some((part) => part === "Bash" || /^Bash\([^)]*\*[^)]*\)$/.test(part));
  }
  if (Array.isArray(value)) return value.some((item) => containsBashWildcard(item));
  return true;
}

function frontmatterLine(source: string, key: string, fallbackLine: number): number {
  const lines = linesOf(source);
  const found = lines.findIndex(
    (line, index) => index > 0 && line.trimStart().startsWith(`${key}:`),
  );
  return found >= 0 ? found + 1 : fallbackLine;
}

function scanFrontmatter(rel: string, source: string): ManifestCheckDraft[] {
  const frontmatter = leadingFrontmatter(source);
  if (frontmatter === undefined) return [];
  if (frontmatter.endLine === 1) {
    return [
      {
        code: AUTO_EXEC_CODE,
        path: rel,
        line: 1,
        detail: "unparseable YAML frontmatter in trust document",
      },
    ];
  }

  let parsed: unknown;
  try {
    parsed = parseFrontmatterYamlV1(frontmatter.yaml);
  } catch {
    return [
      {
        code: AUTO_EXEC_CODE,
        path: rel,
        line: 1,
        detail: "unparseable YAML frontmatter in trust document",
      },
    ];
  }
  if (!isRecord(parsed)) return [];

  const checks: ManifestCheckDraft[] = [];
  const allowedTools = parsed["allowed-tools"];
  if (isRecord(allowedTools)) {
    checks.push({
      code: AUTO_EXEC_CODE,
      path: rel,
      line: frontmatterLine(source, "allowed-tools", 1),
      detail: "frontmatter allowed-tools has an invalid map shape",
    });
  } else if (containsBashWildcard(allowedTools)) {
    checks.push({
      code: PERMISSION_RISK_CODE,
      path: rel,
      line: frontmatterLine(source, "allowed-tools", 1),
      detail: "frontmatter allowed-tools grants broad Bash permission",
    });
  }
  if (parsed.permissionMode === "bypassPermissions") {
    checks.push({
      code: AUTO_EXEC_CODE,
      path: rel,
      line: frontmatterLine(source, "permissionMode", 1),
      detail: "frontmatter permissionMode bypasses permissions",
    });
  }
  if (parsed["dangerously-skip-permissions"] === true) {
    checks.push({
      code: AUTO_EXEC_CODE,
      path: rel,
      line: frontmatterLine(source, "dangerously-skip-permissions", 1),
      detail: "frontmatter dangerously skips permissions",
    });
  }
  return checks;
}

function skillBodyStartLine(source: string): number {
  const frontmatter = leadingFrontmatter(source);
  if (frontmatter === undefined || frontmatter.endLine === 1) return 1;
  return frontmatter.endLine + 1;
}

function scanBangAutoRun(rel: string, source: string): ManifestCheckDraft[] {
  const checks: ManifestCheckDraft[] = [];
  const lines = linesOf(source);
  const startLine = skillBodyStartLine(source);
  for (let index = startLine - 1; index < lines.length; index++) {
    const text = lines[index] ?? "";
    const booleanNegation = /^\s*![A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\(/.test(text);
    if (/^\s*!(?!\[)/.test(text) && !booleanNegation) {
      checks.push({
        code: AUTO_EXEC_CODE,
        path: rel,
        line: index + 1,
        detail: "SKILL body contains a leading ! auto-run line",
      });
    }
  }
  return checks;
}

function scanPackageJson(rel: string, source: string): ManifestCheckDraft[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return [
      {
        code: AUTO_EXEC_CODE,
        path: rel,
        line: 1,
        detail: "unparseable package.json in trust source",
      },
    ];
  }
  if (!isRecord(parsed) || !isRecord(parsed.scripts)) return [];

  const checks: ManifestCheckDraft[] = [];
  for (const name of Object.keys(parsed.scripts).sort()) {
    if (!LIFECYCLE_SCRIPTS.has(name)) continue;
    checks.push(
      name === "prepublishOnly"
        ? {
            code: PERMISSION_RISK_CODE,
            path: rel,
            line: lineForNeedle(source, `"${name}"`),
            detail:
              "package.json prepublishOnly script executes only during an explicit publish workflow",
          }
        : {
            code: AUTO_EXEC_CODE,
            path: rel,
            line: lineForNeedle(source, `"${name}"`),
            detail: `package.json lifecycle script ${name} can execute during install/publish`,
          },
    );
  }
  return checks;
}

function scanNpmrc(rel: string, source: string): ManifestCheckDraft[] {
  const checks: ManifestCheckDraft[] = [];
  for (const [index, text] of linesOf(source).entries()) {
    if (/^\s*ignore-scripts\s*=\s*false\s*(?:[#;].*)?$/i.test(text)) {
      checks.push({
        code: AUTO_EXEC_CODE,
        path: rel,
        line: index + 1,
        detail: ".npmrc explicitly enables package scripts",
      });
    }
  }
  return checks;
}

function scanSettingsHooks(rel: string, source: string): ManifestCheckDraft[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return [];
  }
  if (!isRecord(parsed) || !Object.hasOwn(parsed, "hooks")) return [];
  return [
    {
      code: AUTO_EXEC_CODE,
      path: rel,
      line: lineForNeedle(source, '"hooks"'),
      detail: "settings file declares hooks that may auto-execute",
    },
  ];
}

function isSettingsPath(rel: string): boolean {
  return rel === "settings.json" || rel === ".claude/settings.json";
}

function toFinding(
  tree: TrustLintTreeV1,
  occurrences: Map<string, number>,
  draft: ManifestCheckDraft,
): TrustLintFindingV1 {
  const text = tree.readText(draft.path);
  // Core re-reads the file when fingerprinting; an unreadable path (the
  // .claude/hooks directory check) fingerprints against the path itself.
  const lineContent = text === undefined ? draft.path : lineText(text, draft.line);
  const ruleId = draft.detail;
  const content = `${lineContent}\0${ruleId}`;
  const key = JSON.stringify([draft.code, draft.path, ruleId, content]);
  const occurrence = occurrences.get(key) ?? 0;
  occurrences.set(key, occurrence + 1);
  return {
    name: draft.code,
    verdict: "fail",
    detail: `${draft.path}:${draft.line} — ${draft.detail}`,
    code: draft.code,
    location: { uri: draft.path, startLine: draft.line },
    fingerprint: contentFindingFingerprintV1({
      code: draft.code,
      path: draft.path,
      ruleId,
      content,
      occurrence,
      displayLine: draft.line,
    }),
  };
}

/** Port of Core's `scanTrustManifests` over the tree seam. */
export function scanTrustManifestsV1(tree: TrustLintTreeV1): TrustLintFindingV1[] {
  const drafts: ManifestCheckDraft[] = [];
  // .claude/hooks directory can auto-execute hook commands.
  if (tree.isDirectory(".claude/hooks")) {
    drafts.push({
      code: AUTO_EXEC_CODE,
      path: ".claude/hooks",
      line: 1,
      detail: ".claude/hooks directory can auto-execute hook commands",
    });
  }
  for (const entry of tree.files) {
    const rel = entry.relativePath;
    if (isDocumentationMirror(rel)) continue;
    const name = rel.split("/").at(-1) ?? "";
    const scansFrontmatter = isFrontmatterDoc(rel);
    const scansSkillBody = isSkillDoc(rel);
    const scansPackage = name === "package.json";
    const scansNpmrc = name === ".npmrc";
    const scansSettings = isSettingsPath(rel);
    if (!scansFrontmatter && !scansSkillBody && !scansPackage && !scansNpmrc && !scansSettings) {
      continue;
    }
    const source = tree.readText(rel);
    if (source === undefined)
      throw new TypeError(`trust-lint: unreadable manifest candidate ${rel}`);
    if (scansFrontmatter) drafts.push(...scanFrontmatter(rel, source));
    if (scansSkillBody) drafts.push(...scanBangAutoRun(rel, source));
    if (scansPackage) drafts.push(...scanPackageJson(rel, source));
    if (scansNpmrc) drafts.push(...scanNpmrc(rel, source));
    if (scansSettings) drafts.push(...scanSettingsHooks(rel, source));
  }
  const occurrences = new Map<string, number>();
  return drafts.map((draft) => toFinding(tree, occurrences, draft));
}
