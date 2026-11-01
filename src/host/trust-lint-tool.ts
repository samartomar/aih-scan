import type { FindingPart, Severity } from "../contracts/risk.js";
import { textOf } from "../contracts/routing.js";
import { scanTrustDependencyNamesV1 } from "../trust-lint/depnames.js";
import type { TrustLintFindingV1 } from "../trust-lint/findings.js";
import type {
  TrustLintPathKindV1,
  TrustLintTreeEntryV1,
  TrustLintTreeV1,
} from "../trust-lint/inventory.js";
import { scanTrustDocumentV1, scanTrustUnicodeDocumentV1 } from "../trust-lint/lint.js";
import { scanMaliciousCodeTextV1 } from "../trust-lint/malicious-code.js";
import { scanTrustManifestsV1 } from "../trust-lint/manifest.js";
import { scanMcpServerDescriptionsV1 } from "../trust-lint/mcp-description.js";
import { scanMcpConfigSecretsV1, scanTextSecretsV1 } from "../trust-lint/secrets.js";
import type { AssessItem, ToolAdapter, ToolContext, ToolFinding, ToolRun } from "./tools.js";

export const TRUST_LINT_VERSION = "1.0.0";

/** aih-trust-lint's own severity and confidence for each of its rules. */
const RULES: Readonly<
  Record<string, Readonly<{ severity: Severity; confidence: number; description: string }>>
> = Object.freeze({
  "trust.prompt-injection": {
    severity: "HIGH",
    confidence: 0.8,
    description: "Prompt injection or instruction override",
  },
  "trust.hidden-unicode": {
    severity: "HIGH",
    confidence: 0.9,
    description: "Hidden or bidirectional Unicode",
  },
  "trust.visible-unicode": {
    severity: "LOW",
    confidence: 0.5,
    description: "Confusable visible Unicode",
  },
  "trust.malicious-code": {
    severity: "HIGH",
    confidence: 0.8,
    description: "Raw malicious-code shape",
  },
  "trust.external-egress": {
    severity: "MEDIUM",
    confidence: 0.7,
    description: "Exfiltration or external egress instruction",
  },
  "trust.auto-exec-hook": {
    severity: "MEDIUM",
    confidence: 0.9,
    description: "Automatically executed hook or script",
  },
  "trust.permission-risk": {
    severity: "MEDIUM",
    confidence: 0.7,
    description: "Excessive agency or permission",
  },
  "secrets.plaintext-detected": {
    severity: "HIGH",
    confidence: 0.9,
    description: "Plaintext secret",
  },
  "mcp.hardcoded-secret": {
    severity: "HIGH",
    confidence: 0.9,
    description: "Hard-coded secret in MCP or hook config",
  },
  "mcp.tool-poisoning": {
    severity: "HIGH",
    confidence: 0.7,
    description: "MCP tool description poisoning",
  },
  "mcp.config-invalid": {
    severity: "LOW",
    confidence: 1,
    description: "Config could not be inspected",
  },
  "trust.typosquat": {
    severity: "HIGH",
    confidence: 0.6,
    description: "Possible typosquatted dependency",
  },
  "trust.dependency-confusion": {
    severity: "HIGH",
    confidence: 0.6,
    description: "Possible dependency confusion",
  },
  "trust.unpinned-dependency": {
    severity: "LOW",
    confidence: 0.9,
    description: "Unpinned dependency",
  },
});

/** An in-memory trust-lint tree over the exact snapshot bytes. */
function treeOf(item: AssessItem): TrustLintTreeV1 {
  const texts = new Map<string, string | undefined>();
  const entries: TrustLintTreeEntryV1[] = item.files.map((file) =>
    Object.freeze({
      relativePath: file.path,
      size: file.bytes.length,
      symlink: false,
      executable: file.mode === "100755",
      realpathContained: true,
    }),
  );
  const byPath = new Map(entries.map((entry) => [entry.relativePath, entry]));
  const bytes = new Map(item.files.map((file) => [file.path, file.bytes]));
  const directories = new Set<string>();
  for (const file of item.files) {
    const parts = file.path.split("/");
    for (let depth = 1; depth < parts.length; depth += 1)
      directories.add(parts.slice(0, depth).join("/"));
  }
  const readText = (rel: string) => {
    if (!texts.has(rel)) {
      const content = bytes.get(rel);
      texts.set(rel, content === undefined ? undefined : textOf(content));
    }
    return texts.get(rel);
  };
  return {
    files: entries,
    *matching(predicate) {
      for (const entry of entries) if (predicate(entry)) yield entry;
    },
    fileEntry: (rel) => byPath.get(rel),
    pathKind: (rel): TrustLintPathKindV1 =>
      byPath.has(rel) ? "file" : directories.has(rel) ? "directory" : "absent",
    isDirectory: (rel) => directories.has(rel),
    hasFile: (rel) => byPath.has(rel),
    readText,
  };
}

const EXACT_NPM = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const EXACT_PYPI = /^===?\s*[0-9A-Za-z.!+-]+$/;

/**
 * The always-on baseline. Every part goes to its checks: Text gets the full document lint,
 * Code and Config hidden-Unicode and malicious-code checks (inline config commands too, as
 * part `code`), Config the MCP secret and tool-poisoning checks, Dependencies the name and
 * pinning checks; every text file, whatever its part, gets the secret check. Pure: no process,
 * no network, no execution.
 */
export function trustLintFindings(
  item: AssessItem,
  internalScopes: readonly string[],
): ToolFinding[] {
  const tree = treeOf(item);
  const partOf = (path: string): FindingPart => item.routed.get(path)?.part ?? "none";
  const raw: { finding: TrustLintFindingV1; part?: FindingPart; ruleId?: string; path?: string }[] =
    [];
  const textFiles = item.files
    .filter((file) => item.routed.get(file.path)?.text === true)
    .map((file) => file.path);
  const inPart = (part: string) => textFiles.filter((path) => item.routed.get(path)?.part === part);
  const occurrences = new Map<string, number>();
  for (const path of inPart("text"))
    for (const finding of scanTrustDocumentV1(path, tree.readText(path) ?? ""))
      raw.push({ finding });
  for (const path of [...inPart("code"), ...inPart("config"), ...inPart("dependencies")])
    for (const finding of scanTrustUnicodeDocumentV1(path, tree.readText(path) ?? ""))
      raw.push({ finding });
  for (const path of inPart("code"))
    for (const finding of scanMaliciousCodeTextV1(path, tree.readText(path) ?? "", occurrences))
      raw.push({ finding });
  for (const path of inPart("config")) {
    for (const command of item.routed.get(path)?.inlineCommands ?? []) {
      for (const finding of scanMaliciousCodeTextV1(
        path,
        command.command,
        occurrences,
        command.line - 1,
      ))
        raw.push({ finding, part: "code" });
      for (const finding of scanTrustUnicodeDocumentV1(path, command.command))
        raw.push({
          finding: { ...finding, location: { uri: path, startLine: command.line } },
          part: "code",
        });
    }
  }
  for (const finding of scanTrustManifestsV1(tree, textFiles)) raw.push({ finding });
  const packages = textFiles.filter((path) => (path.split("/").at(-1) ?? "") === "package.json");
  for (const finding of scanTrustDependencyNamesV1(
    tree,
    [...packages, ...textFiles.filter((p) => !packages.includes(p))],
    internalScopes,
  ))
    raw.push({ finding });
  const configs = inPart("config");
  for (const finding of scanMcpConfigSecretsV1(tree, configs)) raw.push({ finding });
  for (const finding of scanMcpServerDescriptionsV1(tree, configs))
    raw.push({
      finding,
      ruleId: "mcp.tool-poisoning",
      path: finding.mcpDescription?.configPath ?? finding.location.uri,
    });
  for (const path of textFiles.filter((path) => partOf(path) !== "config"))
    for (const finding of scanTextSecretsV1(path, tree.readText(path) ?? "")) raw.push({ finding });
  for (const path of textFiles) {
    for (const dependency of item.routed.get(path)?.dependencies ?? []) {
      if (dependency.file !== path) continue;
      const version = dependency.version;
      const exact =
        version !== null && (dependency.ecosystem === "npm" ? EXACT_NPM : EXACT_PYPI).test(version);
      const launcher = partOf(path) === "config";
      if (exact || (dependency.ecosystem === "npm" && !launcher)) continue; // package.json pinning is checked above
      raw.push({
        finding: {
          name: "trust.unpinned-dependency",
          verdict: "fail",
          code: "trust.unpinned-dependency",
          detail: `${path} — ${dependency.name} is not pinned to an exact version`,
          location: { uri: path, startLine: 1 },
          fingerprint: `trust.unpinned-dependency:${path}:${dependency.name}`,
        },
      });
    }
  }
  return raw.map(({ finding, part, ruleId, path }) => {
    const id = ruleId ?? finding.code;
    const rule = RULES[id];
    const location = path ?? finding.location.uri;
    const file = item.routed.has(location) ? location : finding.location.uri;
    return Object.freeze({
      ruleId: id,
      message: finding.detail,
      path: file,
      line: finding.location.startLine,
      part: part ?? partOf(file),
      ...(rule === undefined
        ? { level: "error" as const }
        : { severity: rule.severity, confidence: rule.confidence }),
      fingerprint: finding.fingerprint,
    });
  });
}

export const trustLintAdapter: ToolAdapter = Object.freeze({
  id: "aih-trust-lint" as const,
  version: TRUST_LINT_VERSION,
  async run(item: AssessItem, context: ToolContext): Promise<ToolRun> {
    if (context.signal.aborted)
      return Object.freeze({
        status: "not-run" as const,
        version: TRUST_LINT_VERSION,
        mode: "static" as const,
        reason: "cancelled" as const,
      });
    try {
      const findings = trustLintFindings(item, context.internalScopes).filter((finding) =>
        item.routed.has(finding.path),
      );
      return Object.freeze({
        status: "ran" as const,
        version: TRUST_LINT_VERSION,
        mode: "static" as const,
        findings: Object.freeze(findings),
        rules: Object.fromEntries(
          Object.entries(RULES).map(([id, rule]) => [id, rule.description]),
        ),
      });
    } catch {
      return Object.freeze({
        status: "not-run" as const,
        version: TRUST_LINT_VERSION,
        mode: "static" as const,
        reason: "failed" as const,
        detail: "aih-trust-lint failed",
      });
    }
  },
});
