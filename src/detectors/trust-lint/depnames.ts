import type { TrustLintFindingV1 } from "./findings.js";
import { contentFindingFingerprintV1 } from "./fingerprint.js";
import type { TrustLintTreeV1 } from "./inventory.js";

/**
 * Port of Core's `src/trust/depnames.ts` dependency-name checks:
 * `trust.typosquat` (Damerau-Levenshtein distance 1 from a popular package),
 * `trust.dependency-confusion` (direct dependency under a configured internal
 * scope), and `trust.unpinned-dependency` (floating/git/url-without-SHA spec,
 * or dependencies declared with no lockfile anywhere in the trust source).
 *
 * Dropped Core wiring (stays in Core): org-policy `trust.internalScopes`
 * resolution (policy) and `gradeTrustCheck` posture grading — identity for
 * these codes anyway, since none is in TRUST_WARN_CODES/TRUST_REVIEW_CODES.
 */

type DependencyCheckCode = Extract<
  import("./findings.js").TrustLintCheckCodeV1,
  "trust.dependency-confusion" | "trust.typosquat" | "trust.unpinned-dependency"
>;

export const POPULAR_PACKAGES_V1: readonly string[] = [
  "@types/node",
  "axios",
  "chalk",
  "commander",
  "debug",
  "dotenv",
  "esbuild",
  "eslint",
  "express",
  "lodash",
  "next",
  "react",
  "react-dom",
  "request",
  "requests",
  "typescript",
  "vite",
  "vitest",
  "yaml",
  "zod",
];

const DIRECT_DEP_BLOCKS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);
const EXACT_VERSION = /^=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

interface DirectDependencySpec {
  blockName: (typeof DIRECT_DEP_BLOCKS)[number];
  name: string;
  spec: string;
}

function dependencyFingerprint(
  occurrences: Map<string, number>,
  code: DependencyCheckCode,
  path: string,
  line: number,
  content: string,
): string {
  const key = JSON.stringify([code, path, content]);
  const occurrence = occurrences.get(key) ?? 0;
  occurrences.set(key, occurrence + 1);
  return contentFindingFingerprintV1({
    code,
    path,
    ruleId: code,
    content,
    occurrence,
    displayLine: line,
  });
}

function linesOf(source: string): string[] {
  return source.split(/\r?\n/);
}

function lineText(source: string, line: number): string {
  return linesOf(source)[line - 1] ?? "";
}

function lineForDependency(source: string, name: string, spec?: string): number {
  const quoted = `"${name.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const quotedSpec = spec === undefined ? undefined : JSON.stringify(spec);
  const found = linesOf(source).findIndex(
    (line) => line.includes(quoted) && (quotedSpec === undefined || line.includes(quotedSpec)),
  );
  return found >= 0 ? found + 1 : 1;
}

function dependencyCheck(
  occurrences: Map<string, number>,
  code: DependencyCheckCode,
  path: string,
  line: number,
  lineTextValue: string,
  detail: string,
): TrustLintFindingV1 {
  return {
    name: code,
    verdict: "fail",
    detail: `${path}:${line} — ${detail}`,
    code,
    location: { uri: path, startLine: line },
    fingerprint: dependencyFingerprint(
      occurrences,
      code,
      path,
      line,
      `${lineTextValue}\0${detail}`,
    ),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function packageBaseName(rel: string): string {
  return rel.split("/").at(-1) ?? "";
}

function packageDirName(rel: string): string {
  const index = rel.lastIndexOf("/");
  return index === -1 ? "" : rel.slice(0, index);
}

function directDependencySpecs(pkg: Record<string, unknown>): DirectDependencySpec[] {
  const specs: DirectDependencySpec[] = [];
  for (const blockName of DIRECT_DEP_BLOCKS) {
    const block = pkg[blockName];
    if (!isRecord(block)) continue;
    for (const [name, rawSpec] of Object.entries(block)) {
      specs.push({
        blockName,
        name,
        spec: typeof rawSpec === "string" ? rawSpec : "",
      });
    }
  }
  return specs.sort(
    (a, b) => a.name.localeCompare(b.name) || a.blockName.localeCompare(b.blockName),
  );
}

function directDependencyNames(pkg: Record<string, unknown>): string[] {
  const names = new Set<string>();
  for (const spec of directDependencySpecs(pkg)) names.add(spec.name);
  return [...names].sort((a, b) => a.localeCompare(b));
}

function scopeOfPackage(name: string): string | undefined {
  if (!name.startsWith("@")) return undefined;
  const slash = name.indexOf("/");
  if (slash <= 0) return undefined;
  return name.slice(0, slash).toLowerCase();
}

interface PackageIdentity {
  scope?: string;
  name: string;
}

function packageIdentity(rawName: string): PackageIdentity | undefined {
  const name = rawName.toLowerCase();
  if (!name.startsWith("@")) return { name };
  const slash = name.indexOf("/");
  if (slash <= 1 || slash === name.length - 1) return undefined;
  return { scope: name.slice(0, slash), name: name.slice(slash + 1) };
}

function isDamerauLevenshteinDistanceOne(left: string, right: string): boolean {
  if (left === right) return false;
  const lengthDelta = left.length - right.length;
  if (Math.abs(lengthDelta) > 1) return false;

  if (lengthDelta === 0) {
    const mismatches: number[] = [];
    for (let index = 0; index < left.length; index++) {
      if (left[index] !== right[index]) mismatches.push(index);
      if (mismatches.length > 2) return false;
    }
    if (mismatches.length === 1) return true;
    if (mismatches.length !== 2) return false;
    const [first, second] = mismatches;
    if (first === undefined || second === undefined || second !== first + 1) return false;
    return left[first] === right[second] && left[second] === right[first];
  }

  const longer = left.length > right.length ? left : right;
  const shorter = left.length > right.length ? right : left;
  let longerIndex = 0;
  let shorterIndex = 0;
  let edits = 0;
  while (longerIndex < longer.length && shorterIndex < shorter.length) {
    if (longer[longerIndex] === shorter[shorterIndex]) {
      longerIndex++;
      shorterIndex++;
      continue;
    }
    edits++;
    if (edits > 1) return false;
    longerIndex++;
  }
  return true;
}

function popularTypoTarget(name: string): string | undefined {
  const dependency = packageIdentity(name);
  if (dependency === undefined) return undefined;
  return POPULAR_PACKAGES_V1.find((popular) => {
    const target = packageIdentity(popular);
    if (target === undefined || target.scope !== dependency.scope) return false;
    return isDamerauLevenshteinDistanceOne(dependency.name, target.name);
  });
}

function hasFullShaFragment(spec: string): boolean {
  return /#[0-9a-f]{40}$/.test(spec.trim());
}

function isGitOrUrlDependency(spec: string): boolean {
  const trimmed = spec.trim();
  const lower = trimmed.toLowerCase();
  return (
    /^(?:git\+)?(?:https?|ssh):\/\//.test(lower) ||
    lower.startsWith("git@") ||
    lower.startsWith("github:") ||
    lower.startsWith("gitlab:") ||
    lower.startsWith("bitbucket:") ||
    lower.startsWith("file:") ||
    lower.startsWith("link:") ||
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.+)?$/.test(trimmed)
  );
}

function isExactVersionSpec(spec: string): boolean {
  const trimmed = spec.trim();
  const npmAlias = /^npm:.+@(.+)$/.exec(trimmed);
  return EXACT_VERSION.test(npmAlias?.[1] ?? trimmed);
}

function unpinnedDependencyReason(name: string, spec: string): string | undefined {
  const trimmed = spec.trim();
  if (trimmed.length === 0) return `direct dependency ${name} has an empty version spec`;
  if (isGitOrUrlDependency(trimmed)) {
    return hasFullShaFragment(trimmed)
      ? undefined
      : `direct dependency ${name} uses a git/url dependency without a 40-character SHA pin`;
  }
  if (isExactVersionSpec(trimmed)) return undefined;
  return `direct dependency ${name} uses unpinned version spec ${JSON.stringify(spec)}`;
}

function readColocatedNpmLock(tree: TrustLintTreeV1, packageRel: string): string | undefined {
  const dir = packageDirName(packageRel);
  const prefix = dir.length === 0 ? "" : `${dir}/`;
  return (
    tree.readText(`${prefix}package-lock.json`) ?? tree.readText(`${prefix}npm-shrinkwrap.json`)
  );
}

function isResolvedByIntegrityBoundNpmLock(
  lockSource: string | undefined,
  dependency: DirectDependencySpec,
): boolean {
  if (lockSource === undefined) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockSource);
  } catch {
    return false;
  }
  if (!isRecord(parsed) || !isRecord(parsed.packages)) return false;
  const root = parsed.packages[""];
  if (!isRecord(root)) return false;
  const rootBlock = root[dependency.blockName];
  if (!isRecord(rootBlock) || rootBlock[dependency.name] !== dependency.spec) {
    return false;
  }
  const resolved = parsed.packages[`node_modules/${dependency.name}`];
  if (!isRecord(resolved)) return false;
  const version = resolved.version;
  const integrity = resolved.integrity;
  return (
    typeof version === "string" &&
    isExactVersionSpec(version) &&
    typeof integrity === "string" &&
    /^sha(?:1|256|384|512)-[A-Za-z0-9+/=]+$/.test(integrity)
  );
}

interface PackageScanResult {
  checks: TrustLintFindingV1[];
  declaresDependencies: boolean;
}

function scanPackageJson(
  occurrences: Map<string, number>,
  rel: string,
  source: string,
  internalScopes: ReadonlySet<string>,
  npmLockSource?: string,
): PackageScanResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return { checks: [], declaresDependencies: false };
  }
  if (!isRecord(parsed)) return { checks: [], declaresDependencies: false };

  const checks: TrustLintFindingV1[] = [];
  const dependencySpecs = directDependencySpecs(parsed);
  for (const dependency of dependencySpecs) {
    const reason = unpinnedDependencyReason(dependency.name, dependency.spec);
    if (reason === undefined) continue;
    if (isResolvedByIntegrityBoundNpmLock(npmLockSource, dependency)) continue;
    const line = lineForDependency(source, dependency.name, dependency.spec);
    const text = lineText(source, line);
    checks.push(dependencyCheck(occurrences, "trust.unpinned-dependency", rel, line, text, reason));
  }

  for (const name of directDependencyNames(parsed)) {
    const line = lineForDependency(source, name);
    const text = lineText(source, line);
    const scope = scopeOfPackage(name);
    if (scope !== undefined && internalScopes.has(scope)) {
      checks.push(
        dependencyCheck(
          occurrences,
          "trust.dependency-confusion",
          rel,
          line,
          text,
          `direct dependency ${name} uses configured internal scope ${scope}`,
        ),
      );
      continue;
    }

    const target = popularTypoTarget(name);
    if (target !== undefined) {
      checks.push(
        dependencyCheck(
          occurrences,
          "trust.typosquat",
          rel,
          line,
          text,
          `direct dependency ${name} is Damerau-Levenshtein distance 1 from popular package ${target}`,
        ),
      );
    }
  }
  return { checks, declaresDependencies: dependencySpecs.length > 0 };
}

/**
 * Port of Core's `scanTrustDependencyNames` over the tree seam (C2a §2.2(3)):
 * per SELECTED `package.json` in selection order; the missing-lockfile check
 * looks for a lockfile name in the SELECTION; a co-located
 * `package-lock.json` / `npm-shrinkwrap.json` is read from the tree to
 * suppress integrity-bound entries.
 */
export function scanTrustDependencyNamesV1(
  tree: TrustLintTreeV1,
  selection: readonly string[],
  internalScopes: readonly string[],
): TrustLintFindingV1[] {
  // Already normalized by Core and validated at the options boundary (§2.1).
  const scopes = new Set(internalScopes);
  const checks: TrustLintFindingV1[] = [];
  const occurrences = new Map<string, number>();
  let firstPackageWithDependencies: { rel: string; source: string } | undefined;
  for (const rel of selection) {
    if (packageBaseName(rel) !== "package.json") continue;
    const source = tree.readText(rel);
    if (source === undefined) throw new TypeError(`trust-lint: unreadable package manifest ${rel}`);
    const result = scanPackageJson(
      occurrences,
      rel,
      source,
      scopes,
      readColocatedNpmLock(tree, rel),
    );
    checks.push(...result.checks);
    if (result.declaresDependencies && firstPackageWithDependencies === undefined) {
      firstPackageWithDependencies = { rel, source };
    }
  }
  const hasLockfile = selection.some((rel) => LOCKFILE_NAMES.has(packageBaseName(rel)));
  if (firstPackageWithDependencies !== undefined && !hasLockfile) {
    const { rel, source } = firstPackageWithDependencies;
    checks.push(
      dependencyCheck(
        occurrences,
        "trust.unpinned-dependency",
        rel,
        1,
        lineText(source, 1),
        "package.json declares direct dependencies but no lockfile was found anywhere in the trust source",
      ),
    );
  }
  return checks;
}
