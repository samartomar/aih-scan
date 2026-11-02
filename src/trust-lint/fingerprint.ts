import { createHash } from "node:crypto";

/**
 * Port of Core's `src/trust/fingerprint.ts` (content-bound finding identity).
 *
 * The digest binds the check code, normalized source-relative path, rule id,
 * occurrence ordinal and the finding content; `displayLine` is accepted for
 * call-site clarity and deliberately NOT hashed, so shifting an unchanged
 * finding to a different line keeps its identity.
 */
export interface TrustLintFindingIdentityV1 {
  readonly code: string;
  readonly path: string;
  readonly ruleId: string;
  readonly content: string | Buffer;
  readonly occurrence: number;
  readonly displayLine?: number;
}

function normalizedSafePath(path: string): string {
  const normalized = path
    .replace(/\\/g, "/")
    .replace(/^(?:\.\/)+/, "")
    .replace(/\/{2,}/g, "/");
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized) ||
    normalized.split("/").some((part) => part === "..")
  ) {
    return "untrusted-document";
  }
  return normalized;
}

export function contentFindingFingerprintV1(input: TrustLintFindingIdentityV1): string {
  if (!Number.isSafeInteger(input.occurrence) || input.occurrence < 0) {
    throw new TypeError("trust-lint: finding occurrence must be a non-negative safe integer");
  }
  const path = normalizedSafePath(input.path);
  const hash = createHash("sha256");
  for (const value of [input.code, path, input.ruleId, String(input.occurrence)]) {
    hash.update(value, "utf8");
    hash.update("\0", "utf8");
  }
  hash.update(input.content);
  return `${input.code.replace(/\./g, "-")}:${path}:${hash.digest("hex")}`;
}
