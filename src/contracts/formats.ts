/** Format identifiers of the replacement contract. Compatibility follows these, never package versions. */
export const formats = Object.freeze({
  request: "aih-scan-request/1",
  source: "aih-scan-source/1",
  summary: "aih-scan-summary/1",
  withdrawn: "aih-scan-withdrawn/1",
  routing: "aih-scan-routing/1",
  scoring: "aih-risk/1",
  codes: "aih-codes/1",
  limits: "aih-scan-limits/1",
} as const);

export type ResultStatus = "ok" | "refused" | "invalid" | "unsupported-version";

/** A bad-input result. No contract function throws on bad input. */
export type Problem =
  | Readonly<{ status: "refused"; reason: string; detail?: string }>
  | Readonly<{ status: "invalid"; reason: string; detail?: string }>
  | Readonly<{ status: "unsupported-version"; reason: string; detail?: string }>;

const FORMAT_PATTERN = /^([a-z][a-z0-9-]*)\/(\d+)$/;

/**
 * Classifies a document's format field against the one supported identifier:
 * the same family at another version is `unsupported-version`; anything else is `invalid`.
 */
export function formatProblem(
  value: unknown,
  expected: string,
  label: string,
): Problem | undefined {
  if (value === expected) return undefined;
  const family = FORMAT_PATTERN.exec(expected)?.[1];
  if (typeof value === "string") {
    const match = FORMAT_PATTERN.exec(value);
    if (match !== null && match[1] === family)
      return Object.freeze({
        status: "unsupported-version" as const,
        reason: "unsupported-version",
        detail: `${label} format ${value} is not supported; expected ${expected}`,
      });
  }
  return Object.freeze({
    status: "invalid" as const,
    reason: "format",
    detail: `${label} format must be ${expected}`,
  });
}
